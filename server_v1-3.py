import asyncio
import websockets
import json
import socket
import time
import uuid
import aiosqlite
from db import ChatDB
from copy import deepcopy

from websockets.exceptions import ConnectionClosedOK
import sys

from cryptography.hazmat.primitives import serialization
import codec
import base64


# --- Load bootstrap servers ---
with open("bootstrap_servers.json", "r") as f:
    BOOTSTRAP_SERVERS = json.load(f)


class Link:
    """Wrapper for WebSocket connections with metadata"""
    def __init__(self, websocket):
        self.websocket = websocket
        self.last_heartbeat = time.time()

    async def close(self):
        await self.websocket.close()


class Server:
    def __init__(self, host="127.0.0.1", port=9000, introducers=None, introducer_mode=False):
        # --- Server state ---
        self.servers = {}            # server_id -> Link
        self.server_addrs = {}       # server_id -> (host, port, pubkey)
        self.servers_websockets = {} # websocket -> server_id

        self.local_users = {}        # user_id -> Link
        self.user_locations = {}     # user_id -> "local" | server_id

        with open("SOCP.json", 'r') as file:
            self.JSON_base_template = json.load(file)

        self.host = host
        self.port = port
        self.server_uuid = str(uuid.uuid4())
        self.UDP_DISCOVERY_PORT = 9999

        # Pick introducer
        selected = None
        if introducer_mode:
            for entry in BOOTSTRAP_SERVERS:
                if entry["host"] == host and entry["port"] == port:
                    selected = entry
                    break
            if selected is None:
                raise ValueError("No matching introducer found")
        else:
            self.introducers = introducers or BOOTSTRAP_SERVERS

        # --- Load keys ---
        if introducer_mode:
            self.private_key = serialization.load_pem_private_key(
                base64.urlsafe_b64decode(selected["private_key"]),
                password=None
            )
            self.public_key = serialization.load_pem_public_key(
                base64.urlsafe_b64decode(selected["public_key"])
            )
        else:
            self.private_key, self.public_key = codec.generate_keys()

        # PEM + base64url
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.private_key_base64url = base64.urlsafe_b64encode(private_key_pem).decode("utf-8")
        self.public_key_base64url = base64.urlsafe_b64encode(public_key_pem).decode("utf-8")

        # --- Other state ---
        self.introducer_mode = introducer_mode
        self.tasks = []
        self.server_websocket = None
        self.udp_sock = None
        self._incoming_responses = {}   # uri -> asyncio.Queue
        self._shutdown_event = asyncio.Event()
        self.selected_bootstrap_server = {}

        # Per-port DB file (one DB per server)
        self.db = ChatDB(f"chat_{self.port}.db")

        print(f"[{self.server_uuid}] Initialized server on {self.host}:{self.port} ({'INTRODUCER' if self.introducer_mode else 'NORMAL'})")

    async def cleanup_client(self, username):
        self.local_users.pop(username, None)
        self.server_addrs.pop(username, None)
        print(f"[-] Removed client: {username}")

        # Notify peers USER_REMOVE to other servers
        user_remove_message = deepcopy(self.JSON_base_template)
        user_remove_message["type"] = "USER_REMOVE"
        user_remove_message["from"] = self.server_uuid 
        user_remove_message["to"] = "*"
        user_remove_message["ts"] = time.time()
        user_remove_message["payload"] = {
            "user_id": username,
            "server_id": self.server_uuid,
        }
        user_remove_message["sig"] = codec.generate_payload_signature(
            user_remove_message,
            self.private_key
        )
                    
        # Broadcast USER_REMOVE to all connected servers
        for server_id, link in self.servers.items():
            try:
                await link.websocket.send(json.dumps(user_remove_message))
                print(f"[{self.server_uuid}] Sent USER_REMOVE to server {server_id}")
            except Exception as e:
                    print(f"[{self.server_uuid}] Failed to send USER_REMOVE to {server_id}: {e}")

            continue 

    async def wait_for_message(self, uri, expected_type):
        queue = self._incoming_responses[uri]
        while True:
            raw = await queue.get()
            frame = json.loads(raw)
            if frame.get("type") == expected_type:
                return frame
            else:
                await queue.put(raw)
                await asyncio.sleep(0)

    async def outgoing_connection_handler(self, ws, uri):
        """Handle messages for an outgoing websocket connection."""
        try:
            async for msg in ws:
                try:
                    frame = json.loads(msg)
                except Exception:
                    continue
                print(f"[{self.server_uuid}] Received {frame.get('type')} from {frame.get('from')} on {uri}")

                if uri in self._incoming_responses:
                    await self._incoming_responses[uri].put(msg)
        except websockets.exceptions.ConnectionClosed:
            print(f"[{self.server_uuid}] Outgoing connection closed for {uri}")
        finally:
            server_uuid = self.servers_websockets.pop(ws, None)
            if server_uuid:
                self.servers.pop(server_uuid, None)
                self.server_addrs.pop(server_uuid, None)
                print(f"[{self.server_uuid}] Cleaned up outgoing peer {server_uuid} for {uri} THIS HAS NOT BEEN TESTED")
    

    # Updated incoming_connection_handler for incoming connections (servers connecting to us)
    async def incoming_connection_handler(self, ws):
        """Handle incoming websocket connections (servers connecting to this server)."""
        remote_host, remote_port = ws.remote_address
        uri = f"ws://{remote_host}:{remote_port}"

        if ws in self.servers_websockets:
            server_uuid = self.servers_websockets[ws]
            link = self.servers.get(server_uuid)
            if link:
                link.last_heartbeat = time.time()
        
        try:            
            async for msg in ws:
                try:
                    frame = json.loads(msg)
                except Exception:
                    continue

                msg_type = frame.get("type")
                print(f"[{self.server_uuid}] Received {msg_type} from {frame.get('from')}")

                # --- Server ↔ Introducer join ---
                if self.introducer_mode and msg_type == "SERVER_HELLO_JOIN":
                    await self.handle_server_hello_join(frame, ws)
                    continue

                if msg_type == "SERVER_ANNOUNCE":
                    await self.handle_server_announce(frame, ws)
                    continue
                    
            
                # Handle USER_ADVERTISE (update user_locations + gossip forward)
                if msg_type == "USER_ADVERTISE":
                    payload = frame.get("payload")
                    user_location = payload.get("server_id")
                    user_id = payload.get("user_id")

                    # 1) Verify server signature 
                    _, _, pubkey = self.server_addrs[user_location] 

                    pubkey_obj = codec.decode_public_key_base64url(pubkey)
                    codec.verify_payload_signature(frame, pubkey_obj)

                    #TODO: error handling for if verification fails

                    # only add to user locations and forward user advertise if we havent seen this user before
                    if user_id not in self.user_locations:
                        # 2) If verified, add to list 
                        self.user_locations[user_id] = user_location
                        # 3) Forward message to other servers (gossip) 
                        for server_id, link in self.servers.items():
                            if server_id != user_location:  # Don't send back to the origin
                                try:
                                    await link.websocket.send(json.dumps(frame))
                                    print(f"[{self.server_uuid}] Forwarded USER_ADVERTISE for {user_id} to server {server_id}")
                                except Exception as e:
                                    print(f"[{self.server_uuid}] Failed to forward USER_ADVERTISE to {server_id}: {e}")
                        
                        print(f"[debug] self.user_locations[{user_id}] = {self.user_locations[user_id]}")

                        # TODO: 4) Notify my clients a new user has joined

                    continue
                
                # TODO: Handle USER_REMOVE (remove user if mapping matches)
                if msg_type == "USER_REMOVE":
                    # only remove and forward if we haven't done so yet
                    if user_id in self.user_locations:
                        # 1) Verify server signature 
                        _, _, pubkey = self.server_addrs[user_location] 

                        pubkey_obj = codec.decode_public_key_base64url(pubkey)
                        codec.verify_payload_signature(frame, pubkey_obj)

                        #TODO: error handling for if verification fails

                        # 2) remove
                        payload = frame.get("payload")
                        user_location = payload.get("server_id")
                        user_id = payload.get("user_id")

                        self.local_users.pop(user_id, None)
                        self.user_locations.pop(user_id, None)
                        self.server_addrs.pop(user_id, None)
                        print(f"[-] Removed client: {user_id}")
                        
                        # 3) Forward message to other servers (gossip)
                        for server_id, link in self.servers.items():
                            if server_id != user_location:  # Don't send back to the origin
                                try:
                                    await link.websocket.send(json.dumps(frame))
                                    print(f"[{self.server_uuid}] Forwarded USER_REMOVE for {user_id} to server {server_id}")
                                except Exception as e:
                                    print(f"[{self.server_uuid}] Failed to forward USER_REMOVE to {server_id}: {e}")
                        
                        print(f"[debug] removed user: {user_id}")

                        # TODO: 4) Notify my clients a new user has joined                        
                    continue
                
                # TODO: Handle SERVER_DELIVER (forward to local user or to correct server)
                if msg_type == "SERVER_DELIVER":
                    payload = frame.get("payload", {})
                    sender = payload.get("sender")
                    ciphertext = payload.get("ciphertext")
                    sender_pub = payload.get("sender_pub")
                    content_sig = payload.get("content_sig")

                    # Find the target user in the payload or frame
                    target_user = None
                    if "user_id" in payload:
                        target_user = payload["user_id"]
                    else:
                        # If not in payload, might need to extract from original message
                        print(f"[{self.server_uuid}] SERVER_DELIVER missing target_user in payload")
                        continue
                    
                    # Check if target user is local
                    if target_user in self.local_users and self.user_locations.get(target_user) == "local":
                        try:
                            # 1) TODO: verify signature

                            # Convert SERVER_DELIVER to USER_DELIVER for local client
                            user_deliver_msg = deepcopy(self.JSON_base_template)
                            user_deliver_msg["type"] = "USER_DELIVER"
                            user_deliver_msg["from"] = self.server_uuid
                            user_deliver_msg["to"] = target_user
                            user_deliver_msg["ts"] = frame.get("ts")
                            user_deliver_msg["payload"] = {
                                "sender": sender,
                                "ciphertext": ciphertext,
                                "sender_pub": sender_pub,
                                "content_sig": content_sig
                            }
                            # user_deliver_msg["sig"] = server sig 
                            
                            await self.local_users[target_user].websocket.send(json.dumps(user_deliver_msg))
                            print(f'[{self.server_uuid}] Delivered message to local user {target_user}')
                            
                        except Exception as e:
                            print(f"[{self.server_uuid}] Error delivering to local user {target_user}: {e}")
                            await self.cleanup_client(target_user)
                    else:
                        print(f"[{self.server_uuid}] Received SERVER_DELIVER for non-local user: {target_user}")
                    
                    continue

                # TODO: Handle HEARTBEAT (update health state, maybe reply)
                # TODO: Handle ACK (log/track successful delivery)
                # TODO: Handle ERROR (parse code, log, maybe correct state)

                # --- User ↔ Server TODOs ---
                # TODO: Handle USER_HELLO (register local user, broadcast USER_ADVERTISE)
                if msg_type == "USER_HELLO":
                    client_id = str(uuid.uuid4())
                    payload = frame.get("payload", {}) or {}
                    pubkey_b64url = payload.get("pubkey")
                    if not pubkey_b64url:
                        await ws.send(json.dumps({"type": "ERROR", "code": "BAD_KEY", "reason": "missing pubkey"}))
                        continue

                    # local presence
                    self.local_users[client_id] = Link(ws)
                    self.user_locations[client_id] = "local"

                    # persist in DB
                    await self.db.upsert_user(
                        user_id=client_id,
                        pubkey_b64url=pubkey_b64url,
                        privkey_store="",
                        pake_password="",
                        meta={"display_name": client_id},
                        version=1,
                    )

                    # ensure membership in 'public'
                    now_ts = int(time.time())
                    await self.db.ensure_public_group(now_ts)
                    await self.db.add_member_to_group("public", client_id, pubkey_b64url, now_ts)

                    # welcome
                    message = deepcopy(self.JSON_base_template)
                    message["type"] = "USER_WELCOME"
                    message["from"] = self.server_uuid
                    message["to"] = client_id
                    message["ts"] = time.time()
                    await ws.send(json.dumps(message))

                    # USER_ADVERTISE TO OTHER SERVERS
                    user_advertise_message = deepcopy(self.JSON_base_template)
                    user_advertise_message["type"] = "USER_ADVERTISE"
                    user_advertise_message["from"] = self.server_uuid 
                    user_advertise_message["to"] = "*"
                    user_advertise_message["ts"] = time.time()
                    user_advertise_message["payload"] = {
                        "user_id": client_id,
                        "server_id": self.server_uuid,
                        "meta": {}
                    }
                    user_advertise_message["sig"] = codec.generate_payload_signature(
                        user_advertise_message,
                        self.private_key
                    )
                    
                    # Broadcast USER_ADVERTISE to all connected servers
                    for server_id, link in self.servers.items():
                        try:
                            await link.websocket.send(json.dumps(user_advertise_message))
                            print(f"[{self.server_uuid}] Sent USER_ADVERTISE to server {server_id}")
                        except Exception as e:
                            print(f"[{self.server_uuid}] Failed to send USER_ADVERTISE to {server_id}: {e}")

                    continue

                # --- Direct message routing ---
                if msg_type == "MSG_DIRECT":
                    recipient = frame.get("to", "")
                    sender = frame.get("from", "")

                    if recipient not in self.user_locations:
                        # NOTE: cross-server routing requires user_locations[recipient] = <server_id>.
                        # You haven't implemented USER_ADVERTISE yet, so remote routing won't work.
                        await ws.send(json.dumps({"type": "Error", "content": f"{recipient} not connected"}))
                        continue

                    if self.user_locations[recipient] == "local":
                        try:
                            # deliver to local user as USER_DELIVER
                            message = deepcopy(self.JSON_base_template)
                            message["type"] = "USER_DELIVER"
                            message["from"] = self.server_uuid
                            message["to"] = recipient
                            message["ts"] = frame.get("ts")
                            payload = frame.get("payload", {}) or {}
                            payload["sender"] = sender
                            message["payload"] = payload
                            await self.local_users[recipient].websocket.send(json.dumps(message))
                            print(f"DEBUG: MSG_DIRECT delivered to {recipient} from {sender}")
                        except Exception:
                            await self.cleanup_client(recipient)
                            
                            
                    else:
                        try:
                            server_location = self.user_locations[recipient]
                            
                            # Create SERVER_DELIVER message
                            server_deliver_msg = deepcopy(self.JSON_base_template)
                            server_deliver_msg["type"] = "SERVER_DELIVER"
                            server_deliver_msg["from"] = self.server_uuid
                            server_deliver_msg["to"] = server_location
                            server_deliver_msg["ts"] = frame.get("ts") # not sure if this is the correct way...

                            # Include original payload + metadata
                            payload = frame.get("payload", {})
                            if not isinstance(payload, dict):
                                payload = payload
                            
                            payload["sender"] = sender
                            payload["user_id"] = recipient  
                            payload["original_ts"] = frame.get("ts")  # Preserve original timestamp
                            
                            server_deliver_msg["payload"] = payload

                            #server_deliver_msg["sig"] = server sig over payload

                            if server_location in self.servers:
                                await self.servers[server_location].websocket.send(json.dumps(server_deliver_msg))
                                print(f'[{self.server_uuid}] Forwarded message from {sender} to {server_location} for user {recipient}')
                            else:
                                print(f"[{self.server_uuid}] Server {server_location} not connected")
                                
                        except Exception as e:
                            print(f"[{self.server_uuid}] Error forwarding message to {server_location}: {e}")
                            
                    continue

                # --- FILE TRANSFER routing (DM only for now) ---
                if msg_type == "FILE_START":
                    payload = frame.get("payload") or {}
                    mode = payload.get("mode", "dm")
                    recipient = frame.get("to", "")
                    sender = frame.get("from", "")

                    if mode != "dm":
                        await ws.send(json.dumps({
                            "type": "ERROR",
                            "code": "PUBLIC_NOT_IMPLEMENTED",
                            "reason": "public channel file transfer not implemented yet"
                        }))
                        continue

                    if recipient not in self.user_locations:
                        await ws.send(json.dumps({"type": "Error", "content": f"{recipient} not connected"}))
                        continue

                    if self.user_locations[recipient] == "local":
                        try:
                            await self.local_users[recipient].websocket.send(json.dumps(frame))
                            print(f"DEBUG: FILE_START routed to {recipient} from {sender}")
                        except Exception:
                            await self.cleanup_client(recipient)
                    else:
                        try:
                            target_server_id = self.user_locations[recipient]
                            link = self.servers.get(target_server_id)
                            if not link:
                                await ws.send(json.dumps({"type": "Error", "content": f"route to {recipient} unknown"}))
                                continue
                            await link.websocket.send(json.dumps(frame))  # forward unchanged
                            print(f"DEBUG: FILE_START forwarded to server {target_server_id} for user {recipient}")
                        except Exception:
                            await self.cleanup_client(recipient)
                    continue

                if msg_type == "FILE_CHUNK":
                    recipient = frame.get("to", "")
                    if recipient not in self.user_locations:
                        await ws.send(json.dumps({"type": "Error", "content": f"{recipient} not connected"}))
                        continue

                    if self.user_locations[recipient] == "local":
                        try:
                            await self.local_users[recipient].websocket.send(json.dumps(frame))
                        except Exception:
                            await self.cleanup_client(recipient)
                    else:
                        try:
                            target_server_id = self.user_locations[recipient]
                            link = self.servers.get(target_server_id)
                            if not link:
                                await ws.send(json.dumps({"type": "Error", "content": f"route to {recipient} unknown"}))
                                continue
                            await link.websocket.send(json.dumps(frame))  # forward unchanged
                        except Exception:
                            await self.cleanup_client(recipient)
                    continue

                if msg_type == "FILE_END":
                    recipient = frame.get("to", "")
                    sender = frame.get("from", "")

                    if recipient not in self.user_locations:
                        await ws.send(json.dumps({"type": "Error", "content": f"{recipient} not connected"}))
                        continue

                    if self.user_locations[recipient] == "local":
                        try:
                            await self.local_users[recipient].websocket.send(json.dumps(frame))
                            print(f"DEBUG: FILE_END delivered to {recipient} from {sender}")
                        except Exception:
                            await self.cleanup_client(recipient)
                    else:
                        try:
                            target_server_id = self.user_locations[recipient]
                            link = self.servers.get(target_server_id)
                            if not link:
                                await ws.send(json.dumps({"type": "Error", "content": f"route to {recipient} unknown"}))
                                continue
                            await link.websocket.send(json.dumps(frame))  # forward unchanged
                            print(f"DEBUG: FILE_END forwarded to server {target_server_id} for user {recipient}")
                        except Exception:
                            await self.cleanup_client(recipient)
                    continue

                # --- Pubkey lookup from DB ---
                if msg_type == "PUB_KEY_REQUEST":
                    payload = frame.get("payload") or {}
                    target = payload.get("recipient_uuid")
                    requester = frame.get("from")

                    # Look up the user's public key from the database
                    pub_key = await self.db.get_user_pubkey(target)

                    if pub_key:
                        # We have the key locally - send it back
                        message_json = deepcopy(self.JSON_base_template)
                        message_json['type'] = "PUB_KEY"
                        message_json['from'] = self.server_uuid 
                        message_json['to'] = requester
                        message_json['ts'] = time.time()
                        message_json['payload'] = {
                            "recipient_pub": pub_key,
                            "recipient_uuid": target
                        }
                        await ws.send(json.dumps(message_json))
                        print(f"[{self.server_uuid}] Sent local public key for {target}")
                        
                    else: 
                        # Get pubkey for user connected to another server
                        try:
                            server_location = self.user_locations.get(target)
                            if not server_location or server_location == "local":
                                # User not found or should be local but isn't in client_public_keys
                                error_msg = deepcopy(self.JSON_base_template)
                                error_msg["type"] = "ERROR"
                                error_msg["from"] = self.server_uuid
                                error_msg["to"] = requester
                                error_msg["payload"] = {"code": "USER_NOT_FOUND", "message": f"User {target} not found"}
                                await ws.send(json.dumps(error_msg))
                                continue
                                
                            if server_location not in self.servers:
                                print(f"[{self.server_uuid}] Server {server_location} not connected")
                                continue

                            # Create the request message  
                            pubkey_request = deepcopy(self.JSON_base_template)
                            pubkey_request['type'] = "PUB_KEY_REQUEST"
                            pubkey_request['from'] = self.server_uuid
                            pubkey_request['to'] = server_location
                            pubkey_request['ts'] = time.time()
                            pubkey_request['payload'] = {
                                "recipient_uuid": target  # Fixed: was 'recipient' before
                            }
                            
                            # Send to the correct server
                            server_uri = f"ws://{self.server_addrs[server_location][0]}:{self.server_addrs[server_location][1]}"
                            
                            # Make sure we have a response queue for this URI
                            if server_uri not in self._incoming_responses:
                                self._incoming_responses[server_uri] = asyncio.Queue()
                                
                            await self.servers[server_location].websocket.send(json.dumps(pubkey_request))
                            print(f"[{self.server_uuid}] Sent PUB_KEY_REQUEST to {server_location} for {target}")

                            # Wait for PUB_KEY response from that specific server
                            response_msg = await self.wait_for_message(server_uri, "PUB_KEY")
                            response_payload = response_msg.get("payload", {})
                            
                            if response_payload.get("recipient_uuid") == target:
                                pub_key = response_payload.get("recipient_pub")
                                
                                # Forward the response back to the original requester
                                message_json = deepcopy(self.JSON_base_template)
                                message_json['type'] = "PUB_KEY"
                                message_json['from'] = self.server_uuid
                                message_json['to'] = requester
                                message_json['ts'] = time.time()
                                message_json['payload'] = {
                                    "recipient_pub": pub_key,
                                    "recipient_uuid": target
                                }
                                await ws.send(json.dumps(message_json))
                                print(f"[{self.server_uuid}] Forwarded public key for {target} to {requester}")
                            else:
                                print(f"[{self.server_uuid}] Received wrong PUB_KEY response")

                        except Exception as e:
                            print(f"[{self.server_uuid}] Error handling cross-server PUB_KEY_REQUEST: {e}")
                            # Send error back to requester
                            error_msg = deepcopy(self.JSON_base_template)
                            error_msg["type"] = "ERROR"
                            error_msg["from"] = self.server_uuid
                            error_msg["to"] = requester
                            error_msg["payload"] = {"code": "PUBKEY_REQUEST_FAILED", "message": str(e)}
                            await ws.send(json.dumps(error_msg))

                    continue

     
        except ConnectionClosedOK:
            print(f"[{self.server_uuid}] Graceful close from {uri}")
        except websockets.exceptions.ConnectionClosed:
            print(f"[{self.server_uuid}] Incoming connection closed {uri}")
        finally:
            server_uuid = self.servers_websockets.pop(ws, None)
            if server_uuid:
                self.servers.pop(server_uuid, None)
                self.server_addrs.pop(server_uuid, None)

            # call clean-up client on user disconnect
            for client_id, link in list(self.local_users.items()):
                if link.websocket == ws:
                    await self.cleanup_client(client_id)
                    self.local_users.pop(client_id, None)
                    self.user_locations.pop(client_id, None)

            print(f"[{self.server_uuid}] Removed peer {server_uuid or '<unknown>'} for {uri}")

    async def handle_server_hello_join(self, frame, ws):
        assigned_id = frame["from"]
        clients_list = []
        for server_id, (host, port, pubkey) in self.server_addrs.items():
            clients_list.append({"user_id": server_id, "host": host, "port": port, "pubkey": pubkey})
        welcome = {
            "type": "SERVER_WELCOME",
            "from": self.server_uuid,
            "to": assigned_id,
            "ts": int(time.time() * 1000),
            "payload": {"assigned_id": assigned_id, "clients": clients_list},
            "sig": "..."
        }
        await ws.send(json.dumps(welcome))
        print(f"[{self.server_uuid}] Sent SERVER_WELCOME to {assigned_id}")

    async def handle_server_announce(self, frame, ws):
        try:
            codec.verify_payload_signature(
                frame, codec.decode_public_key_base64url(frame["payload"]["pubkey"])
            )
            server_uuid = frame["from"]
            host = frame["payload"]["host"]
            port = frame["payload"]["port"]
            pubkey = frame["payload"]["pubkey"]
            peer_uri = f"ws://{host}:{port}"
            if server_uuid not in self.servers:
                peer_ws = await websockets.connect(peer_uri)
                self.servers[server_uuid] = Link(peer_ws)
                task = asyncio.create_task(self.outgoing_connection_handler(peer_ws, peer_uri))
                self.tasks.append(task)
                self.server_addrs[server_uuid] = (host, port, pubkey)
                self.servers_websockets[peer_ws] = server_uuid
                print(f"[{self.server_uuid}] Linked to peer {server_uuid} at {peer_uri}")
        except Exception as e:
            print(f"[{self.server_uuid}] Failed to process SERVER_ANNOUNCE: {e}")
    
    async def udp_discovery_server(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_sock.bind(('', self.UDP_DISCOVERY_PORT))
        loop = asyncio.get_event_loop()
        print(f"[{self.server_uuid}] UDP discovery running on {self.UDP_DISCOVERY_PORT}")
        try:
            while True:
                data, addr = await loop.run_in_executor(None, self.udp_sock.recvfrom, 1024)
                msg = data.decode()
                if msg == "USER_ANNOUNCE":
                    server_uri = f"ws://{self.host}:{self.port}"  # reply with the exact bound host:port
                    self.udp_sock.sendto(server_uri.encode(), addr)
        except asyncio.CancelledError:
            raise
        finally:
            if self.udp_sock:
                self.udp_sock.close()
                print(f"[{self.server_uuid}] UDP discovery server closed")
    
    async def heartbeat_loop(self, delay=15):
        try:
            while not self._shutdown_event.is_set():
                now = time.time()
                to_remove = []

                for server_uuid, link in self.servers.items():
                    ws = link.websocket
                    try:
                        # Ping the websocket to check if it's alive
                        pong_waiter = await ws.ping()
                        await asyncio.wait_for(pong_waiter, timeout=5)
                        
                        link.last_heartbeat = time.time()
                        
                        # Log live status
                        print(f"[{self.server_uuid}] Server {server_uuid} is alive (last heartbeat {now - link.last_heartbeat:.2f}s ago)")

                    except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                        print(f"[{self.server_uuid}] Server {server_uuid} failed heartbeat, closing connection")
                        to_remove.append(server_uuid)
                        await ws.close()

                # Cleanup dead connections
                for server_uuid in to_remove:
                    link = self.servers.pop(server_uuid, None)
                    if link:
                        self.servers_websockets.pop(link.websocket, None)
                        self.server_addrs.pop(server_uuid, None)
                        print(f"[{self.server_uuid}] Cleaned up server {server_uuid}")

                await asyncio.sleep(delay)

        except asyncio.CancelledError:
            print(f"[{self.server_uuid}] Heartbeat loop cancelled")
            raise

    async def debug_loop(self, delay=5):
        try:
            while not self._shutdown_event.is_set():
                print(f"[{self.server_uuid}] --- Server state ---")
                print("Servers:", list(self.servers.keys()) or "(none)")
                print("Users:", list(self.local_users.keys()) or "(none)")
                print("-" * 60)
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            raise

    
    
    
    
    async def shutdown(self):
        print(f"[{self.server_uuid}] Shutting down server...")
        self._shutdown_event.set()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.udp_sock:
            self.udp_sock.close()
        if self.server_websocket:
            self.server_websocket.close()
            await self.server_websocket.wait_closed()

    async def start(self):
        # DB ready + ensure public group row
        await self.db.init()
        await self.db.ensure_public_group(int(time.time()))

        self.server_websocket = await websockets.serve(
            self.incoming_connection_handler, self.host, self.port
        )
        print(f"[{self.server_uuid}] Listening on {self.host}:{self.port}")

        if not self.introducer_mode:
            await self.bootstrap()

        udp_task = asyncio.create_task(self.udp_discovery_server())
        self.tasks.append(udp_task)
        debug_loop = asyncio.create_task(self.debug_loop())
        self.tasks.append(debug_loop)
        heartbeat_loop = asyncio.create_task(self.heartbeat_loop())
        self.tasks.append(heartbeat_loop)
        
        
        # Wait for shutdown event instead of hanging forever
        await self._shutdown_event.wait()

    async def bootstrap(self):
        for entry in self.introducers:
            uri = f"ws://{entry['host']}:{entry['port']}"
            try:
                await self._connect_to_introducer(uri, entry)
                return
            except Exception as e:
                print(f"[{self.server_uuid}] Bootstrap fail {uri}: {e}")
        raise ValueError("Unable to connect to any introducer")

    async def _connect_to_introducer(self, uri, entry):
        self._incoming_responses[uri] = asyncio.Queue()
        ws = await websockets.connect(uri)
        print(f"[{self.server_uuid}] Connected introducer {uri}")
        task = asyncio.create_task(self.outgoing_connection_handler(ws, uri))
        self.tasks.append(task)
        await ws.send(json.dumps(self._build_hello_join(entry)))
        frame = await self.wait_for_message(uri, expected_type="SERVER_WELCOME")
        await self._handle_server_welcome(frame, ws, entry)

    async def _handle_server_welcome(self, frame, ws, entry):
        server_uuid = frame["from"]
        self.server_addrs[server_uuid] = (entry["host"], entry["port"], entry["public_key"])
        self.servers[server_uuid] = Link(ws)
        self.servers_websockets[ws] = server_uuid
        self.selected_bootstrap_server = entry
        for client in frame["payload"].get("clients", []):
            await self._connect_to_peer(client)
        await self._broadcast_server_announce()

    async def _connect_to_peer(self, client):
        server_uuid = client["user_id"]
        host, port, pubkey = client["host"], client["port"], client["pubkey"]
        peer_uri = f"ws://{host}:{port}"
        if server_uuid in self.servers:
            return
        peer_ws = await websockets.connect(peer_uri)
        self.servers[server_uuid] = Link(peer_ws)
        task = asyncio.create_task(self.outgoing_connection_handler(peer_ws, peer_uri))
        self.tasks.append(task)
        self.server_addrs[server_uuid] = (host, port, pubkey)
        self.servers_websockets[peer_ws] = server_uuid
        print(f"[{self.server_uuid}] Linked peer {server_uuid} {peer_uri}")

    def _build_hello_join(self, entry):
        return {
            "type": "SERVER_HELLO_JOIN",
            "from": self.server_uuid,
            "to": f"{entry['host']}:{entry['port']}",
            "ts": int(time.time() * 1000),
            "payload": {"host": self.host, "port": self.port, "pubkey": self.public_key_base64url},
            "sig": "...",
        }

    async def _broadcast_server_announce(self):
        announce = {
            "type": "SERVER_ANNOUNCE",
            "from": self.server_uuid,
            "to": "*",
            "ts": int(time.time() * 1000),
            "payload": {"host": self.host, "port": self.port, "pubkey": self.public_key_base64url},
            "sig": codec.generate_payload_signature(
                {"payload": {"host": self.host, "port": self.port, "pubkey": self.public_key_base64url}},
                self.private_key,
            ),
        }
        for server_uuid, link in self.servers.items():
            try:
                await link.websocket.send(json.dumps(announce))
                print(f"[{self.server_uuid}] Sent SERVER_ANNOUNCE to {server_uuid}")
            except Exception:
                pass


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    introducer_mode = "--intro" in sys.argv
    server = Server(port=port, introducer_mode=introducer_mode)
    try:
        await server.start()
    except KeyboardInterrupt:
        print("Ctrl+C pressed. Shutting down.")
    finally:
        await server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
