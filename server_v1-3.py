import asyncio
import websockets
import json
import socket
import time
import signal
import uuid
from copy import deepcopy

from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError
import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

import codec
import base64


# --- Load bootstrap servers ---
with open("bootstrap_servers.json", "r") as f:
    BOOTSTRAP_SERVERS = json.load(f)
# 

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
        self.servers = {}           # server_id -> Link
        self.server_addrs = {}      # server_id -> (host, port, pubkey)
        self.servers_websockets = {}           # u -> server_id
        
        self.local_users = {}       # user_id -> Link
        self.user_locations = {}    # user_id -> "local" | f"server_{id}"
        
        # brought over from previous server implemetation
        self.connected_clients = {}     # username -> websocket (local clients)
        self.remote_users = {}          # username -> server_uri (remote users on peers)
        self.client_public_keys = {}    # username -> public key (local clients)

        with open("SOCP.json", 'r') as file:
            self.JSON_base_template = json.load(file)

        self.host = host
        self.port = port
        self.server_uuid = str(uuid.uuid4())
        self.UDP_DISCOVERY_PORT = 9999
        
        # Pick one server randomly (or some strategy)
        selected = None
        if introducer_mode:
            for entry in BOOTSTRAP_SERVERS:
                if entry["host"] == host and entry["port"] == port:
                    selected = entry
                    break
            if selected is None:
                raise ValueError(f"No matching introducer found for host={host}, port={port} in BOOTSTRAP_SERVERS")
        else:
            self.introducers = introducers or BOOTSTRAP_SERVERS
            
        # --- Load keys ---
        if introducer_mode:
            # Assume keys exist in selected bootstrap server entry
            # Decode Base64URL PEM and load as objects
            self.private_key = serialization.load_pem_private_key(
                base64.urlsafe_b64decode(selected["private_key"]),
                password=None
            )
            self.public_key = serialization.load_pem_public_key(
                base64.urlsafe_b64decode(selected["public_key"])
            )
        else:
            # Generate new keys for normal server
            self.private_key, self.public_key = codec.generate_keys()
        
        # PEM + base64url for sending
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
        self.tasks = []                  # list of asyncio tasks
        self.server_websocket = None
        self.udp_sock = None
        self._incoming_responses = {}  # uri -> asyncio.Queue()
        
        self._shutdown_event = asyncio.Event()
        self.selected_bootstrap_server = {}
        
        print(f"[{self.server_uuid}] Initialized server on {self.host}:{self.port}")

    async def cleanup_client(self, username):
        self.connected_clients.pop(username, None)
        self.client_public_keys.pop(username, None)
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
    
         #implementation below
    
    async def outgoing_connection_handler_handler(self, ws, uri):
        """Handle incoming messages for an outgoing websocket connection."""
        try:
            async for msg in ws:
                frame = json.loads(msg)
                print(f"[{self.server_uuid}] Received {frame['type']} from {frame['from']} on {uri}")
                
                # Put the raw message into the appropriate queue
                if uri in self._incoming_responses:
                    await self._incoming_responses[uri].put(msg)
                else:
                    print(f"[{self.server_uuid}] No queue found for URI: {uri}")
                    
        except websockets.exceptions.ConnectionClosed:
            print(f"[{self.server_uuid}] Connection closed for {uri}")
        except Exception as e:
            print(f"[{self.server_uuid}] Error handling connection {uri}: {e}")
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
    
        
        try:            
            async for msg in ws:
                frame = json.loads(msg)
                msg_type = frame.get("type")

                print(f"[{self.server_uuid}] Received {frame['type']} from {frame['from']}")
                
                if self.introducer_mode and msg_type == "SERVER_HELLO_JOIN":
                    await self.handle_server_hello_join(frame, ws)
                    continue
                
                # --- Server ↔ Server TODOs ---
                # TODO: Handle SERVER_ANNOUNCE (register new server + update server_addrs)
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

                        self.connected_clients.pop(user_id, None)
                        self.user_locations.pop(user_id, None)
                        self.client_public_keys.pop(user_id, None)
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
                    payload = frame.get("payload", {})

                    #old
                    self.connected_clients[client_id] = ws

                    self.client_public_keys[client_id] = payload.get("pubkey")

                    #new
                    self.local_users[client_id] = Link(ws)
                    self.user_locations[client_id] = "local"

                    print(f"[{self.server_uuid}] Added {client_id} to client list")

                    # message formatted to SOCP specifications
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

                # TODO: Handle MSG_DIRECT (wrap into SERVER_DELIVER or deliver locally)
                if msg_type == "MSG_DIRECT":
                    recipient = frame.get("to", "")
                    sender = frame.get("from", "")

                    if recipient not in self.user_locations:
                        await ws.send(json.dumps({"type": "Error", "content": f"{recipient} not connected"}))

                    elif self.user_locations[recipient] == "local":
                        try:
                            # send message to specified client according to SOCP format 
                            message = deepcopy(self.JSON_base_template)
                            message["type"] = "USER_DELIVER"
                            message["from"] = self.server_uuid
                            message["to"] = recipient
                            message["ts"] = frame.get("ts")

                            payload = frame.get("payload", "")
                            payload["sender"] = sender
                            message["payload"] = payload

                            #await self.connected_clients[recipient].send(json.dumps(message))
                            await self.local_users[recipient].websocket.send(json.dumps(message))
                            print(f'DEBUG: message to {recipient} from {sender} sent')

                        except:
                            await self.cleanup_client(recipient)

                    # user is not local, forward to other server YET TO TEST
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
                        
                # TODO: Handle MSG_PUBLIC_CHANNEL (fan-out to members, maintain channel state)
                # TODO: Handle FILE_START / FILE_CHUNK / FILE_END (forward chunks per §9.4)

                # RSA public key request
                if msg_type == "PUB_KEY_REQUEST":
                    payload = frame.get("payload")
                    target = payload.get("recipient_uuid")
                    requester = frame.get("from")

                    pub_key = self.client_public_keys.get(target)

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
        # This happens when .close() is called and shutdown is clean
            print(f"[{self.server_uuid}] Graceful close detected from {uri}")
        
        except websockets.exceptions.ConnectionClosed:
            print(f"[{self.server_uuid}] Incoming connection closed from {uri}")
            
        finally:
            server_uuid = self.servers_websockets.pop(ws, None)
            if server_uuid:
                # Remove live connection
                self.servers.pop(server_uuid, None)
                # Remove metadata
                self.server_addrs.pop(server_uuid, None)

            # call clean-up client on user disconnect
            for client_id, link in list(self.local_users.items()):
                if link.websocket == ws:
                    await self.cleanup_client(client_id)
                    self.local_users.pop(client_id, None)
                    self.user_locations.pop(client_id, None)

            print(f"[{self.server_uuid}] Removed peer {server_uuid or '<unknown>'} for {uri}")
        
    
        """
    # TODO: Send HEARTBEAT frames every 15s to connected servers as above
    async def send_heartbeat(self):
        # TODO: send heartbeat to server (e.g., websocket.send(...))
        print(">> Sending HEARTBEAT")
        # Simulate ACK (in real code, update this when ACK is received from server)
        asyncio.create_task(self.fake_server_ack())

    async def fake_server_ack(self):
        await asyncio.sleep(5)  # pretend server replies after 5s
        self.last_heartbeat_ack = time.time()
        print("<< Received HEARTBEAT ACK")

    async def close_and_reconnect(self):
        print("Connection lost! Closing and reconnecting...")
        self.connected = False
        await asyncio.sleep(2)  # simulate reconnect delay
        self.connected = True
        self.last_heartbeat_ack = time.time()
        print("Reconnected.")

    async def heartbeat_loop(self):
        while True:
            if not self.connected:
                await asyncio.sleep(1)
                continue

            # Send heartbeat
            await self.send_heartbeat()

            # Wait 15s before sending the next one
            await asyncio.sleep(15)

            # Check for timeout (45s without ack)
            if time.time() - self.last_heartbeat_ack > 45:
                await self.close_and_reconnect()       
        """
    
       
    
    async def handle_server_hello_join(self, frame, ws):
        """Handle a SERVER_HELLO_JOIN message when acting as introducer."""
        assigned_id = frame["from"]

        # TODO: Check if assigned_id is valid
        clients_list = []
        for server_id, (host, port, pubkey) in self.server_addrs.items():
            clients_list.append({
                "user_id": server_id,
                "host": host,
                "port": port,
                "pubkey": pubkey
            })

        # Introducer ---> New Server
        welcome = {
            "type": "SERVER_WELCOME",
            "from": self.server_uuid,
            "to": assigned_id,
            "ts": int(time.time() * 1000),
            "payload": {
                "assigned_id": assigned_id,
                "clients": clients_list
            },
            "sig": "..."  # TODO: sign properly
        }

        await ws.send(json.dumps(welcome))
        print(f"[{self.server_uuid}] Sent SERVER_WELCOME to {assigned_id}")

    async def handle_server_announce(self, frame, ws):
        """
        Handle SERVER_ANNOUNCE messages.
        Expects:
        {
            "type": "SERVER_ANNOUNCE",
            "from": "server_id",
            "to": "*",  # Broadcast
            "ts": 1700000000500,
            "payload": {
                "host": "A.B.C.D",          # Server IP
                "port": 12345,              # Server WS port
                "pubkey": "BASE64URL(RSA)"  # Public key
            },
            "sig": "..."
        }
        """
        try:
            # --- Verify sender signature ---
            codec.verify_payload_signature(
                frame, codec.decode_public_key_base64url(frame["payload"]["pubkey"])
            )

            server_uuid = frame["from"]
            host = frame["payload"]["host"]
            port = frame["payload"]["port"]
            pubkey = frame["payload"]["pubkey"]
            peer_uri = f"ws://{host}:{port}"

            # Only connect if we don’t already know this server
            if server_uuid not in self.servers:
                try:
                    peer_ws = await websockets.connect(peer_uri)
                    self.servers[server_uuid] = Link(peer_ws)

                    # Start outgoing handler task
                    task = asyncio.create_task(
                        self.outgoing_connection_handler_handler(peer_ws, peer_uri)
                    )
                    self.tasks.append(task)

                    # Track server metadata
                    self.server_addrs[server_uuid] = (host, port, pubkey)
                    self.servers_websockets[ws] = server_uuid

                    print(f"[{self.server_uuid}] Linked to peer server {server_uuid} at {peer_uri}")

                except Exception as e:
                    print(f"[{self.server_uuid}] Failed to connect to peer {server_uuid}: {e}")

        except Exception as e:
            print(f"[{self.server_uuid}] Failed to process SERVER_ANNOUNCE: {e}")

    
    
    async def udp_discovery_server(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_sock.bind(('', self.UDP_DISCOVERY_PORT))
        loop = asyncio.get_event_loop()
        print(f"[{self.server_uuid}] UDP discovery server running on port {self.UDP_DISCOVERY_PORT}")

        try:
            while True:
                data, addr = await loop.run_in_executor(None, self.udp_sock.recvfrom, 1024)
                msg = data.decode()

                if msg == "USER_ANNOUNCE":
                    server_uri = f"ws://{socket.gethostbyname(socket.gethostname())}:{self.port}"  # LAN ip
                    self.udp_sock.sendto(server_uri.encode(), addr)

        except asyncio.CancelledError:
            print(f"[{self.server_uuid}] UDP discovery server cancelled")
            raise
        finally:
            if self.udp_sock:
                self.udp_sock.close()
                print(f"[{self.server_uuid}] UDP discovery server closed")
    
    
    
    async def debug_loop(self, delay=5):
        """Periodically print all known servers for debugging."""
        try:
            while not self._shutdown_event.is_set():
                print(f"[{self.server_uuid}] --- Server state ---")
            
                # Print Links
                print("Servers (Links):")
                if self.servers:
                    for server_id, link in self.servers.items():
                        # If Link has useful attributes, print them
                        link_info = repr(link)  # or f"{link.host}:{link.port}" if those exist
                        print(f"  {server_id}: {link_info}")
                else:
                    print("  (no servers)")

                # Print server addresses (host, port, pubkey)
                print("Server addresses:")
                if self.server_addrs:
                    for server_id, addr in self.server_addrs.items():
                        host, port, pubkey = addr
                        print(f"  {server_id}: host={host}, port={port}, pubkey={pubkey[:10]}...")  # show only first 10 chars
                else:
                    print("  (no server addresses)")

                # 
                
                print("-" * 60)
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            print(f"[{self.server_uuid}] Debug loop cancelled")
            raise

    
    
    
    
    
    async def shutdown(self):
        """Clean shutdown of all tasks and connections."""
        print(f"[{self.server_uuid}] Shutting down server...")

        # Signal shutdown
        self._shutdown_event.set()

        # Cancel all background tasks
        for task in self.tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)

        # Close UDP socket if still open
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception as e:
                print(f"[{self.server_uuid}] Error closing UDP socket: {e}")
            self.udp_sock = None

        # Close server websocket
        if self.server_websocket:
            self.server_websocket.close()
            await self.server_websocket.wait_closed()
    
    async def start(self):
        self.server_websocket = await websockets.serve(
            self.incoming_connection_handler,
            self.host,
            self.port
        )

        role = "INTRODUCER" if self.introducer_mode else "NORMAL"
        print(f"[{self.server_uuid}] Listening on {self.host}:{self.port} ({role})")
        
        if not self.introducer_mode:
            await self.bootstrap()
        

        # TODO: Start user connection handler (separate from server connections)
        # Start UDP discovery as background task
        udp_task = asyncio.create_task(self.udp_discovery_server())
        self.tasks.append(udp_task)
        debug_loop = asyncio.create_task(self.debug_loop())
        self.tasks.append(debug_loop)
        
        
        # Wait for shutdown event instead of hanging forever
        await self._shutdown_event.wait()

    async def bootstrap(self):
        """Attempt to connect to introducers and join the network."""
        for entry in self.introducers:
            uri = f"ws://{entry['host']}:{entry['port']}"
            try:
                await self._connect_to_introducer(uri, entry)
                return  # success → exit bootstrap
            except Exception as e:
                print(f"[{self.server_uuid}] Failed bootstrap with {uri}: {e}")

        # If loop completes without success
        raise ValueError(f"[{self.server_uuid}] Unable to connect to any static introducer")

    async def _connect_to_introducer(self, uri, entry):
        """Establish connection to a single introducer and perform join handshake."""
        # Queue for responses from this introducer
        self._incoming_responses[uri] = asyncio.Queue()

        ws = await websockets.connect(uri)
        print(f"[{self.server_uuid}] Connected to introducer {uri}")

        # Start a handler task for this connection
        task = asyncio.create_task(self.outgoing_connection_handler_handler(ws, uri))
        self.tasks.append(task)

        # Send join request
        await ws.send(json.dumps(self._build_hello_join(entry)))

        # Wait for SERVER_WELCOME
        frame = await self.wait_for_message(uri, expected_type="SERVER_WELCOME")
        if frame["type"] != "SERVER_WELCOME":
            raise ValueError(f"Unexpected frame from introducer: {frame['type']}")

        # Process welcome
        await self._handle_server_welcome(frame, ws, entry)

    async def _handle_server_welcome(self, frame, ws, entry):
        """Handle SERVER_WELCOME frame from introducer."""
        # Save bootstrap server
        server_uuid = frame["from"]
        self.server_addrs[server_uuid] = (entry["host"], entry["port"], entry["public_key"])
        self.servers[server_uuid] = Link(ws)
        self.servers_websockets[ws] = server_uuid
        self.selected_bootstrap_server = entry

        # Connect to additional servers returned by introducer
        for client in frame["payload"].get("clients", []):
            await self._connect_to_peer(client)

        # After joining → announce ourselves
        await self._broadcast_server_announce()

    async def _connect_to_peer(self, client):
        """Connect to a peer server returned by introducer."""
        server_uuid = client["user_id"]
        host, port, pubkey = client["host"], client["port"], client["pubkey"]
        peer_uri = f"ws://{host}:{port}"

        if server_uuid in self.servers:
            return  # already connected

        try:
            peer_ws = await websockets.connect(peer_uri)
            self.servers[server_uuid] = Link(peer_ws)

            # Start handler
            task = asyncio.create_task(self.outgoing_connection_handler_handler(peer_ws, peer_uri))
            self.tasks.append(task)

            # Record metadata
            self.server_addrs[server_uuid] = (host, port, pubkey)
            self.servers_websockets[peer_ws] = server_uuid

            print(f"[{self.server_uuid}] Linked to peer {server_uuid} at {peer_uri}")
        except Exception as e:
            print(f"[{self.server_uuid}] Failed to connect to peer {server_uuid}: {e}")

    def _build_hello_join(self, entry):
        """Construct SERVER_HELLO_JOIN message for introducer."""
        return {
            "type": "SERVER_HELLO_JOIN",
            "from": self.server_uuid,
            "to": f"{entry['host']}:{entry['port']}",
            "ts": int(time.time() * 1000),
            "payload": {
                "host": self.host,
                "port": self.port,
                "pubkey": self.public_key_base64url,
            },
            "sig": "...",  # TODO: sign properly
        }

    async def _broadcast_server_announce(self):
        """Broadcast SERVER_ANNOUNCE to all connected servers."""
        announce = {
            "type": "SERVER_ANNOUNCE",
            "from": self.server_uuid,
            "to": "*",
            "ts": int(time.time() * 1000),
            "payload": {
                "host": self.host,
                "port": self.port,
                "pubkey": self.public_key_base64url,
            },
            "sig": codec.generate_payload_signature(
                {"payload": {
                    "host": self.host,
                    "port": self.port,
                    "pubkey": self.public_key_base64url,
                }},
                self.private_key,
            ),
        }

        for server_uuid, link in self.servers.items():
            try:
                await link.websocket.send(json.dumps(announce))
                print(f"[{self.server_uuid}] Sent SERVER_ANNOUNCE to {server_uuid}")
            except Exception as e:
                print(f"[{self.server_uuid}] Failed to send SERVER_ANNOUNCE to {server_uuid}: {e}")


    
    
    # --- Routing ---
    # TODO: Implement route_to_user(user_id, frame) per §10
    #       - If local_users[user_id] → send USER_DELIVER
    #       - Else if user_locations[user_id] == server_id → send SERVER_DELIVER
    #       - Else → send ERROR(USER_NOT_FOUND)
    
    # --- Database ---
    # TODO: Implement persistent database layer per §15
    #       - register_user(user_id, pubkey, meta)
    #       - get_pubkey(user_id)
    #       - store profiles, public channel state
    #       - enforce NAME_IN_USE, BAD_KEY, INVALID_SIG, etc.

    # --- Client commands ---
    # TODO: Implement /list → return known online users
    # TODO: Implement /tell <user> <text> → DM
    # TODO: Implement /all <text> → Public channel message
    # TODO: Implement /file <user> <path> → File transfer

async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    introducer_mode = "--intro" in sys.argv
    server = Server(port=port, introducer_mode=introducer_mode)
    
    try:
        await server.start()
    except KeyboardInterrupt:
        print("\nCtrl+C pressed. Initiating graceful Server shutdown.")
    finally:
        await server.shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # This catches KeyboardInterrupt that might escape the main() function
        print("\nShutdown complete.\n")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")