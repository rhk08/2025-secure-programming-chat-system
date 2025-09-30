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
        self.servers_websockets = {} # websocket -> server_id
        
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
        # TODO: Notify peers

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

        if ws in self.servers_websockets:
            server_uuid = self.servers_websockets[ws]
            link = self.servers.get(server_uuid)
            if link:
                link.last_heartbeat = time.time()
        
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
                    
            
                # TODO: Handle USER_ADVERTISE (update user_locations + gossip forward)
                if msg_type == "USER_ADVERTISE":
                    print(f"[{self.server_uuid}] Recieved USER_ADVERTISE, Implementation Required")
                    continue
                
                
                # TODO: Handle USER_REMOVE (remove user if mapping matches)
                if msg_type == "USER_REMOVE":
                    print(f"[{self.server_uuid}] Recieved USER_REMOVE, Implementation Required")
                    continue
                
                # TODO: Handle SERVER_DELIVER (forward to local user or to correct server)
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
                    message["from"] = "Server" 
                    message["to"] = client_id
                    message["ts"] = time.time()
                    await ws.send(json.dumps(message))

                    #TODO: USER_ADVERTISE TO OTHER SERVERS
                    
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
                            recipient = self.user_locations[recipient]
                            # send message to specified client according to SOCP format 
                            message = deepcopy(self.JSON_base_template)
                            message["type"] = "SERVER_DELIVER"
                            message["from"] = self.server_uuid
                            message["to"] = recipient
                            message["ts"] = time.time()

                            payload = frame.get("payload", "")

                            if not isinstance(payload, dict):
                                payload = {"content": payload}
                            payload["sender"] = sender
                            message["payload"] = payload

                            await self.connected_clients[recipient].send(json.dumps(message))
                            print(f'DEBUG: message to {recipient} from {sender} sent')

                        except:
                            await self.cleanup_client(recipient)
                        
                # TODO: Handle MSG_PUBLIC_CHANNEL (fan-out to members, maintain channel state)
                # TODO: Handle FILE_START / FILE_CHUNK / FILE_END (forward chunks per §9.4)

                # RSA public key request
                if msg_type == "PUB_KEY_REQUEST":
                    payload = frame.get("payload")
                    target = payload.get("recipient_uuid")

                    pub_key = self.client_public_keys.get(target)

                    message_json = deepcopy(self.JSON_base_template)
                    message_json['type'] = "PUB_KEY"
                    message_json['from'] = self.server_uuid
                    message_json['to'] = frame.get("from")
                    message_json['ts'] = time.time()
                    message_json['payload'] = {
                        "recipient_pub": pub_key,
                        "recipient_uuid": target
                    }

                    await ws.send(json.dumps(message_json))
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

            print(f"[{self.server_uuid}] Removed peer {server_uuid or '<unknown>'} for {uri}")
    
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
        heartbeat_loop = asyncio.create_task(self.heartbeat_loop())
        self.tasks.append(heartbeat_loop)
        
        
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