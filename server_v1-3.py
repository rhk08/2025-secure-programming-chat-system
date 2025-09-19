import asyncio
import websockets
import json
import socket
import time
import signal
import uuid
from copy import deepcopy

import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

import base64

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    return private_key, public_key

def generate_payload_signature(message: dict, private_key):
    
    """
    Signs the 'payload' field of a message dictionary using the given RSA private key.
    
    Args:
        message (dict): The message containing a 'payload' field.
        private_key: RSAPrivateKey object used to sign.
    
    Returns:
        str: Base64URL-encoded signature.
    
    Raises:
        ValueError: If 'payload' field is missing from the message.
    """
    
    if 'payload' not in message:
        raise ValueError("Message does not contain a 'payload' field.")
    
    payload_canonical = json.dumps(message['payload'], separators=(',', ':'), sort_keys=True).encode('utf-8')
    signature_bytes = private_key.sign(
        payload_canonical, # the message bytes
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), # PSS padding with SHA256-based MGF
        hashes.SHA256() # hash function applied to message
    )
    
    return base64.urlsafe_b64encode(signature_bytes).decode('utf-8')

def verify_payload_signature(message: dict, public_key):
    """
    Verifies the 'sig' field of a message against its 'payload' using the given public key.
    
    Args:
        message (dict): The message containing 'payload' and 'sig'.
        public_key: RSAPublicKey object used to verify the signature.
    
    Returns:
        bool: True if signature is valid.
    
    Raises:
        ValueError: If 'payload' or 'sig' field is missing.
        cryptography.exceptions.InvalidSignature: If signature is invalid.
    """
    
    if 'payload' not in message:
        raise ValueError("Message does not contain a 'payload' field.")
    if 'sig' not in message:
        raise ValueError("Message does not contain a 'sig' field.")
    
    # Canonicalize the payload JSON (sorted keys, compact)
    payload_canonical = json.dumps(message['payload'], separators=(',', ':'), sort_keys=True).encode('utf-8')
    
    # Decode the Base64URL signature
    signature_bytes = base64.urlsafe_b64decode(message['sig'])
    
    # Verify the signature
    try:
        public_key.verify(
            signature_bytes,
            payload_canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        raise InvalidSignature("Signature verification failed.")



"""
Every Protocol Message MUST have:
[JSON]
{
    "type": "STRING", // Payload type, case-sensitive
    "from": "UUID",        
    "to":   
    "ts":   
    "UUID",        
    "INT",         
    "payload": { },        
    "sig": "BASE64URL"     
}
"""
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
    def __init__(self, host="0.0.0.0", port=9000, introducers=None, introducer_mode=False):
        # --- Server state ---
        self.servers = {}           # server_id -> Link
        self.server_addrs = {}      # server_id -> (host, port, pubkey)
        
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
            self.private_key, self.public_key = generate_keys()
        
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
        self._incoming_responses = {}  # uri -> asyncio.Queue()
        
        self._shutdown_event = asyncio.Event()
        self.selected_bootstrap_server = {}
        
        print(f"[{self.server_uuid}] Initialized server on {self.host}:{self.port}")

    async def cleanup_client(self, username):
        self.connected_clients.pop(username, None)
        self.client_public_keys.pop(username, None)
        print(f"[-] Removed client: {username}")
        # TODO: Notify peers

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
    
    # ---------------------- UDP Discovery ----------------------
    async def udp_discovery_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', self.UDP_DISCOVERY_PORT))
        loop = asyncio.get_event_loop()
        print(f"[{self.server_uuid}] UDP discovery server running on port {self.UDP_DISCOVERY_PORT}")
        try:
            while True:
                data, addr = await loop.run_in_executor(None, sock.recvfrom, 1024)
                msg = data.decode()

                if msg == "USER_ANNOUNCE":
                    server_uri = f"ws://{socket.gethostbyname(socket.gethostname())}:{self.port}" # LAN ip
                    sock.sendto(server_uri.encode(), addr)

        except asyncio.CancelledError:
            sock.close()
            print(f"[{self.server_uuid}] UDP discovery server closed")
    
    async def bootstrap(self):
        for entry in self.introducers:
            uri = f"ws://{entry['host']}:{entry['port']}"
            try:
                # Create queue for this URI before connecting
                self._incoming_responses[uri] = asyncio.Queue()
                
                ws = await websockets.connect(uri)
                print(f"[{self.server_uuid}] Connected to introducer {uri}")
                
                # Start a task to handle incoming messages on this connection
                message_handler_task = asyncio.create_task(
                    self.outgoing_connection_handler_handler(ws, uri)
                )
                self.tasks.append(message_handler_task)
                
                # New Server ---> Introducer
                hello = {
                    "type": "SERVER_HELLO_JOIN",
                    "from": self.server_uuid,
                    "to": f"{entry['host']}:{entry['port']}",
                    "ts": int(time.time() * 1000), 
                    "payload": {
                        "host": self.host,
                        "port": self.port,
                        "pubkey": self.public_key_base64url,
                    },
                    "sig": "..."
                }
                await ws.send(json.dumps(hello))
                
                # Now wait_for_message will work because the incoming_connection_handler task is reading
                frame = await self.wait_for_message(uri, expected_type="SERVER_WELCOME")
                
                if frame["type"] == "SERVER_WELCOME":
                    # Save bootstrap server
                    server_uuid = frame["from"]  # Fixed variable name
                    self.server_addrs[server_uuid] = (entry["host"], entry["port"], entry["public_key"])
                    server_link = Link(ws)
                    self.server_addrs[server_link]
                    
                    # Save other servers
                    for client_server in frame["payload"].get("clients", []):
                        server_uuid = client_server["user_id"]
                        self.server_addrs[server_uuid] = (client_server["host"], client_server["port"], client_server["pubkey"])
                    

                        # TODO SERVER_ANNOUNCE
                        
                        
                        
                        # TODO servers -> Link
                        
                        
                    
                    self.selected_bootstrap_server = entry
                    
                    
                    # TODO: Send SERVER_ANNOUNCE to all servers after join
                    # TODO: Establish links to all returned servers

                    break
                        
                else:
                    print(f"[{self.server_uuid}] Unexpected frame: {frame['type']}")
                
            except Exception as e:
                print(f"[{self.server_uuid}] Failed to connect {uri}: {e}")
                
        else:  # This runs if the for loop completes without breaking
            raise ValueError(f"[{self.server_uuid}] Unable to connect to any static introducer")

    # Updated incoming_connection_handler for incoming connections (servers connecting to us)
    async def incoming_connection_handler(self, ws):
        """Handle incoming websocket connections (servers connecting to this server)."""
        try:
            # You might want to determine the URI for this connection for queue management
            remote_host, remote_port = ws.remote_address
            uri = f"ws://{remote_host}:{remote_port}"
            
            async for msg in ws:
                frame = json.loads(msg)
                msg_type = frame.get("type")

                print(f"[{self.server_uuid}] Received {frame['type']} from {frame['from']}")
                
                if self.introducer_mode and frame["type"] == "SERVER_HELLO_JOIN":
                    # Should check availability
                    assigned_id = frame["from"]
                    
                    # TODO: Properly include array of known clients
                    
                    # Introducer ---> New Server
                    welcome = {
                        "type": "SERVER_WELCOME",
                        "from": self.server_uuid,
                        "to": assigned_id,
                        "ts": int(time.time() * 1000),
                        "payload": {
                            "assigned_id": assigned_id,
                            "clients": [
                                
                                {"user_id": self.server_uuid,
                                "host": self.host,
                                "port": self.port,
                                "pubkey": self.public_key_base64url}
                            ]
                        },
                        "sig": "..."
                    }
                    await ws.send(json.dumps(welcome))
                    print(f"[{self.server_uuid}] Sent SERVER_WELCOME to {assigned_id}")
                    continue
                
                # --- Server ↔ Server TODOs ---
                # TODO: Handle SERVER_ANNOUNCE (register new server + update server_addrs)
                
                # TODO: Handle USER_ADVERTISE (update user_locations + gossip forward)
                # TODO: Handle USER_REMOVE (remove user if mapping matches) !!
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

                    if sender not in self.user_locations:
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

                            await self.connected_clients[recipient].send(json.dumps(message))
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
                    
        except websockets.exceptions.ConnectionClosed:
            print(f"[{self.server_uuid}] Incoming connection closed from {uri}")
    
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
            
            # Close server websocket
            if self.server_websocket:
                self.server_websocket.close()
                await self.server_websocket.wait_closed()
            
            print(f"[{self.server_uuid}] Shutdown complete")
    
    async def start(self):
        print("1")
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
        
        # Wait for shutdown event instead of hanging forever
        await self._shutdown_event.wait()

    
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
        print("\nShutdown complete.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")