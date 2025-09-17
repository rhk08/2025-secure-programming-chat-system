import asyncio
import websockets
import json
import socket
import time
import signal
import uuid

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

class Server:
    def __init__(self, host="127.0.0.1", port=9000, introducers=None, introducer_mode=False):
         # --- Server state ---
        self.servers = {}           # server_id -> Link
        self.server_addrs = {}      # server_id -> (host, port)
        self.local_users = {}       # user_id -> Link
        self.user_locations = {}    # user_id -> "local" | f"server_{id}"
        
        
        
        
        self.host = host
        self.port = port
        self.server_uuid = str(uuid.uuid4())
        
        
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
                    # TODO servers -> Link
                    
                    # Save other servers
                    for client_server in frame["payload"].get("clients", []):
                        server_uuid = client_server["user_id"]
                        self.server_addrs[server_uuid] = (client_server["host"], client_server["port"], client_server["pubkey"])
                        # TODO servers -> Link
                        
                        # TODO SERVER_ANNOUNCE
                    
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
                print(f"[{self.server_uuid}] Received {frame['type']} from {frame['from']}")
                
                if self.introducer_mode and frame["type"] == "SERVER_HELLO_JOIN":
                    # Should check availability
                    assigned_id = frame["from"]
                    
                    # TODO: Properly include array of known clients
                    
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
                # TODO: Handle USER_REMOVE (remove user if mapping matches)
                # TODO: Handle SERVER_DELIVER (forward to local user or to correct server)
                # TODO: Handle HEARTBEAT (update health state, maybe reply)
                # TODO: Handle ACK (log/track successful delivery)
                # TODO: Handle ERROR (parse code, log, maybe correct state)

                # --- User ↔ Server TODOs ---
                # TODO: Handle USER_HELLO (register local user, broadcast USER_ADVERTISE)
                # TODO: Handle MSG_DIRECT (wrap into SERVER_DELIVER or deliver locally)
                # TODO: Handle MSG_PUBLIC_CHANNEL (fan-out to members, maintain channel state)
                # TODO: Handle FILE_START / FILE_CHUNK / FILE_END (forward chunks per §9.4)
                    
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
    
    async def heartbeat_loop(self):
        # TODO: Send HEARTBEAT frames every 15s to connected servers
        # TODO: Detect 45s timeout -> close and reconnect
        return
    
    
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
        self.server_websocket = await websockets.serve(self.incoming_connection_handler, self.host, self.port)
        
        role = "INTRODUCER" if self.introducer_mode else "NORMAL"
        print(f"[{self.server_uuid}] Listening on {self.host}:{self.port} ({role})")
        
        if not self.introducer_mode:
            await self.bootstrap()
        
        # TODO: Start heartbeat_loop as a background task
        # self.tasks.append(asyncio.create_task(self.heartbeat_loop()))

        # TODO: Start user connection handler (separate from server connections)
        
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