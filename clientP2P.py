import asyncio
import websockets
import json
import socket
import base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

UDP_DISCOVERY_PORT = 9999
HEARTBEAT_INTERVAL = 10

class Client:
    def __init__(self):
        self.websocket = None
        self.client_id = "Guest"
        self._pending_key_requests = {}
        self.rsa_key = RSA.generate(2048)
        self.private_key = self.rsa_key
        self.public_key = self.rsa_key.publickey()
        self.server_uri = None
        self._incoming_responses = asyncio.Queue()
        
        self.message_history = {}
        self.unread_messages = {}

    # ---------------- LAN server discovery ----------------
    def discover_server(self, timeout=3):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(b"CHAT_DISCOVERY", ('<broadcast>', UDP_DISCOVERY_PORT))
        try:
            data, addr = sock.recvfrom(1024)
            self.server_uri = data.decode()
            print(f"[i] Discovered server at {self.server_uri}")
        except socket.timeout:
            print("[!] No server found on LAN")
        finally:
            sock.close()

    # ---------------- RSA/AES encryption ----------------
    async def encrypt_message(self, message, recipient_public_key_pem):
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        recipient_rsa_key = RSA.import_key(recipient_public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(recipient_rsa_key)
        enc_aes_key = cipher_rsa.encrypt(aes_key)
        return {
            "enc_aes_key": base64.b64encode(enc_aes_key).decode(),
            "nonce": base64.b64encode(cipher_aes.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    async def decrypt_message(self, message):
        try:
            enc_aes_key = base64.b64decode(message["enc_aes_key"])
            nonce = base64.b64decode(message["nonce"])
            tag = base64.b64decode(message["tag"])
            ciphertext = base64.b64decode(message["ciphertext"])
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(enc_aes_key)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode()
        except:
            return None

    # ---------------- Sign-in ----------------
    async def signin(self):
        while True:
            client_username = input("Enter username: ")
            message_data = json.dumps({
                "type": "sign_in",
                "content": client_username,
                "sender": self.client_id,
                "public_key": self.public_key.export_key().decode()
            })
            await self.websocket.send(message_data)
            response = json.loads(await self.websocket.recv())
            if response["content"] == "Success":
                self.client_id = client_username
                print(f"[i] Signed in as {client_username}")
                return
            else:
                print("[!] Username unavailable, try again.")

    
    def store_message(self, msg, plaintext):
        sender = msg.get('sender', 'Unkown') 
        recipient = msg.get('recipient', 'Unkown')  # fallback to Group
        timestamp = msg.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
        history_key = sender if recipient == self.client_id else recipient  # store by conversation

        if history_key not in self.message_history:
            self.message_history[history_key] = []
            self.unread_messages[history_key] = 1
        else:
            self.unread_messages[history_key] += 1

        self.message_history[history_key].append({
            "timestamp": timestamp,
            "sender": sender,
            "recipient": recipient,
            "message": plaintext,
            "direction": "in" if sender != self.client_id else "out",
            "seen" : False
        })
        
       
        
    # ---------------- Listen ----------------
    async def listen_for_messages(self):
        try:
            async for json_message in self.websocket:
                msg = json.loads(json_message)
            
                # If this is a public key response, put it in the queue
                if msg.get("type") == "Public Key":
                    await self._incoming_responses.put(msg)
                elif msg.get("type") == "pong":
                    await self._incoming_responses.put(msg)
                elif msg.get("type") == "user_list":
                    await self._incoming_responses.put(msg)
                else:
                    # handle chat, heartbeat, etc
                    if msg["type"] == "chat":
                        plaintext = await self.decrypt_message(msg)
                        """
                        {
                            'type': 'chat', 
                            'recipient': 'Bob', 
                            'sender': 'Alice', 
                            'timestamp': '2025-09-16 02:23:18', 
                            *encryption info
                        }
                        """
                        
                        if plaintext:
                            self.store_message(msg, plaintext)
                            unread_count = self.unread_messages.get(msg["sender"], 0)
                            if unread_count > 0:
                                print(f"\n[!] Message received from {msg['sender']} ({unread_count} unread)")
                            else:
                                print(f"\n[!] Message received from {msg['sender']}")
                            print(f"[{self.client_id}] Enter command or message ('help' for commands): ", end="", flush=True)
                            
                                
                    elif msg["type"] == "heartbeat":
                        await self.websocket.send(json.dumps({"type": "heartbeat_ack", "sender": self.client_id}))
        except websockets.exceptions.ConnectionClosed:
            print("\n[!] Connection closed")

    
    async def send_messages(self):
        loop = asyncio.get_event_loop()

        while True:
            user_input = await loop.run_in_executor(
                None,
                input,
                f"[{self.client_id}] Enter command or message ('help' for commands): "
            )

            if not user_input.strip():
                continue

            # ------------------ Exit ------------------
            if user_input.lower() == "quit" or user_input.lower() == "q":
                await self.websocket.close()
                break

            # ------------------ Commands ------------------
            cmd_parts = user_input.split(maxsplit=2)
            cmd = cmd_parts[0].lower()

            # ----- Help -----
            if cmd in ("help", "-h"):
                print("[i] Available commands:")
                print("  chat <recipient> <message>  - send a message to a user or 'Group'")
                print("  history [user]              - show message history with a specific user, or all unread messages if no user is specified")
                print("  whoami                     - show your current username")
                print("  ping                       - send a ping to the server")
                print("  list                       - list all connected users")
                print("  quit or q                  - exit the client")
                print("  help or -h                 - show this help message")
                
                continue

            # ----- Whoami -----
            elif cmd == "whoami":
                print(f"[i] You are: {self.client_id}")
                continue

            # ----- Ping -----
            elif cmd == "ping":
                await self.websocket.send(json.dumps({"type": "ping", "sender": self.client_id}))

                # Wait for pong
                while True:
                    msg = await self._incoming_responses.get()
                    if msg.get("type") == "pong":
                        print(f"[i] Server response: {msg.get('content', 'Pong!')}")
                        break
                continue

            # ----- List Users -----
            elif cmd == "list":
                await self.websocket.send(json.dumps({"type": "list_users", "sender": self.client_id}))

                # Wait for user_list
                while True:
                    msg = await self._incoming_responses.get()
                    if msg.get("type") == "user_list":
                        users = msg.get("content", [])
                        if users:
                            print("[i] Connected users:")
                            for u in users:
                                if u == self.client_id:
                                    print(f"  - {u} (That's You!)")
                                else:
                                    print(f"  - {u}")
                        else:
                            print("[i] No users currently connected.")
                        break
                continue
            
            # ----- History -----
            elif cmd == "history":
                if len(cmd_parts) < 1:
                    print("[!] Usage: history <user>")
                    continue
                
                if len(cmd_parts) == 1:
                    print("[i] Unread messages per user:")
                    for user, count in self.unread_messages.items():
                        if count > 0:
                            print(f"  - {user}: {count} unread")
                    continue
                
                target_user = cmd_parts[1]

                # Get the history for the target user (default empty list)
                target_user_history = self.message_history.get(target_user, [])

                if not target_user_history:
                    print(f"[i] No message history with {target_user}.")
                    continue

                # Display the message history
                print(f"[i] Message history with {target_user}:")
                for msg in target_user_history:
                    
                    
                    ts = msg.get("timestamp", "")
                    sender = msg.get("sender", "")
                    content = msg.get("message", "")
                    direction = msg.get("direction", "")
                    
                    prefix = "You" if direction == "out" else sender
                    new_tag = " [NEW]" if not msg.get("seen", False) else ""
                    
                    print(f"[{ts}]{new_tag} {prefix}: {content}")
                    
                    # Mark message as seen
                    msg["seen"] = True
                   
                
                self.unread_messages[target_user] = 0
                
                    
                continue

            # ----- Chat -----
            elif cmd == "chat":
                if len(cmd_parts) < 3:
                    print("[!] Usage: chat <recipient> <message>")
                    continue

                recipient = cmd_parts[1]
                message = cmd_parts[2]

                # Request recipient's public key
                await self.websocket.send(json.dumps({
                    "type": "public_key_request",
                    "recipient": recipient,
                    "sender": self.client_id
                }))

                # Wait for key
                pub_key = None
                while True:
                    msg = await self._incoming_responses.get()
                    if msg.get("type") == "Public Key" and msg.get("sender") == recipient:
                        pub_key = msg.get("content")
                        break

                if not pub_key:
                    print(f"[!] Cannot obtain public key for {recipient}")
                    continue

                # Encrypt and send
                enc_data = await self.encrypt_message(message, pub_key)
                payload = {
                    "type": "chat", 
                    "recipient": recipient, 
                    "sender": self.client_id, 
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                    **enc_data
                }
                self.store_message(payload, message)
                
                await self.websocket.send(json.dumps(payload))
                print("[i] Message sent successfully!")
                continue

            # ----- Unknown command / treat as chat -----
            else:
                print("[!] Unknown command. Type 'help' for a list of commands.")
                continue
        
    # ---------------- Start ----------------
    async def start(self):
        self.discover_server()
        if not self.server_uri:
            return
        async with websockets.connect(self.server_uri) as ws:
            self.websocket = ws
            await self.signin()
            await asyncio.gather(self.listen_for_messages(), self.send_messages())

if __name__ == "__main__":
    client = Client()
    asyncio.run(client.start())
