import asyncio
import websockets
import json
import socket
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from copy import deepcopy
import time 
import uuid

UDP_DISCOVERY_PORT = 9999
HEARTBEAT_INTERVAL = 10

class Client:
    def __init__(self):
        self.websocket = None
        self.client_id = "ERROR Client_UUID not assigned!"
        self._pending_key_requests = {}
        
        # friends list
        self.friends_by_id = {}
        self.friends_by_name = {}


        # generate keys using cryptography library (same as server)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        # export in PEM format
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_base64url = base64.urlsafe_b64encode(public_key_pem).decode('utf-8')

        self.server_uri = None
        self._incoming_responses = asyncio.Queue()
        
        self.message_history = {}
        self.unread_messages = {}

        self.JSON_base_template = self._load_json("SOCP.json")

    # ---------------- Load JSON template from file ----------------
    def _load_json(self, file_path):
        with open(file_path, 'r') as file:
            return json.load(file)

    # ---------------- LAN server discovery ----------------
    def discover_server(self, timeout=3):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(b"USER_ANNOUNCE", ('<broadcast>', UDP_DISCOVERY_PORT))
        try:
            data, addr = sock.recvfrom(1024)
            self.server_uri = data.decode()
            print(f"[i] Discovered server at {self.server_uri}")
        except socket.timeout:
            print("[!] No server found on LAN")
        finally:
            sock.close()

    # ---------------- RSA encryption ----------------
    async def encrypt_message(self, message, recipient_pubkey_b64url):
        pem_bytes = base64.urlsafe_b64decode(recipient_pubkey_b64url.encode("utf-8"))
        recipient_pubkey = serialization.load_pem_public_key(pem_bytes)
        
        ciphertext = recipient_pubkey.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode("utf-8")

    # ---------------- RSA decryption ----------------
    async def decrypt_message(self, encrypted_message_b64):
        ciphertext = base64.b64decode(encrypted_message_b64)
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode("utf-8")
    
    # ---------------- Create message signature ----------------
    async def sign_message(self, sender_privkey, ciphertext, sender_id, recipient_id, timestamp):
        # ensure timestamp is consistent (6 decimal places)
        ts_str = f"{timestamp:.6f}"

        # Concatenate string exactly the same way for signing and verification
        sign_data = f"{ciphertext}|{sender_id}|{recipient_id}|{ts_str}".encode('utf-8')

        signature = sender_privkey.sign(
            sign_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        signature_b64url = base64.urlsafe_b64encode(signature).decode('utf-8')

        # print("\n[! DEBUG] --- Signing Message ---")
        # print(f"Sender UUID: {self.client_id}")
        # print(f"Recipient UUID: {recipient_id}")
        # print(f"Timestamp: {timestamp}")
        # print(f"Ciphertext: {ciphertext}")
        # sign_data = f"{ciphertext}|{self.client_id}|{recipient_id}|{timestamp:.6f}".encode('utf-8')
        # print(f"Signing bytes: {sign_data}")
        # print(f"Signature (b64url): {signature_b64url}")

        return signature_b64url

    # ---------------- Verify message signature ----------------
    async def verify_message(self, msg_direct):
        try:
            payload = msg_direct.get("payload", {})
            ciphertext = payload.get("ciphertext")
            signature_b64url = payload.get("content_sig")
            sender_pubkey_b64url = payload.get("sender_pub")
            sender = payload.get("sender")
            recipient = msg_direct.get("to")
            ts = float(msg_direct.get("ts"))  # ensure float

            if not (ciphertext and signature_b64url and sender_pubkey_b64url):
                print("[! DEBUG ] missing ciphertext, signature, or sender_pub")
                return False

            # decode sender pub key
            pem_bytes = base64.urlsafe_b64decode(sender_pubkey_b64url)
            sender_pubkey_obj = serialization.load_pem_public_key(pem_bytes)

            # reconstruct signed string 
            ts_str = f"{ts:.6f}"
            sign_data = f"{ciphertext}|{sender}|{recipient}|{ts_str}".encode('utf-8')

            # decode signature
            signature = base64.urlsafe_b64decode(signature_b64url)

            # DEBUG OUTPUT
            # print("\n[! DEBUG] --- Signature Verification ---")
            # print(f"Sender UUID: {sender}")
            # print(f"Recipient UUID: {recipient}")
            # print(f"Timestamp (float): {ts}")
            # print(f"Timestamp string: {ts_str}")
            # print(f"Ciphertext: {ciphertext}")
            # print(f"Reconstructed signed bytes: {sign_data}")
            # print(f"Signature (b64url): {signature_b64url}")
            # print(f"Signature bytes: {signature}")
            
            # verify
            sender_pubkey_obj.verify(
                signature,
                sign_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True

        except InvalidSignature:
            print("[! DEBUG] Signature INVALID!")
            return False
        except Exception as e:
            print(f"[! DEBUG] Verification error: {e}")
            return False

    
    # ---------------- Sign-in ----------------
    async def signin(self):
        while True:
  
            # message formatted to SOCP specifications
            message = deepcopy(self.JSON_base_template)
            message["type"] = "USER_HELLO"
            message["from"] = "Guest"
            message["to"] = "Server" #TODO: sub with actual server details 
            message["ts"] = time.time()
            message["payload"] = {
                "client": "cli-v1",
                "pubkey": self.public_key_base64url,
                "enc_pubkey": self.public_key_base64url
            }

            await self.websocket.send(json.dumps(message))
            
            response = json.loads(await self.websocket.recv())
            self.client_id = response.get("to")

            #sharing available commands with user on join
            print("[i] Available commands:")
            print("  chat <recipient> <message>  - send a message to a user or 'Group'")
            print("  history [user]              - show message history with a specific user, or all unread messages if no user is specified")
            print("  add <uuid> <name>          - add a user as a friend")
            print("  friends                    - shows a list of your friends")
            print("  whoami                     - show your current username")
            print("  ping                       - send a ping to the server")
            print("  list                       - list all connected users")
            print("  quit or q                  - exit the client")
            print("  help or -h                 - show this help message")

            return
    
    def store_message(self, msg, plaintext):
        sender = msg.get('from', 'Unknown') 
        recipient = msg.get('to', 'Unknown')  # fallback to Group
        timestamp = msg.get('ts', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
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
                if msg.get("type") == "PUB_KEY":
                    await self._incoming_responses.put(msg)
                # elif msg.get("type") == "pong":
                #     await self._incoming_responses.put(msg)
                # elif msg.get("type") == "user_list":
                #     await self._incoming_responses.put(msg)
                else:
                    # handle chat, heartbeat, etc
                    if msg['type'] == "USER_DELIVER":
                        
                        print("message received !!")
                        if await self.verify_message(msg):
                            
                            payload = msg.get("payload")
                            ciphertext = payload.get("ciphertext")

                            if ciphertext:
                                plaintext = await self.decrypt_message(ciphertext)
                                self.store_message(msg, plaintext)

                                if self.friends_by_id.get(msg.get('from')) == None:
                                    print(f"\n[!] Message received from {msg.get('from')}:")
                                else:
                                    print(f"\n[!] Message received from {self.friends_by_id.get(msg.get('from'))}:")
                                print(plaintext)
                                print(f"[{self.client_id}] Enter command or message ('help' for commands): ", end="", flush=True)

                            else:
                                print("[! DEBUG] Message received but signature verification failed")
                                     
                    elif msg["type"] == "heartbeat":
                        await self.websocket.send(json.dumps({"type": "heartbeat_ack", "sender": self.client_id}))
        except websockets.exceptions.ConnectionClosed:
            print("\n[!] Connection closed")


    def add_friend(self, friend_id, friend_name):
        if len(friend_name) > 12:
            print("Name too long!")
            return

        if friend_name == "Group":
            print("Name cannot be 'Group'!")
            return

        # If the name is already taken by another UUID
        if friend_name in self.friends_by_name and self.friends_by_name[friend_name] != friend_id:
            print(f"Name {friend_name} is already taken by another user!")
            return

        # If the UUID already exists, update its name
        if friend_id in self.friends_by_id:
            old_name = self.friends_by_id[friend_id]
            if old_name != friend_name:
                # remove old name entry
                if old_name in self.friends_by_name:
                    del self.friends_by_name[old_name]
                print(f"Updated friend {friend_id}: {old_name} to {friend_name}")

        else:
            print(f"Friend added: {friend_name} ({friend_id})")

        # Add/update both dicts
        self.friends_by_id[friend_id] = friend_name
        self.friends_by_name[friend_name] = friend_id

    # --- Client commands ---
    # TODO: Implement /list → return known online users
    # TODO: Implement /tell <user> <text> → DM
    # TODO: Implement /all <text> → Public channel message
    # TODO: Implement /file <user> <path> → File transfer
    
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
                print("  add <uuid> <name>          - add a user as a friend")
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
                print("[i] feature not yet available")
                # await self.websocket.send(json.dumps({"type": "ping", "sender": self.client_id}))

                # # Wait for pong
                # while True:
                #     msg = await self._incoming_responses.get()
                #     if msg.get("type") == "pong":
                #         print(f"[i] Server response: {msg.get('content', 'Pong!')}")
                #         break
                # continue

            # ----- List Users -----
            elif cmd == "list":
                print("[i] feature not yet available")

                # await self.websocket.send(json.dumps({"type": "list_users", "sender": self.client_id}))

                # # Wait for user_list
                # while True:
                #     msg = await self._incoming_responses.get()
                #     if msg.get("type") == "user_list":
                #         users = msg.get("content", [])
                #         if users:
                #             print("[i] Connected users:")
                #             for u in users:
                #                 if u == self.client_id:
                #                     print(f"  - {u} (That's You!)")
                #                 else:
                #                     print(f"  - {u}")
                #         else:
                #             print("[i] No users currently connected.")
                #         break
                # continue
            
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

                # Check if recipient is on friends list
                target_friend = self.friends_by_name.get(cmd_parts[1])
                if target_friend != None:
                    target_user = target_friend
                else:
                    target_user = cmd_parts[1]

                target_friend = cmd_parts[1]

                # Get the history for the target user (default empty list)
                target_user_history = self.message_history.get(target_user, [])

                if not target_user_history:
                    print(f"[i] No message history with {target_friend}.")
                    continue

                # Display the message history
                print(f"[i] Message history with {target_friend}:")
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

            # ----- Add -----
            elif cmd == "add":
                if len(cmd_parts) < 3:
                    print("[!] Usage: add <name> <uuid>")
                    continue
                
                self.add_friend(cmd_parts[1], cmd_parts[2])

            # ----- Friends -----
            elif cmd == "friends":
                if not self.friends_by_id:
                    print("[i] You have no friends added yet.")
                else:
                    print("\n[i] Friends list:")
                    print(f"{'Name'} | {'UUID':<40}")
                    print("-" * 55)
                    for friend_id, friend_name in self.friends_by_id.items():
                        print(f"{friend_name} | {friend_id:<40}")
                continue

            # ----- Chat -----
            elif cmd == "chat":
                if len(cmd_parts) < 3:
                    print("[!] Usage: chat <recipient> <message>")
                    continue
                
                # Check if recipient is on friends list
                friend_receiving = self.friends_by_name.get(cmd_parts[1])
                if friend_receiving != None:
                    recipient = friend_receiving
                    friend_receiving = cmd_parts[1]
                else:
                    recipient = cmd_parts[1]

                message = cmd_parts[2]

                if recipient == 'Group':
                    print("[i] Group messaging to be implemented")
                    continue
                
                else:
                    # request recipient's public key
                    pubkey_request = deepcopy(self.JSON_base_template)
                    pubkey_request['type'] = "PUB_KEY_REQUEST"
                    pubkey_request['from'] = self.client_id
                    pubkey_request['to'] = "Server"
                    pubkey_request['ts'] = time.time()
                    pubkey_request['payload'] = {
                        "recipient_uuid": recipient
                        }
                    await self.websocket.send(json.dumps(pubkey_request))

                    # wait for PUB_KEY response 
                    recipient_pubkey_b64url = None
                    while True:
                        msg = await self._incoming_responses.get()
                        payload = msg.get("payload", {})
                        if msg.get("type") == "PUB_KEY" and payload.get("recipient_uuid") == recipient:
                            recipient_pubkey_b64url = payload.get("recipient_pub")
                            break

                    if not recipient_pubkey_b64url:
                        print(f"[!] Cannot obtain public key for {friend_receiving}")
                        continue

                    # encrypt the message
                    encrypted_payload = await self.encrypt_message(message, recipient_pubkey_b64url)
                    timestamp = int(time.time() * 1000)

                    signature_b64url = await self.sign_message(
                        self.private_key,
                        encrypted_payload,
                        self.client_id,
                        recipient,
                        timestamp
                    )

                    # send MSG_DIRECT
                    msg_direct = deepcopy(self.JSON_base_template)
                    msg_direct['type'] = "MSG_DIRECT"
                    msg_direct['from'] = self.client_id
                    msg_direct['to'] = recipient
                    msg_direct['ts'] = timestamp
                    msg_direct['payload'] = {
                        "ciphertext": encrypted_payload,
                        "sender_pub": self.public_key_base64url,
                        "content_sig": signature_b64url
                    }

                    self.store_message(msg_direct, message)  # store plaintext locally
                    await self.websocket.send(json.dumps(msg_direct))
                    print("[i] Message sent successfully!")

            # ----- Unknown command -----
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

# import asyncio
# import websockets
# import json
# import socket
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import AES, PKCS1_OAEP
# from Crypto.Random import get_random_bytes
# import base64
# import time

# class Client:
#     def __init__(self):
#         self._incoming_responses = asyncio.Queue() # Queue to allow for the program to wait on specific responses
#         self.websocket = None

    
#     async def shutdown(self):
#         return
    
#     async def start(self):
#         async with websockets.connect() as socket:
#             self.websocket = socket
            
            
#         return

# if __name__ == "__main__":
#     client = Client()
#     asyncio.run(client.start())
#     try:
#         asyncio.run(client.start())
#     except KeyboardInterrupt:
#         print("\nCtrl+C pressed. Initiating graceful Client shutdown.")
#         asyncio.run(client.shutdown())
#     except Exception as e:
#         print(f"\nAn unexpected error occurred: {e}")