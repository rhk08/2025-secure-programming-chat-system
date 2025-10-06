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
import os
import hashlib
import sys
import codec

UDP_DISCOVERY_PORT = 9999
HEARTBEAT_INTERVAL = 10

# Keep RSA-OAEP payload small enough for 2048-bit keys (≈ 190 bytes max)
FILE_CHUNK_PLAINTEXT = 190
DOWNLOAD_DIR = "downloads"


class Client:
    def __init__(self):
        self.websocket = None
        self.client_id = "ERROR Client_UUID not assigned!"
        self._pending_key_requests = {}

        # friends list
        self.friends_by_id = {}
        self.friends_by_name = {}

        #server pub key
        self.server_pub_key = None

        # Generate keys
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()

        # Export public key in base64url(PEM)
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_base64url = base64.urlsafe_b64encode(public_key_pem).decode('utf-8')
        
        #allow user to specify server uri to connect to for testing purposes
        if len(sys.argv) > 1:
            self.server_uri = sys.argv[1]
        else:
            self.server_uri = None

        self._incoming_responses = asyncio.Queue()

        self.message_history = {}
        self.unread_messages = {}

        self.JSON_base_template = self._load_json("SOCP.json")

        # File receive state
        self.file_rx = {}  # file_id -> {name,size,sha256,received:int,parts:dict}
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    # ---------------- Load JSON template from file ----------------
    def _load_json(self, file_path):
        with open(file_path, "r") as file:
            return json.load(file)

    # ---------------- LAN server discovery ----------------
    def discover_server(self, timeout=3):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(b"USER_ANNOUNCE", ("<broadcast>", UDP_DISCOVERY_PORT))
        try:
            data, addr = sock.recvfrom(1024)
            self.server_uri = data.decode()
            # normalize common localhost alias on some distros
            if self.server_uri.startswith("ws://127.0.1.1:"):
                self.server_uri = self.server_uri.replace("127.0.1.1", "127.0.0.1", 1)
            print(f"[i] Discovered server at {self.server_uri}")
        except socket.timeout:
            print("[!] No server found on LAN")
        finally:
            sock.close()

    # ---------------- RSA (text) encryption/decryption ----------------
    async def encrypt_message(self, message, recipient_pubkey_b64url):
        pem_bytes = base64.urlsafe_b64decode(recipient_pubkey_b64url.encode("utf-8"))
        recipient_pubkey = serialization.load_pem_public_key(pem_bytes)
        ciphertext = recipient_pubkey.encrypt(
            message.encode("utf-8"),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        return base64.b64encode(ciphertext).decode("utf-8")

    async def decrypt_message(self, encrypted_message_b64):
        ciphertext = base64.b64decode(encrypted_message_b64)
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        return plaintext.decode("utf-8")

    # ---------------- Sign / verify ----------------
    async def sign_message(self, sender_privkey, ciphertext, sender_id, recipient_id, timestamp):
        ts_str = f"{timestamp:.6f}"
        sign_data = f"{ciphertext}|{sender_id}|{recipient_id}|{ts_str}".encode("utf-8")
        signature = sender_privkey.sign(
            sign_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return base64.urlsafe_b64encode(signature).decode("utf-8")
    
    # List available commands
    def list_commands(self):
        print("\033[1m[i] Available commands:\033[0m")
        print("  chat <recipient> <message>   - send a message to a user")
        print("  sendfile <recipient> <path>  - send a file to a user (DM)")
        print("  all <message>                - send a group message to all current users")
        print("  history [user]               - show your message history with a user")
        print("  add <uuid> <nickname>        - add a user as a friend")
        print("  friends                      - show a list of your friends")
        print("  whoami                       - show your current UUID")
        print("  list                         - show all current users")
        print("  quit | q                     - exit")
        print("  help | -h                    - show this help")

    async def verify_message(self, msg_direct):
        # verifying signature for user -> user messages (more strict than standard signature in codec)
        try:
            payload = msg_direct.get("payload", {})
            ciphertext = payload.get("ciphertext")
            signature_b64url = payload.get("content_sig")
            sender_pubkey_b64url = payload.get("sender_pub")
            sender = payload.get("sender")
            recipient = msg_direct.get("to")
            ts = float(msg_direct.get("ts"))
            if not (ciphertext and signature_b64url and sender_pubkey_b64url):
                print("[!] [DEBUG] missing ciphertext, signature, or sender_pub")
                return False

            pem_bytes = base64.urlsafe_b64decode(sender_pubkey_b64url)
            sender_pubkey_obj = serialization.load_pem_public_key(pem_bytes)

            ts_str = f"{ts:.6f}"
            sign_data = f"{ciphertext}|{sender}|{recipient}|{ts_str}".encode("utf-8")
            signature = base64.urlsafe_b64decode(signature_b64url)

            sender_pubkey_obj.verify(
                signature,
                sign_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            print("[!] [DEBUG] Signature INVALID!")
            return False
        except Exception as e:
            print(f"[!] [DEBUG] Verification error: {e}")
            return False

    # ---------------- Sign-in ----------------
    async def signin(self):
        while True:
            message = deepcopy(self.JSON_base_template)
            message["type"] = "USER_HELLO"
            message["from"] = "Guest"
            message["to"] = "Server"
            message["ts"] = time.time()
            message["payload"] = {
                "client": "cli-v1",
                "pubkey": self.public_key_base64url,
                "enc_pubkey": self.public_key_base64url,
            }

            await self.websocket.send(json.dumps(message))

            response = json.loads(await self.websocket.recv())
            if response.get("type") == "USER_WELCOME":
                self.client_id = response.get("to")
                payload = response.get("payload")
                self.server_pub_key = payload.get("server_pub_key") 
                self.list_commands()
            else:
                print("Error, please retry connection")

            return

    def store_message(self, msg, plaintext):
        sender = msg.get("from", "Unknown")
        recipient = msg.get("to", "Unknown")
        timestamp = msg.get("ts", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        history_key = sender if recipient == self.client_id else recipient

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
            "seen": False,
        })

    # ---------------- Listen ----------------
    async def listen_for_messages(self):
        try:
            async for json_message in self.websocket:
                msg = json.loads(json_message)

                # Queueable responses
                if msg.get("type") == "PUB_KEY" or msg.get("type") == "LIST_RESPONSE":
                    await self._incoming_responses.put(msg)
                    continue


                # Chat messages
                if msg.get("type") == "USER_DELIVER":
       
                    #verify server signature for transport layer security
                    sig = msg.get("sig")
                    if not sig or not hasattr(self, 'server_pub_key'):
                        print("[!] [DEBUG] Recieved USER_DELIVER, no server signature or server pub key was recorded message will no")
                        continue
                    
                    try:
                        server_pubkey_obj = codec.decode_public_key_base64url(self.server_pub_key)
                        codec.verify_payload_signature(msg, server_pubkey_obj)

                    except Exception as e:
                        print(f"[!] [DEBUG] Server signature verification failed: {e}")
                        continue
        
                    #verify content signature
                    if await self.verify_message(msg):
                        payload = msg.get("payload")
                        ciphertext = payload.get("ciphertext")
                        if ciphertext:
                            plaintext = await self.decrypt_message(ciphertext)
                            self.store_message(msg, plaintext)

                            if self.friends_by_id.get(payload.get('sender')) == None:
                                print(f"\n[i] Message received from {payload.get('sender')}:")
                            else:
                                print(f"\n[i] Message received from {self.friends_by_id.get(payload.get('sender'))}:")

                            print(plaintext)
                            print("-------------------------------------------------------------")
                            print(f"\033[1mEnter command ('help' for commands):\033[0m", end="", flush=True)
                    else:
                        print("[!] [DEBUG] Message received but signature verification failed")
                    continue
                
                if msg.get("type") == "MSG_PUBLIC_CHANNEL":
                    payload = msg.get("payload", {})
                    sender = msg.get("from")
                    message = payload.get("ciphertext", "")  # it's plaintext
                    
                    # Display sender as friendly name if they're in friends list
                    sender_display = self.friends_by_id.get(sender, sender)
                    
                    print(f"\n[i] Public message recieved from {sender_display}:\n{message}")
                    print("-------------------------------------------------------------")
                    print(f"\033[1mEnter command ('help' for commands):\033[0m", end="", flush=True)
                    continue
                
                # --- FILE RX ---
                if msg.get("type") == "FILE_START":
                    p = msg.get("payload") or {}
                    fid = p.get("file_id")
                    if not fid:
                        continue
                    self.file_rx[fid] = {
                        "name": p.get("name") or f"file-{fid}",
                        "size": int(p.get("size") or 0),
                        "sha256": p.get("sha256") or "",
                        "received": 0,
                        "parts": {},
                    }
                    print(f"[i] Incoming file: {self.file_rx[fid]['name']} ({self.file_rx[fid]['size']} bytes)")
                    continue

                if msg.get("type") == "FILE_CHUNK":
                    p = msg.get("payload") or {}
                    fid = p.get("file_id")
                    idx = int(p.get("index", 0))
                    ct = p.get("ciphertext")
                    if not fid or ct is None:
                        continue
                    if fid not in self.file_rx:
                        self.file_rx[fid] = {"name": f"file-{fid}", "size": 0, "sha256": "", "received": 0, "parts": {}}
                    try:
                        plain = await self.decrypt_blob(ct)
                    except Exception as e:
                        print(f"[!] chunk decrypt failed for {fid}:{idx}: {e}")
                        continue
                    self.file_rx[fid]["parts"][idx] = plain
                    self.file_rx[fid]["received"] += len(plain)
                    continue

                if msg.get("type") == "FILE_END":
                    p = msg.get("payload") or {}
                    fid = p.get("file_id")
                    if not fid or fid not in self.file_rx:
                        continue
                    entry = self.file_rx[fid]
                    ordered = [entry["parts"][k] for k in sorted(entry["parts"].keys())]
                    blob = b"".join(ordered)

                    ok_size = (entry["size"] == 0) or (len(blob) == entry["size"])
                    sha_hex = hashlib.sha256(blob).hexdigest()
                    ok_sha = (entry["sha256"] == "" or entry["sha256"] == sha_hex)

                    out_path = os.path.join(DOWNLOAD_DIR, entry["name"])
                    with open(out_path, "wb") as f:
                        f.write(blob)

                    print(f"[i] File saved: {out_path}")
                    if not ok_size:
                        print(f"[!] Size mismatch: got {len(blob)}, expected {entry['size']}")
                    if not ok_sha:
                        print(f"[!] SHA-256 mismatch: got {sha_hex}, expected {entry['sha256']}")
                    del self.file_rx[fid]
                    print("-------------------------------------------------------------")
                    print(f"\033[1mEnter command ('help' for commands):\033[0m", end="", flush=True)

                    continue

                if msg.get("type") == "ERROR":
                    payload = msg.get("payload")
                    sender = msg.get("from")
                    error_code = payload.get("code")
                    print(f"Error {error_code} received from {sender}")
                    print("-------------------------------------------------------------")
                    print(f"\033[1mEnter command ('help' for commands):\033[0m", end="", flush=True)

                    continue

        except websockets.exceptions.ConnectionClosed:
            print("\n[!] Connection closed")

    def add_friend(self, friend_id, friend_name):
        if len(friend_name) > 12:
            print("[!] Name too long!")
            return

        if friend_name == "Group":
            print("[!] Name cannot be 'Group'")
            return

        # If the name is already taken by another UUID
        if friend_name in self.friends_by_name and self.friends_by_name[friend_name] != friend_id:
            print(f"[!] Name {friend_name} is already taken by another user!")
            return

        # If the UUID already exists, update its name
        if friend_id in self.friends_by_id:
            old_name = self.friends_by_id[friend_id]
            if old_name != friend_name:
                # remove old name entry
                if old_name in self.friends_by_name:
                    del self.friends_by_name[old_name]
                print(f"[i] Updated {friend_id}'s nickname from {old_name} to {friend_name}!")

        else:
            print(f"[i] Friend added: {friend_name} ({friend_id})")

        # Add/update both dicts
        self.friends_by_id[friend_id] = friend_name
        self.friends_by_name[friend_name] = friend_id

    # ---------------- Commands ----------------
    async def send_messages(self):
        loop = asyncio.get_event_loop()
        while True:
            user_input = await loop.run_in_executor(None, input, "-------------------------------------------------------------\n\033[1mEnter command ('help' for commands):\033[0m ")
            if not user_input.strip():
                continue

            if user_input.lower() in ("quit", "q"):
                await self.websocket.close()
                break

            cmd_parts = user_input.split(maxsplit=-1)
            cmd = cmd_parts[0].lower()

            if cmd in ("help", "-h"):
                self.list_commands()
                continue

            elif cmd == "whoami":
                print(f"[i] You are: {self.client_id}")
                continue

            elif cmd == "history":
                if len(cmd_parts) == 1:
                    print("[i] Unread messages per user:")
                    for user, count in self.unread_messages.items():
                        if count > 0:
                            print(f"  - {user}: {count} unread")
                    continue

                target_friend = self.friends_by_name.get(cmd_parts[1])
                if target_friend != None:
                    target_user = target_friend
                else:
                    target_user = cmd_parts[1]

                target_friend = cmd_parts[1]
                target_user_history = self.message_history.get(target_user, [])
                if not target_user_history:
                    print(f"[i] No message history with {target_friend}.")
                    continue
                print(f"[i] Message history with {target_friend}:")
                for m in target_user_history:
                    ts = m.get("timestamp", "")
                    sender = m.get("sender", "")
                    content = m.get("message", "")
                    direction = m.get("direction", "")
                    prefix = "You" if direction == "out" else sender
                    new_tag = " [NEW]" if not m.get("seen", False) else ""
                    print(f"[{ts}]{new_tag} {prefix}: {content}")
                    m["seen"] = True
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
            
            # ----- Chat ---
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

                message = " ".join(cmd_parts[2:])
                
                print(message)

                # request recipient pubkey
                pubkey_request = deepcopy(self.JSON_base_template)
                pubkey_request["type"] = "PUB_KEY_REQUEST"
                pubkey_request["from"] = self.client_id
                pubkey_request["to"] = "Server"
                pubkey_request["ts"] = time.time()
                pubkey_request["payload"] = {"recipient_uuid": recipient}
                # signature for user -> server
                pubkey_request["sig"] = codec.generate_payload_signature(
                    pubkey_request,
                    self.private_key
                )
                await self.websocket.send(json.dumps(pubkey_request))
                
                recipient_pubkey_b64url = None
                try:
                    while True:
                        msg = await asyncio.wait_for(self._incoming_responses.get(), timeout=1.0)
                        payload = msg.get("payload", {})
                        if msg.get("type") == "PUB_KEY" and payload.get("recipient_uuid") == recipient:
                            recipient_pubkey_b64url = payload.get("recipient_pub")
                            break
                except asyncio.TimeoutError:
                    print(f"[!] No PUB_KEY response from server for {recipient}, skipping message.")
                    continue

                encrypted_payload = await self.encrypt_message(message, recipient_pubkey_b64url)
                timestamp = int(time.time() * 1000)
                signature_b64url = await self.sign_message(
                    self.private_key, encrypted_payload, self.client_id, recipient, timestamp
                )

                msg_direct = deepcopy(self.JSON_base_template)
                msg_direct["type"] = "MSG_DIRECT"
                msg_direct["from"] = self.client_id
                msg_direct["to"] = recipient
                msg_direct["ts"] = timestamp
                msg_direct["payload"] = {
                    "ciphertext": encrypted_payload,
                    "sender_pub": self.public_key_base64url,
                    "content_sig": signature_b64url 
                }
                # signature for user -> server
                msg_direct["sig"] = codec.generate_payload_signature(
                    msg_direct,
                    self.private_key
                )

                self.store_message(msg_direct, message)
                await self.websocket.send(json.dumps(msg_direct))
                print("[i] Message sent successfully!")
                continue
            
            # ----- All ----
            elif cmd == "all":
                if len(cmd_parts) < 2:
                    print("[!] Usage: all <message>")
                    continue
                
                message = " ".join(cmd_parts[1:])

                encrypted_payload = message
                timestamp = int(time.time() * 1000)
                
                msg_public = deepcopy(self.JSON_base_template)
                msg_public["type"] = "MSG_PUBLIC_CHANNEL"
                msg_public["from"] = self.client_id
                msg_public["to"] = "public"
                msg_public["ts"] = timestamp
                msg_public["payload"] = {
                    "ciphertext": encrypted_payload,
                    "sender_pub": self.public_key_base64url,
                    "content_sig": "..."
                }
                
                await self.websocket.send(json.dumps(msg_public))
                print("[i] Public message sent successfully!")
                continue
            
            # --- list ---
            elif cmd == "list":
                list_request = deepcopy(self.JSON_base_template)
                list_request["type"] = "LIST_REQUEST"
                list_request["from"] = self.client_id
                list_request["to"] = self.server_uri
                list_request["ts"] = int(time.time() * 1000)
                list_request["sig"] = codec.generate_payload_signature(
                    list_request,
                    self.private_key
                )
                await self.websocket.send(json.dumps(list_request))

                users_list = None

                while True:
                    msg = await self._incoming_responses.get()
                    if msg.get("type") == "LIST_RESPONSE":
                        payload = msg.get("payload", {})
                        users_list = payload.get("users", [])
                        break

                if users_list:
                    print("Users available to chat:")
                    for user in users_list:
                        if user != self.client_id:
                            print(user)
                else:
                    print("No users online")

                continue

            elif cmd == "sendfile":
                if len(cmd_parts) < 3:
                    print("[!] Usage: sendfile <recipient> <path>")
                    continue
                recipient = cmd_parts[1]
                path = cmd_parts[2]
                await self.send_file_dm(recipient, path)
                continue

            else:
                print("[!] Unknown command. Type 'help' for commands.")
                continue

    # ---------------- File crypto helpers ----------------
    async def encrypt_blob_for_recipient(self, data: bytes, recipient_pubkey_b64url: str) -> str:
        pem_bytes = base64.urlsafe_b64decode(recipient_pubkey_b64url.encode("utf-8"))
        recipient_pubkey = serialization.load_pem_public_key(pem_bytes)
        ciphertext = recipient_pubkey.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        return base64.urlsafe_b64encode(ciphertext).decode("utf-8")

    async def decrypt_blob(self, ciphertext_b64: str) -> bytes:
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        return plaintext

    # ---------------- Send file (DM) ----------------
    async def send_file_dm(self, recipient: str, path: str):
        # 1) Get recipient pubkey
        pubkey_request = deepcopy(self.JSON_base_template)
        pubkey_request["type"] = "PUB_KEY_REQUEST"
        pubkey_request["from"] = self.client_id
        pubkey_request["to"] = "Server"
        pubkey_request["ts"] = time.time()
        pubkey_request["payload"] = {"recipient_uuid": recipient}
        pubkey_request["sig"] = codec.generate_payload_signature(
            pubkey_request,
            self.private_key
        )
        await self.websocket.send(json.dumps(pubkey_request))

        recipient_pubkey_b64url = None
        try:
            while True:
                msg = await asyncio.wait_for(self._incoming_responses.get(), timeout=1.0)
                payload = msg.get("payload", {})
                if msg.get("type") == "PUB_KEY" and payload.get("recipient_uuid") == recipient:
                    recipient_pubkey_b64url = payload.get("recipient_pub")
                    break
        except asyncio.TimeoutError:
            print(f"[!] No PUB_KEY response from server for {recipient}, cannot send file.")
            return

        # 2) Open file and compute meta
        if not os.path.isfile(path):
            print(f"[!] File not found: {path}")
            return
        size = os.path.getsize(path)
        name = os.path.basename(path)
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        sha_hex = h.hexdigest()
        file_id = str(uuid.uuid4())

        # 3) FILE_START
        start = deepcopy(self.JSON_base_template)
        start["type"] = "FILE_START"
        start["from"] = self.client_id
        start["to"] = recipient
        start["ts"] = int(time.time() * 1000)
        start["payload"] = {
            "file_id": file_id,
            "name": name,
            "size": size,
            "sha256": sha_hex,
            "mode": "dm",
        }
        
        # signature for user -> server
        start["sig"] = codec.generate_payload_signature(
            start,
            self.private_key
        )

        await self.websocket.send(json.dumps(start))

        # 4) FILE_CHUNK(s)
        index = 0
        with open(path, "rb") as f:
            while True:
                plain = f.read(FILE_CHUNK_PLAINTEXT)
                if not plain:
                    break
                enc_b64 = await self.encrypt_blob_for_recipient(plain, recipient_pubkey_b64url)
                chunk = deepcopy(self.JSON_base_template)
                chunk["type"] = "FILE_CHUNK"
                chunk["from"] = self.client_id
                chunk["to"] = recipient
                chunk["ts"] = int(time.time() * 1000)
                chunk["payload"] = {
                    "file_id": file_id,
                    "index": index,
                    "ciphertext": enc_b64,
                }
                # signature for user -> server
                chunk["sig"] = codec.generate_payload_signature(
                    chunk,
                    self.private_key
                )
                await self.websocket.send(json.dumps(chunk))
                index += 1

        # 5) FILE_END
        end = deepcopy(self.JSON_base_template)
        end["type"] = "FILE_END"
        end["from"] = self.client_id
        end["to"] = recipient
        end["ts"] = int(time.time() * 1000)
        end["payload"] = {"file_id": file_id}
        # signature for user -> server
        end["sig"] = codec.generate_payload_signature(
            end,
            self.private_key
        )
        await self.websocket.send(json.dumps(end))

        print(f"[i] Sent file '{name}' ({size} bytes) to {recipient}!")

    # ---------------- Start ----------------
    async def start(self):
        if not self.server_uri:
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
