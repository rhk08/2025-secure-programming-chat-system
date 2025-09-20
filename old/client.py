import asyncio
import websockets
import json
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import time

UDP_DISCOVERY_PORT = 9999
DISCOVERY_TIMEOUT = 3  # seconds to wait for server discovery

class Client:
    def __init__(self):
        self.websocket = None
        self.client_id = None
        self._pending_key_requests = {}
        self.rsa_key = RSA.generate(2048)
        self.private_key = self.rsa_key
        self.public_key = self.rsa_key.publickey()

    # ---------------------- LAN Discovery ----------------------
    async def discover_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(DISCOVERY_TIMEOUT)

        while True:
            try:
                sock.sendto(b"CHAT_DISCOVERY", ('<broadcast>', UDP_DISCOVERY_PORT))
                data, _ = sock.recvfrom(1024)
                server_uri = data.decode()
                print(f"[i] Discovered server at {server_uri}")
                return server_uri
            except socket.timeout:
                print("[!] Server not found, retrying in 3 seconds...")
                await asyncio.sleep(3)

    # ---------------------- Encryption/Decryption ----------------------
    async def encrypt_message(self, message: str, recipient_public_key_pem: str):
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        recipient_rsa_key = RSA.import_key(recipient_public_key_pem)
        enc_aes_key = PKCS1_OAEP.new(recipient_rsa_key).encrypt(aes_key)
        return {
            "enc_aes_key": base64.b64encode(enc_aes_key).decode(),
            "nonce": base64.b64encode(cipher_aes.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    async def decrypt_message(self, message: dict):
        try:
            enc_aes_key = base64.b64decode(message["enc_aes_key"])
            nonce = base64.b64decode(message["nonce"])
            tag = base64.b64decode(message["tag"])
            ciphertext = base64.b64decode(message["ciphertext"])
            aes_key = PKCS1_OAEP.new(self.private_key).decrypt(enc_aes_key)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            return cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
        except:
            return None

    # ---------------------- Public Key Request ----------------------
    async def get_recipient_public_key(self, recipient, timeout=5):
        fut = asyncio.get_event_loop().create_future()
        self._pending_key_requests[recipient] = fut
        await self.websocket.send(json.dumps({
            "type": "public_key_request",
            "recipient": recipient,
            "sender": self.client_id
        }))
        try:
            pem = await asyncio.wait_for(fut, timeout=timeout)
            if pem: return pem
        except asyncio.TimeoutError:
            print(f"Timeout: No public key from {recipient}")
        finally:
            self._pending_key_requests.pop(recipient, None)
        return None

    # ---------------------- Sign-in ----------------------
    async def signin(self):
        while True:
            name = input("Enter your username: ")
            await self.websocket.send(json.dumps({
                "type": "Sign-in",
                "content": name,
                "sender": name,
                "public_key": self.public_key.export_key().decode()
            }))
            try:
                response = json.loads(await asyncio.wait_for(self.websocket.recv(), timeout=5))
                if response["content"] == "Success":
                    self.client_id = name
                    print(f"Signed in as {name}")
                    return
                else:
                    print("Name in use, try another.")
            except:
                print("No response from server, retry.")

    # ---------------------- Listen for messages ----------------------
    async def listen_messages(self):
        async for msg in self.websocket:
            message = json.loads(msg)
            msg_type = message.get("type")

            if msg_type == "heartbeat":
                # Respond immediately
                await self.websocket.send(json.dumps({
                    "type": "heartbeat_ack",
                    "sender": self.client_id
                }))

            elif msg_type == "Public Key" and message.get("sender") in self._pending_key_requests:
                fut = self._pending_key_requests[message["sender"]]
                if not fut.done(): fut.set_result(message.get("content"))

            elif msg_type == "chat":
                plaintext = await self.decrypt_message(message)
                if plaintext:
                    print(f"{message['sender']}: {plaintext}")

    # ---------------------- Send messages ----------------------
    async def send_messages(self):
        loop = asyncio.get_event_loop()
        while True:
            message = await loop.run_in_executor(None, input, "Message (or 'quit'): ")
            if message.lower() == 'quit':
                await self.websocket.close()
                break

            recipient = await loop.run_in_executor(None, input, "Recipient (or 'Group'): ")
            pub_key = await self.get_recipient_public_key(recipient)
            if not pub_key:
                print(f"Failed to get {recipient}'s public key")
                continue

            payload = {
                "type": "chat",
                "recipient": recipient,
                "sender": self.client_id,
                **await self.encrypt_message(message, pub_key)
            }
            try:
                await self.websocket.send(json.dumps(payload))
            except websockets.exceptions.ConnectionClosed:
                print("Disconnected from server")
                break

    # ---------------------- Start Client ----------------------
    async def start(self):
        server_uri = await self.discover_server()
        print(f"Connecting to server at {server_uri}")
        try:
            async with websockets.connect(server_uri) as ws:
                self.websocket = ws
                await self.signin()
                print("Connected! You can now send messages.")
                await asyncio.gather(
                    self.listen_messages(),
                    self.send_messages()
                )
        except Exception as e:
            print(f"Connection error: {e}")

if __name__ == "__main__":
    asyncio.run(Client().start())
