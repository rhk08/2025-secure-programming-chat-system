import asyncio
import websockets
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64


class Client:
    def __init__(self):
        self.websocket = None
        self.client_id = "Guest"
        self._pending_key_requests = {}
        
        # Generate RSA key pair for this client
        self.rsa_key = RSA.generate(2048)
        self.private_key = self.rsa_key
        self.public_key = self.rsa_key.publickey()

    async def get_recipient_public_key(self, recipient, timeout=5):
        fut = asyncio.get_event_loop().create_future()
        self._pending_key_requests[recipient] = fut

        # send request
        request_data = json.dumps({
            "type": "public_key_request",
            "recipient": recipient,
            "sender": self.client_id
        })
        await self.websocket.send(request_data)

        try:
            # wait for response with timeout
            pem = await asyncio.wait_for(fut, timeout=timeout)

            if pem is None:
                print(f"No public key found for {recipient}")
                return None

            try:
                # Verify the key can be imported
                RSA.import_key(pem)
                return pem
            except ValueError as e:
                print(f"Failed to import recipient public key: {e}")
                return None

        except asyncio.TimeoutError:
            print(f"Timeout: No public key received from {recipient}")
            return None
        finally:
            # Clean up the pending request
            self._pending_key_requests.pop(recipient, None)

    async def encrypt_message(self, message: str, recipient_public_key_pem: str):
        try:
            # 1. Generate AES key
            aes_key = get_random_bytes(32)  # 256-bit AES

            # 2. Encrypt the message with AES (EAX mode ensures integrity)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

            # 3. Encrypt the AES key with recipient's RSA public key
            recipient_rsa_key = RSA.import_key(recipient_public_key_pem)
            cipher_rsa = PKCS1_OAEP.new(recipient_rsa_key)
            enc_aes_key = cipher_rsa.encrypt(aes_key)

            # 4. Return all necessary data in base64 to include in JSON
            return {
                "enc_aes_key": base64.b64encode(enc_aes_key).decode(),
                "nonce": base64.b64encode(cipher_aes.nonce).decode(),
                "tag": base64.b64encode(tag).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode()
            }
        except Exception as e:
            print(f"Failed to encrypt message: {e}")
            return None
    
    async def decrypt_message(self, message: dict):
        try:
            # Extract encrypted components
            enc_aes_key = base64.b64decode(message["enc_aes_key"])
            nonce = base64.b64decode(message["nonce"])
            tag = base64.b64decode(message["tag"])
            ciphertext = base64.b64decode(message["ciphertext"])

            # Decrypt AES key with RSA private key
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(enc_aes_key)

            # Decrypt message with AES
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

            return plaintext.decode()

        except Exception as e:
            print(f"Failed to decrypt message from {message.get('sender', 'unknown')}: {e}")
            return None

    async def signin(self):
        """Sign into the chat service"""
        while True:
            auth_type = input("If you are a new user, please enter 0.\nIf you are a returning user, please enter 1:\n")

            if auth_type == '0':
                auth_type = "Sign-up"
                break
            elif auth_type == '1':
                auth_type = "Sign-in"
                break
            else:
                print("Please enter 0 or 1")
        
        # loop to sign in user, will not complete until user signed in successfully 
        while True:
            client_username = input("Please enter your username: ")
            message_data = json.dumps({
                "type": auth_type,
                "content": client_username,
                "recipient": "server",
                "sender": self.client_id,
                "public_key": self.public_key.export_key().decode()
            })
            await self.websocket.send(message_data)
            
            try:
                message = await asyncio.wait_for(self.websocket.recv(), timeout=10)
                response = json.loads(message)
                if response["content"] == "Success":
                    self.client_id = client_username
                    print(f"Successfully signed in as {client_username}")
                    return  
                elif response["content"] == "Unavailable":
                    print("Username unavailable. Please try another username.")
                else:
                    print(f"Unexpected response: {response['content']}")
            except asyncio.TimeoutError:
                print("Sign-in timeout. Please try again.")
            except websockets.exceptions.ConnectionClosed:
                print("Connection closed by server")
                return
    
    async def listen_for_messages(self):
        """Listens to incoming messages from the server"""
        try:
            async for json_message in self.websocket:
                try:
                    message = json.loads(json_message)
                    msg_type = message.get("type")
                    
                    if msg_type == "Public Key":
                        sender = message.get("sender")
                        if sender in self._pending_key_requests:
                            fut = self._pending_key_requests[sender]
                            if not fut.done():
                                fut.set_result(message.get("content"))
                        
                    elif msg_type == "chat":
                        # This message is encrypted and meant for us
                        plaintext = await self.decrypt_message(message)
                        if plaintext is not None:
                            print(f"{message['sender']}: {plaintext}")
                        else:
                            print(f"Failed to decrypt message from {message.get('sender', 'unknown')}")

                    elif msg_type == "Error":
                        print(f"Server error: {message['content']}")

                    else:
                        print(f"Unknown message type received: {msg_type}")
                        
                except json.JSONDecodeError:
                    print("Received invalid JSON message")
                except Exception as e:
                    print(f"Error processing message: {e}")

        except websockets.exceptions.ConnectionClosed:
            print("Connection closed by server")
        except Exception as e:
            print(f"Error in message listener: {e}")

    async def send_messages(self):
        """Send messages from user input"""
        loop = asyncio.get_event_loop()
        
        while True:
            try:
                # get message 
                message = await loop.run_in_executor(None, input, "Enter message (or 'quit' to exit): ")
                
                # check if user wishes to quit
                if message.lower() == 'quit':
                    await self.websocket.close()
                    break
                
                # get recipient of message 
                recipient = await loop.run_in_executor(None, input, "Enter recipient username (or 'Group' for all users): ")

                # Get recipient's public key
                recipient_public_key = await self.get_recipient_public_key(recipient)
                if recipient_public_key is None:
                    print(f"Failed to obtain {recipient}'s public key. Message not sent.")
                    continue
                
                # Encrypt the message
                encrypted_data = await self.encrypt_message(message, recipient_public_key)
                if encrypted_data is None:
                    print("Failed to encrypt message. Message not sent.")
                    continue
                
                payload = {
                    "type": "chat",
                    "recipient": recipient,
                    "sender": self.client_id,
                    **encrypted_data
                }

                # send message over websockets
                await self.websocket.send(json.dumps(payload))
                print("Message sent successfully!")
                
            except Exception as e:
                print(f"Error sending message: {e}")
    
    async def start(self):
        uri = "ws://localhost:8765"
        try:
            # use connect function to establish websocket connection with specified uri
            async with websockets.connect(uri) as websocket:
                self.websocket = websocket
                print("Connected to chat server!")
                await self.signin()

                print("You are now connected to the chat!")
                
                # run both listening and sending concurrently
                await asyncio.gather(
                    self.listen_for_messages(),
                    self.send_messages()
                )
        except Exception as e:
            print(f"Connection error: {e}")

if __name__ == "__main__":
    # initialise client and run
    client = Client()
    asyncio.run(client.start())