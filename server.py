import asyncio
import websockets
import json

class Server:
    def __init__(self):
        self.clients = {}
        self.client_public_keys = {}
        
    async def client_sign_up(self, client_id, client_public_key, websocket):
        """Sign up a new client"""
        # if client id is already taken, or client attempts to use a restricted username, respond as unavailable
        if client_id.lower() == "group" or client_id.lower() == "server" or client_id in self.clients:
            await websocket.send(json.dumps({
                "type": "Server Auth",
                "content": "Unavailable",
                "recipient": "Guest",
                "sender": "Server"
            }))
            return None
        # if client id is available, add user to client list 
        else:
            await websocket.send(json.dumps({
                "type": "Server Auth",
                "content": "Success",
                "recipient": client_id,
                "sender": "Server"
            }))
            self.clients[client_id] = websocket
            self.client_public_keys[client_id] = client_public_key
            
            print(f"Client {client_id} signed up. Total clients: {len(self.clients)}")
            return client_id

    async def client_sign_in(self, client_id, client_public_key, websocket):
        """Sign in a client"""
        # For now, treat sign-in the same as sign-up since we don't have persistent storage
        # In a real implementation, you'd verify credentials against a database
        if client_id in self.clients:
            # Update the websocket connection for existing user
            self.clients[client_id] = websocket
            self.client_public_keys[client_id] = client_public_key
            await websocket.send(json.dumps({
                "type": "Server Auth",
                "content": "Success",
                "recipient": client_id,
                "sender": "Server"
            }))
            print(f"Client {client_id} signed in. Total clients: {len(self.clients)}")
            return client_id
        else:
            # If client doesn't exist, treat as sign-up
            return await self.client_sign_up(client_id, client_public_key, websocket)

    async def send_group_message(self, encrypted_message, sender_id):
        """Broadcast an encrypted message to all clients (except sender)"""
        # Note: For group messages to work properly with encryption, each message 
        # would need to be encrypted separately for each recipient's public key.
        # This is a simplified version that forwards the encrypted message as-is.
        if self.clients:
            send_tasks = []
            for client_id, client_ws in self.clients.items():
                if client_id != sender_id:
                    try:
                        # Forward the encrypted message exactly as received
                        send_tasks.append(client_ws.send(json.dumps(encrypted_message)))
                    except Exception as e:
                        print(f"Failed to queue message for {client_id}: {e}")
            
            if send_tasks:
                # Send all messages concurrently
                results = await asyncio.gather(*send_tasks, return_exceptions=True)
                # Log any exceptions
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        print(f"Failed to send group message to client: {result}")

    async def send_message(self, encrypted_message, sender_id, websocket):
        """Forward an encrypted message to a specific client"""
        recipient_id = encrypted_message.get("recipient")
        
        if recipient_id in self.clients:
            recipient_ws = self.clients[recipient_id]
            try:
                # Forward the encrypted message exactly as received
                await recipient_ws.send(json.dumps(encrypted_message))
                print(f"Message forwarded from {sender_id} to {recipient_id}")
            except Exception as e:
                print(f"Failed to forward message to {recipient_id}: {e}")
                await websocket.send(json.dumps({
                    "type": "Error",
                    "content": "Failed to deliver message",
                    "recipient": sender_id,
                    "sender": "Server"
                }))
        else:
            # Recipient not connected, notify the sender
            await websocket.send(json.dumps({
                "type": "Error",
                "content": f"Recipient '{recipient_id}' not found or not connected",
                "recipient": sender_id,
                "sender": "Server"
            }))

    async def handle_public_key_request(self, message, websocket):
        """Handle public key requests"""
        requester = message.get("sender")
        recipient = message.get("recipient")
        
        # Look up the recipient's public key
        recipient_key = self.client_public_keys.get(recipient)
        
        if recipient_key:
            # Send the public key back to the requester
            await websocket.send(json.dumps({
                "type": "Public Key",
                "content": recipient_key,
                "recipient": requester,
                "sender": recipient
            }))
            print(f"Sent {recipient}'s public key to {requester}")
        else:
            # Recipient not found or no key available
            await websocket.send(json.dumps({
                "type": "Public Key",
                "content": None,
                "recipient": requester,
                "sender": recipient
            }))
            print(f"Public key for {recipient} not found, sent None to {requester}")
            
    async def handle_client(self, websocket):
        """Handle messages from clients"""
        client_id = "guest"
        
        try:
            async for json_message in websocket:
                try:
                    message = json.loads(json_message)
                    msg_type = message.get("type")
                    
                    # Log received message (but don't log encrypted content)
                    if msg_type == "chat":
                        print(f"Encrypted message from {message.get('sender')} to {message.get('recipient')}")
                    else:
                        print(f"Received {msg_type} message from {message.get('sender', 'unknown')}")
                    
                    if msg_type == "Sign-in":
                        client_id = await self.client_sign_in(
                            message["content"], 
                            message["public_key"], 
                            websocket
                        )
                        
                    elif msg_type == "Sign-up":
                        client_id = await self.client_sign_up(
                            message["content"], 
                            message["public_key"], 
                            websocket
                        )
                        
                    elif msg_type == "chat":
                        # Don't decrypt - just forward the encrypted message
                        if message.get("recipient", "").lower() == "group":
                            await self.send_group_message(message, client_id)
                        else:
                            await self.send_message(message, client_id, websocket)
                            
                    elif msg_type == "public_key_request":
                        await self.handle_public_key_request(message, websocket)
                        
                    else:
                        print(f"Unknown message type: {msg_type}")
                        
                except json.JSONDecodeError:
                    print("Received invalid JSON message")
                    await websocket.send(json.dumps({
                        "type": "Error",
                        "content": "Invalid JSON format",
                        "recipient": client_id,
                        "sender": "Server"
                    }))
                except Exception as e:
                    print(f"Error processing message: {e}")
                    await websocket.send(json.dumps({
                        "type": "Error",
                        "content": "Message processing error",
                        "recipient": client_id,
                        "sender": "Server"
                    }))

        except websockets.exceptions.ConnectionClosed:
            print(f"Client connection closed normally")
        except Exception as e:
            print(f"Unexpected error handling client: {e}")
        
        finally:
            # Remove client when disconnected
            if client_id and client_id in self.clients:
                del self.clients[client_id]
                if client_id in self.client_public_keys:
                    del self.client_public_keys[client_id]
                print(f"Client {client_id} disconnected. Total clients: {len(self.clients)}")

    async def start(self):
        """Start running server"""
        print("WebSocket chat server running on ws://localhost:8765")
        print("The server will forward encrypted messages without decrypting them")
        
        async with websockets.serve(self.handle_client, "localhost", 8765):
            await asyncio.Future()  # Run forever

if __name__ == "__main__":
    server = Server()
    asyncio.run(server.start())