
import asyncio
import websockets
import json

class Server:
    def __init__(self):
        self.clients = {}

    async def client_sign_up(self, client_id, websocket):
        """Sign up a new client"""
        # if client id is already taken, or client attempts to use a restricted username, respond as unavailable
        if client_id == "group" or client_id in self.clients:
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
            print(f"Client {client_id} connected. Total clients: {len(self.clients)}")
            return client_id

    async def client_sign_in(self, client_id, websocket):
        """Sign up a client"""
        # if client id is in client list, sign them in
        if client_id in self.clients:
            await websocket.send(json.dumps({
                "type": "Server Auth",
                "content": "Success",
                "recipient": client_id,
                "sender": "Server"
            }))
            print(f"Client {client_id} connected. Total clients: {len(self.clients)}")
            return client_id
        # if client id is not in client list, treat as a sign up
        else:
            await self.client_sign_up(client_id, websocket)

    async def send_group_message(self, message, client_id):
        """Broadcast a message to all clients (except for sender)"""
        # if clients exist in client list, send them the message
        if self.clients:
            send_tasks = []
            # go through all clients and add to task array 
            for id, client in self.clients.items():
                if id != client_id:
                    send_tasks.append(client.send(json.dumps({
                        "type": "chat",
                        "content": message["content"],
                        "recipient": message["recipient"],
                        "sender": client_id
                    })))
                # send all messages at the same time 
                await asyncio.gather(*send_tasks, return_exceptions=True)

    async def send_message(self, message, client_id, websocket):
        """Send a message to a specific client"""
        # check if message recipient is in client list, if so, send them the message
        message_recipient = message["recipient"]
        if message_recipient in self.clients:
            recipient_ws = self.clients[message_recipient]
            await recipient_ws.send(json.dumps({
                "type": "chat",
                "content": message["content"],
                "recipient": message["recipient"],
                "sender": client_id
            }))
        # if recipient is not found, notify the sender
        else:
            await websocket.send(json.dumps({
                "type": "Error",
                "content": "Recipient not found",
                "recipient": client_id,
                "sender": "Server"
            }))
            

    async def handle_client(self, websocket):
        """Handle messages from clients"""
        # initialise client id
        client_id = "guest"

        try:
            async for json_message in websocket:
                message = json.loads(json_message)

                # log all messages received 
                print(message)
                
                if message["type"] == "Sign-in":
                    client_id = await self.client_sign_in(message["content"], websocket)
                elif message["type"] == "Sign-up":
                    client_id = await self.client_sign_up(message["content"], websocket)
                elif message["type"] == "chat":
                    if message["recipient"] == "Group":
                        await self.send_group_message(message, client_id)
                    else:
                        await self.send_message(message, client_id, websocket)

        except websockets.exceptions.ConnectionClosed:
            pass
        
        finally:
            # remove client when disconnected
            if client_id in self.clients:
                del self.clients[client_id]
                print(f"Client {client_id} disconnected. Total clients: {len(self.clients)}")

    async def start(self):
        """Start running server"""
        print("WebSocket chat server running on ws://localhost:8765")
        async with websockets.serve(self.handle_client, "localhost", 8765):
            await asyncio.Future()  # Run forever

if __name__ == "__main__":
    server = Server()
    asyncio.run(server.start())