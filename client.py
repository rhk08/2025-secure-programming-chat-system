import asyncio
import websockets

class Client:
    def __init__(self):
        self.websocket = None
    
    async def listen_for_messages(self):
        # listen for incoming messages from server
        try:
            async for message in self.websocket:
                print(f"Received: {message}")
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed by server")
    
    async def send_messages(self):
        # send messages from user input
        loop = asyncio.get_event_loop()
        
        while True:
            # get user input in a non-blocking way
            message = await loop.run_in_executor(None, input)
            if message.lower() == 'quit':
                break
            await self.websocket.send(message)
    
    async def start(self):
        uri = "ws://localhost:8765"
        try:
            async with websockets.connect(uri) as websocket:
                self.websocket = websocket
                print("Connected to chat server!")
                print("Type messages and press Enter. Type 'quit' to exit.")
                
                # run both listening and sending concurrently
                await asyncio.gather(
                    self.listen_for_messages(),
                    self.send_messages()
                )
        except Exception as e:
            print(f"Connection error: {e}")

if __name__ == "__main__":
    client = Client()
    asyncio.run(client.start())