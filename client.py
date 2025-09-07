import asyncio
import websockets
import json

class Client:
    def __init__(self):
        self.websocket = None
        self.client_id = "Guest"

    async def encrypt_message(self):
        #TODO: set up method of encrypting a message, only encrypt message content, not other json text
        return 
    
    async def decrypt_message(self):
        # TODO: set up method of decrypting a message
        return 

    async def signin(self):
        """Sign into the chat service"""
        # TODO: implementation to be improved for sign in to increase security 
        while True:
            auth_type = input("If you are a new user, please enter 0.\n If you are a returning user, please enter 1:\n")

            if auth_type == '0':
                auth_type = "Sign-up"
                break
            elif auth_type == '1':
                auth_type = "Sign-in"
                break
        
        # loop to sign in user, will not complete until user signed in successfully 
        while True:
            client_username = input("Please enter your username: ")
            message_data = json.dumps({
                "type": auth_type,
                "content": client_username,
                "recipient": "server",
                "sender": self.client_id
            })
            await self.websocket.send(message_data)
            
            try:
                message = await self.websocket.recv()
                response = json.loads(message)
                if response["content"] == "Success":
                    self.client_id = client_username
                    return  
                elif response["content"] == "Unavailable":
                    print("Username unavailable. ")
                else:
                    print("Unexpected response")
            except websockets.exceptions.ConnectionClosed:
                print("Connection closed by server")
    
    async def listen_for_messages(self):
        """Listens to incoming messages from the server"""
        #loop through and print received messages
        #TODO: error handling for messages with type 'Error'

        try:
            async for json_message in self.websocket:
                message = json.loads(json_message)
                print(f"Received: {message['content']} from {message['sender']}")
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed by server")
    
    async def send_messages(self):
        """Send messages from user input"""

        loop = asyncio.get_event_loop()
        
        while True:
            # get message 
            message = await loop.run_in_executor(None, input)
            
            # check if user wishes to quit
            if message.lower() == 'quit':
                break
            
            # get recipient of message 
            recipient = input("Please enter the username of the recipient of this message, or 'Group' to send to all users: ")

            # format json message data
            message_data = json.dumps({
                "type": "chat",
                "content": message,
                "recipient": recipient,
                "sender": self.client_id
            })

            # send message over websockets
            await self.websocket.send(message_data)
    
    async def start(self):
        # TODO: 1) modify to work over network using ip and port forwarding
        # 2) need to join server without knowing ip & port ?

        uri = "ws://localhost:8765"
        try:
            # use connect function to establish websocket connection with specified uri
            async with websockets.connect(uri) as websocket:
                self.websocket = websocket
                print("Connected to chat server!")
                await self.signin()

                print("Type messages and press Enter. Type 'quit' to exit.")
                
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