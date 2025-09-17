import asyncio
import websockets
import json
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import time

class Client:
    def __init__(self):
        self._incoming_responses = asyncio.Queue() # Queue to allow for the program to wait on specific responses
        self.websocket = None
    
    
    
    
    async def shutdown(self):
        return
    
    async def start(self):
        async with websockets.connect() as socket:
            self.websocket = socket
            
            
        return

if __name__ == "__main__":
    client = Client()
    asyncio.run(client.start())
    try:
        asyncio.run(client.start())
    except KeyboardInterrupt:
        print("\nCtrl+C pressed. Initiating graceful Client shutdown.")
        asyncio.run(client.shutdown())
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")