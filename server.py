import asyncio
import websockets

# store all connected clients with their IDs
clients = {}
next_client_id = 1

async def handle_client(websocket):
    global next_client_id
    
    # assign ID to client
    client_id = next_client_id
    next_client_id += 1
    
    # add client to dictionary
    clients[client_id] = websocket
    print(f"Client {client_id} connected. Total clients: {len(clients)}")
    
    try:
        async for message in websocket:
            print(f"Client {client_id} sent: {message}")
            
            # broadcast message to all other clients
            if clients:
                send_tasks = []
                for id, client in clients.items():
                    if id != client_id: # don't send message back to same client
                        send_tasks.append(client.send(f"Client {client_id}: {message}"))
                await asyncio.gather(*send_tasks, return_exceptions=True)
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        # remove client when disconnected
        del clients[client_id]
        print(f"Client {client_id} disconnected. Total clients: {len(clients)}")

async def main():
    print("WebSocket chat server running on ws://localhost:8765")
    async with websockets.serve(handle_client, "localhost", 8765):
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())