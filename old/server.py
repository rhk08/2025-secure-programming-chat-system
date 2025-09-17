import asyncio
import websockets
import json
import socket
import time
import signal

# ---------------------- Configuration ----------------------
WS_PORT = 8765
UDP_DISCOVERY_PORT = 9999
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 30

# ---------------------- Global State ----------------------
connected_clients = {}   # username -> websocket
client_public_keys = {}  # username -> public key
client_last_seen = {}    # username -> last heartbeat timestamp
tasks = []               # background tasks

# ---------------------- WebSocket Handler ----------------------
async def handle_client(ws):
    username = None
    try:
        async for msg in ws:
            data = json.loads(msg)
            msg_type = data.get("type")
            sender = data.get("sender")

            # ---------------------- Heartbeat ----------------------
            if msg_type == "heartbeat_ack":
                client_last_seen[sender] = time.time()
                continue

            # ---------------------- Sign-in ----------------------
            if msg_type == "Sign-in":
                requested_name = data.get("content")
                if requested_name in connected_clients:
                    await ws.send(json.dumps({"type": "Server Auth", "content": "Unavailable"}))
                else:
                    username = requested_name
                    connected_clients[username] = ws
                    client_public_keys[username] = data.get("public_key")
                    client_last_seen[username] = time.time()
                    await ws.send(json.dumps({"type": "Server Auth", "content": "Success"}))
                    print(f"[+] User signed in: {username}")
                continue

            # ---------------------- Public Key Request ----------------------
            if msg_type == "public_key_request":
                target = data.get("recipient")
                pub_key = client_public_keys.get(target)
                await ws.send(json.dumps({
                    "type": "Public Key",
                    "content": pub_key,
                    "recipient": sender,
                    "sender": target
                }))
                continue

            # ---------------------- Chat Message ----------------------
            if msg_type == "chat":
                recipient = data.get("recipient", "")
                if recipient.lower() == "group":
                    for user, client_ws in list(connected_clients.items()):
                        if user != sender:
                            try:
                                await client_ws.send(json.dumps(data))
                            except websockets.exceptions.ConnectionClosed:
                                cleanup_client(user)
                elif recipient in connected_clients:
                    try:
                        await connected_clients[recipient].send(json.dumps(data))
                    except websockets.exceptions.ConnectionClosed:
                        cleanup_client(recipient)
                else:
                    await ws.send(json.dumps({"type": "Error", "content": f"{recipient} not connected"}))
                continue

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if username:
            cleanup_client(username)

# ---------------------- Cleanup ----------------------
def cleanup_client(username):
    connected_clients.pop(username, None)
    client_public_keys.pop(username, None)
    client_last_seen.pop(username, None)
    print(f"[-] Removed client: {username}")

# ---------------------- Heartbeat Loop ----------------------
async def heartbeat_loop():
    try:
        while True:
            now = time.time()
            to_remove = []

            for username, ws in list(connected_clients.items()):
                try:
                    await ws.send(json.dumps({"type": "heartbeat"}))
                except websockets.exceptions.ConnectionClosed:
                    to_remove.append(username)

                last_seen = client_last_seen.get(username, now)
                if now - last_seen > HEARTBEAT_TIMEOUT:
                    to_remove.append(username)

            for username in set(to_remove):
                cleanup_client(username)

            await asyncio.sleep(HEARTBEAT_INTERVAL)
    except asyncio.CancelledError:
        print("[i] Heartbeat loop cancelled")

# ---------------------- UDP Discovery ----------------------
async def udp_discovery_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', UDP_DISCOVERY_PORT))
    print(f"[i] UDP discovery server running on port {UDP_DISCOVERY_PORT}")
    loop = asyncio.get_event_loop()
    try:
        while True:
            data, addr = await loop.run_in_executor(None, sock.recvfrom, 1024)
            if data.decode() == "CHAT_DISCOVERY":
                ip = socket.gethostbyname(socket.gethostname())
                response = f"ws://{ip}:{WS_PORT}"
                sock.sendto(response.encode(), addr)
    except asyncio.CancelledError:
        sock.close()
        print("[i] UDP discovery loop cancelled")

# ---------------------- Graceful Shutdown ----------------------
def shutdown():
    print("\n[i] Server shutting down...")
    for username, ws in list(connected_clients.items()):
        asyncio.create_task(ws.close(code=1001, reason="Server shutting down"))
    for t in tasks:
        t.cancel()

# ---------------------- Main ----------------------
async def main():
    ws_server = await websockets.serve(handle_client, "0.0.0.0", WS_PORT)
    tasks.append(asyncio.create_task(heartbeat_loop()))
    tasks.append(asyncio.create_task(udp_discovery_server()))
    print(f"[i] WebSocket server running on port {WS_PORT}")

    await asyncio.Future()  # run until cancelled

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[i] Server shutting down (Ctrl+C)")
        # Cancel all background tasks
        for t in tasks:
            t.cancel()
        # Close all client connections
        for username, ws in list(connected_clients.items()):
            try:
                asyncio.run(ws.close(code=1001, reason="Server shutting down"))
            except:
                pass
        print("[i] Shutdown complete")
