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
connected_clients = {}     # username -> websocket (local clients)
client_public_keys = {}    # username -> public key (local clients)
client_last_seen = {}      # username -> last heartbeat timestamp
remote_users = {}          # username -> server_uri (remote users on peers)
peer_servers = set()       # discovered peer servers
tasks = []                 # background tasks

# ---------------------- Graceful Shutdown ----------------------
async def shutdown():
    print("[i] Shutting down server...")
    for username, ws in list(connected_clients.items()):
        try:
            await ws.close(code=1001, reason="Server shutting down")
        except:
            pass
    for t in tasks:
        t.cancel()
    await asyncio.sleep(0.1)

# ---------------------- Utility ----------------------
def cleanup_client(username):
    connected_clients.pop(username, None)
    client_public_keys.pop(username, None)
    client_last_seen.pop(username, None)
    print(f"[-] Removed client: {username}")
    # Notify peers
    asyncio.create_task(propagate_user_disconnect(username))

# ---------------------- Heartbeat ----------------------
async def heartbeat_loop():
    try:
        while True:
            now = time.time()
            to_remove = []
            # Ping local clients
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
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', UDP_DISCOVERY_PORT))
    loop = asyncio.get_event_loop()
    print(f"[i] UDP discovery server running on port {UDP_DISCOVERY_PORT}")
    try:
        while True:
            data, addr = await loop.run_in_executor(None, sock.recvfrom, 1024)
            msg = data.decode()
            ip = addr[0]

            # Client discovery
            if msg == "CHAT_DISCOVERY":
                server_uri = f"ws://{socket.gethostbyname(socket.gethostname())}:{WS_PORT}"
                sock.sendto(server_uri.encode(), addr)

            # Server discovery
            if msg == "SERVER_DISCOVERY":
                peer_uri = f"ws://{ip}:{WS_PORT}"
                if peer_uri != f"ws://{socket.gethostbyname(socket.gethostname())}:{WS_PORT}":
                    peer_servers.add(peer_uri)
                    print(f"[i] Discovered peer server: {peer_uri}")

    except asyncio.CancelledError:
        sock.close()
        print("[i] UDP discovery loop cancelled")

async def broadcast_server_presence():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    msg = b"SERVER_DISCOVERY"
    while True:
        sock.sendto(msg, ('<broadcast>', UDP_DISCOVERY_PORT))
        await asyncio.sleep(5)

# ---------------------- Peer Communication ----------------------
async def propagate_user_disconnect(username):
    for peer in peer_servers:
        try:
            async with websockets.connect(peer) as ws:
                await ws.send(json.dumps({
                    "type": "user_disconnected",
                    "content": username
                }))
        except:
            pass

async def check_username_peers(username):
    for peer in peer_servers:
        try:
            async with websockets.connect(peer) as ws:
                await ws.send(json.dumps({"type": "username_check", "content": username}))
                resp = json.loads(await ws.recv())
                if resp.get("available") is False:
                    return False
        except:
            pass
    return True

# ---------------------- WebSocket Handler ----------------------
async def handle_client(ws):
    username = None
    try:
        async for msg in ws:
            data = json.loads(msg)
            msg_type = data.get("type")
            sender = data.get("sender")

            # Heartbeat acknowledgment
            if msg_type == "heartbeat_ack":
                client_last_seen[sender] = time.time()
                continue

            # Username check from peer
            if msg_type == "username_check":
                uname = data.get("content")
                available = uname not in connected_clients and uname not in remote_users
                await ws.send(json.dumps({"available": available}))
                continue

            # User disconnect notification from peer
            if msg_type == "user_disconnected":
                uname = data.get("content")
                remote_users.pop(uname, None)
                continue
            
            # ---------------------- Ping -------------------------
            if msg_type == "ping":
                response = {
                    "type": "pong",
                    "content": "Pong!",
                    "recipient": sender,
                    "sender": "Server"
                }
                await ws.send(json.dumps(response))
                continue
                
            # ---------------------- List -------------------------
            if msg_type == "list_users":
                all_users = list(connected_clients.keys()) + list(remote_users.keys())
                response = {
                    "type": "user_list",
                    "content": all_users,
                    "recipient": sender,
                    "sender": "Server"
                }
                await connected_clients[sender].send(json.dumps(response))
            
            # ---------------------- Sign-in ----------------------
            if msg_type == "sign_in":
                requested_name = data.get("content")
                local_free = requested_name not in connected_clients
                peer_free = await check_username_peers(requested_name)
                if local_free and peer_free:
                    username = requested_name
                    connected_clients[username] = ws
                    client_public_keys[username] = data.get("public_key")
                    client_last_seen[username] = time.time()
                    await ws.send(json.dumps({"type": "Server Auth", "content": "Success"}))
                    print(f"[+] User signed in: {username}")
                else:
                    await ws.send(json.dumps({"type": "Server Auth", "content": "Unavailable"}))
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

            # ---------------------- Chat ----------------------
            if msg_type == "chat":
                recipient = data.get("recipient", "")
                if recipient.lower() == "group":
                    # Send to local clients
                    for user, client_ws in list(connected_clients.items()):
                        if user != sender:
                            try:
                                await client_ws.send(json.dumps(data))
                            except:
                                cleanup_client(user)
                    # Forward to peers
                    for peer in peer_servers:
                        try:
                            async with websockets.connect(peer) as ws_peer:
                                await ws_peer.send(json.dumps(data))
                        except:
                            pass
                elif recipient in connected_clients:
                    try:
                        await connected_clients[recipient].send(json.dumps(data))
                    except:
                        cleanup_client(recipient)
                else:
                    await ws.send(json.dumps({"type": "Error", "content": f"{recipient} not connected"}))

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if username:
            cleanup_client(username)

# ---------------------- Main ----------------------
async def main():
    # WebSocket server
    ws_server = await websockets.serve(handle_client, "0.0.0.0", WS_PORT)
    tasks.append(asyncio.create_task(heartbeat_loop()))
    tasks.append(asyncio.create_task(udp_discovery_server()))
    tasks.append(asyncio.create_task(broadcast_server_presence()))
    print(f"[i] WebSocket server running on port {WS_PORT}")

    await asyncio.Future()  # run until cancelled

# ---------------------- Entry Point ----------------------
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[i] Server shutting down (Ctrl+C)")
        asyncio.run(shutdown())
        print("[i] Shutdown complete")
