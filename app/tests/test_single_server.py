import pytest
import asyncio
import builtins
import queue
from unittest.mock import patch
import uuid

from app.server_v1_3 import Server
from app.client_v1_3 import Client


@pytest.mark.asyncio
# async def test_user_connect_local():
#     servers = {}
#     clients = {}

#     async def run_server(host, port, introducer_mode, discovery_port, key):
#         server = Server(
#             host=host,
#             port=port,
#             introducer_mode=introducer_mode,
#             localhost_mode=True,
#             discovery_port=discovery_port,
#         )
#         servers[key] = server
#         await server.start()

#     async def run_client(key):
#         client = Client()
#         client.server_uri = "ws://127.0.0.1:9001"
#         clients[key] = client
#         await client.start()

#     # --- Simple queue-based input script ---
#     q = queue.Queue()

#     # feeder: put commands into the queue with delays (runs in the test event loop)
#     async def feeder():
#         await asyncio.sleep(1.0)  # let client start
#         for cmd, delay, callback in script:
#             q.put(cmd)
#             print(f"[test -> input] queued '{cmd}'")
#             await asyncio.sleep(delay)  # wait for client to process the command
#             if callback:
#                 # Now run callback AFTER the delay
#                 if asyncio.iscoroutinefunction(callback):
#                     await callback()
#                 else:
#                     callback()
#         q.put(None)
        
#     async def check_server_state():
#         server1 = servers.get("s1")
#         print("Checking users:", server1.local_users)
#         assert server1.local_users, "No users connected"

#     def patched_input(prompt=""):
#         val = q.get()
#         if val is None:
#             raise EOFError
#         print(f"[test -> input] {val}")
#         return val

#     script = [
#         ("help", 1, None),
#         ("list", 1, check_server_state),
#         ("quit", 0, None),
#     ]
    
    
#     # Start server/client and feeder under patched input
#     with patch.object(builtins, "input", patched_input):
#         task_server = asyncio.create_task(run_server("127.0.0.1", 9001, True, 9999, "s1"))

#         await asyncio.sleep(0.2)
#         task_client = asyncio.create_task(run_client("c1"))
#         feeder_task = asyncio.create_task(feeder())

#         await feeder_task
#         await asyncio.sleep(1.0)

#         # examine server/client
#         server1 = servers.get("s1")
#         client1 = clients.get("c1")
#         print("Server local users:", getattr(server1, "local_users", None))
#         print("Client ID:", getattr(client1, "client_id", None))

#         # cleanup
#         for t in (task_client, task_server):
#             t.cancel()
#         await asyncio.gather(task_client, task_server, return_exceptions=True)


@pytest.mark.asyncio
async def test_two_clients_independent_inputs():
    servers = {}
    clients = {}

    async def run_server():
        server = Server(host="127.0.0.1", port=9001, introducer_mode=True,
                        localhost_mode=True, discovery_port=9999)
        servers["s1"] = server
        await server.start()

    async def run_client(key):
        client = Client()
        client.server_uri = "ws://127.0.0.1:9001"
        clients[key] = client
        await client.start()

    # Input queues for each client
    input_queues = {
        "c1": queue.Queue(),
        "c2": queue.Queue(),
    }

    # Global mapping from thread id → client key
    thread_to_client = {}

    # Patch input globally
    def patched_input(prompt=""):
        import threading
        thread_id = threading.get_ident()
        # Map thread to client key if first call
        if thread_id not in thread_to_client:
            # Assign the next client whose input hasn't started yet
            for k in input_queues:
                if k not in thread_to_client.values():
                    thread_to_client[thread_id] = k
                    break

        key = thread_to_client[thread_id]
        val = input_queues[key].get()
        if val is None:
            raise EOFError
        print(f"[{key} -> input] {val}")
        return val

    with patch.object(builtins, "input", patched_input):
        task_server = asyncio.create_task(run_server())
        await asyncio.sleep(0.3)

        task_c1 = asyncio.create_task(run_client("c1"))
        task_c2 = asyncio.create_task(run_client("c2"))

        async def feeder():
            await asyncio.sleep(1.0)
            input_queues["c1"].put("whoami")
            await asyncio.sleep(1.0)
            input_queues["c2"].put("whoami")
            await asyncio.sleep(1.0)
            server1 = servers.get("s1")
            print("Server local users:", getattr(server1, "local_users", None))
            await asyncio.sleep(1.0)
            input_queues["c1"].put("quit")
            input_queues["c2"].put("quit")
            input_queues["c1"].put(None)
            input_queues["c2"].put(None)

        feeder_task = asyncio.create_task(feeder())
        await asyncio.gather(task_c1, task_c2, feeder_task)

        task_server.cancel()
        await asyncio.gather(task_server, return_exceptions=True)
        

# ====================
# Group 40
# ====================
# Ryan Khor - a1887993
# Lucy Fidock - a1884810
# Nicholas Brown - a1870629
# Luke Schaefer - a1852210
# Nelson Then - a1825642
