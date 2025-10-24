import pytest
import asyncio
import sys
from io import StringIO
from unittest.mock import patch
import uuid

from app.server_v1_3 import Server

@pytest.mark.asyncio
async def test_server_connection_state():
    """Test that verifies the actual connection state between servers"""
    servers = {}

    async def run_server(host, port, introducer_mode, discovery_port, key):
        server = Server(
            host=host, port=port,
            introducer_mode=introducer_mode,
            localhost_mode=True,
            discovery_port=discovery_port
        )
        servers[key] = server
        await server.start()

    task1 = asyncio.create_task(run_server("127.0.0.1", 9001, True, 9998, "s1"))
    task2 = asyncio.create_task(run_server("127.0.0.1", 9003, False, 9999, "s2"))

    await asyncio.sleep(2)

    server1 = servers.get("s1")
    server2 = servers.get("s2")

    # Check that servers know about each other via self.servers dict
    assert server2.server_uuid in server1.servers, "Server1 should have Server2 in servers dict"
    assert server1.server_uuid in server2.servers, "Server2 should have Server1 in servers dict"

    # Verify server addresses are stored
    assert server2.server_uuid in server1.server_addrs, "Server1 should have Server2's address"
    assert server1.server_uuid in server2.server_addrs, "Server2 should have Server1's address"

    # Check address tuple structure (host, port, pubkey)
    s2_addr_in_s1 = server1.server_addrs[server2.server_uuid]
    s1_addr_in_s2 = server2.server_addrs[server1.server_uuid]

    assert s2_addr_in_s1[0] == "127.0.0.1", "Server2's host should be stored correctly in Server1"
    assert s2_addr_in_s1[1] == 9003, "Server2's port should be stored correctly in Server1"
    assert s2_addr_in_s1[2] is not None, "Server2's pubkey should be stored in Server1"

    assert s1_addr_in_s2[0] == "127.0.0.1", "Server1's host should be stored correctly in Server2"
    assert s1_addr_in_s2[1] == 9001, "Server1's port should be stored correctly in Server2"
    assert s1_addr_in_s2[2] is not None, "Server1's pubkey should be stored in Server2"

    # Verify Link objects exist
    link1_to_2 = server1.servers[server2.server_uuid]
    link2_to_1 = server2.servers[server1.server_uuid]

    assert link1_to_2 is not None, "Server1 should have a Link to Server2"
    assert link2_to_1 is not None, "Server2 should have a Link to Server1"

    # Verify websocket mappings exist
    assert len(server1.servers_websockets) > 0, "Server1 should have websocket mappings"
    assert len(server2.servers_websockets) > 0, "Server2 should have websocket mappings"

    # Verify at least one websocket maps to the peer server
    s1_has_s2_ws = server2.server_uuid in server1.servers_websockets.values()
    s2_has_s1_ws = server1.server_uuid in server2.servers_websockets.values()
    
    assert s1_has_s2_ws, "Server1 should have a websocket mapped to Server2"
    assert s2_has_s1_ws, "Server2 should have a websocket mapped to Server1"

    # Clean up
    task1.cancel()
    task2.cancel()
    try:
        await asyncio.gather(task1, task2, return_exceptions=True)
    except asyncio.CancelledError:
        pass

@pytest.mark.asyncio
async def test_server_keys_and_uuid():
    """Test that server keys and UUID are properly initialized"""
    servers = {}

    async def run_server(host, port, introducer_mode, discovery_port, key):
        server = Server(
            host=host, port=port,
            introducer_mode=introducer_mode,
            localhost_mode=True,
            discovery_port=discovery_port
        )
        servers[key] = server
        await server.start()

    task1 = asyncio.create_task(run_server("127.0.0.1", 9001, True, 9998, "s1"))
    await asyncio.sleep(1)

    server1 = servers.get("s1")

    # UUID validation
    uuid_obj = uuid.UUID(server1.server_uuid)
    assert str(uuid_obj) == server1.server_uuid, "Server UUID should be valid"

    # Keys should exist
    assert server1.private_key is not None, "Private key should be initialized"
    assert server1.public_key is not None, "Public key should be initialized"
    assert server1.private_key_base64url is not None, "Private key base64url should be initialized"
    assert server1.public_key_base64url is not None, "Public key base64url should be initialized"

    # Base64url strings should be valid
    assert len(server1.private_key_base64url) > 0, "Private key base64url should not be empty"
    assert len(server1.public_key_base64url) > 0, "Public key base64url should not be empty"

    # For introducer, keys should match BOOTSTRAP_SERVERS
    if server1.introducer_mode:
        assert server1.public_key_base64url, "Introducer should have predefined public key"

    task1.cancel()
    try:
        await task1
    except asyncio.CancelledError:
        pass

@pytest.mark.asyncio
async def test_comprehensive_server_network():
    """Comprehensive test of server network formation and state (no output checking)"""
    servers = {}

    async def run_server(host, port, introducer_mode, discovery_port, key):
        server = Server(
            host=host, port=port,
            introducer_mode=introducer_mode,
            localhost_mode=True,
            discovery_port=discovery_port
        )
        servers[key] = server
        await server.start()

    # Start introducer first
    task1 = asyncio.create_task(run_server("127.0.0.1", 9001, True, 9998, "s1"))
    await asyncio.sleep(0.5)

    # Start normal server
    task2 = asyncio.create_task(run_server("127.0.0.1", 9003, False, 9999, "s2"))
    await asyncio.sleep(2)

    server1 = servers.get("s1")  # Introducer
    server2 = servers.get("s2")  # Normal

    # === Basic Server Properties ===
    assert server1.host == "127.0.0.1"
    assert server1.port == 9001
    assert server1.introducer_mode is True
    assert server1.UDP_DISCOVERY_PORT == 9998

    assert server2.host == "127.0.0.1"
    assert server2.port == 9003
    assert server2.introducer_mode is False
    assert server2.UDP_DISCOVERY_PORT == 9999

    # === UUID Validation ===
    uuid.UUID(server1.server_uuid)
    uuid.UUID(server2.server_uuid)
    assert server1.server_uuid != server2.server_uuid

    # === Server-to-Server Connectivity ===
    assert server2.server_uuid in server1.servers
    assert server1.server_uuid in server2.servers

    # Address storage
    assert server2.server_uuid in server1.server_addrs
    assert server1.server_uuid in server2.server_addrs

    # Verify address tuples
    s1_knows_s2 = server1.server_addrs[server2.server_uuid]
    s2_knows_s1 = server2.server_addrs[server1.server_uuid]

    assert s1_knows_s2 == ("127.0.0.1", 9003, server2.public_key_base64url)
    assert s2_knows_s1 == ("127.0.0.1", 9001, server1.public_key_base64url)

    # === WebSocket Mappings ===
    assert len(server1.servers_websockets) >= 1
    assert len(server2.servers_websockets) >= 1

    assert server2.server_uuid in server1.servers_websockets.values()
    assert server1.server_uuid in server2.servers_websockets.values()

    # === User State (should be empty) ===
    assert len(server1.local_users) == 0
    assert len(server2.local_users) == 0
    assert len(server1.user_locations) == 0
    assert len(server2.user_locations) == 0

    # === Cryptographic Keys ===
    assert server1.private_key is not None
    assert server1.public_key is not None
    assert server2.private_key is not None
    assert server2.public_key is not None

    # === Database Initialization ===
    assert server1.db is not None
    assert server2.db is not None

    # Print summary
    print("\n" + "="*70)
    print("COMPREHENSIVE TEST RESULTS")
    print("="*70)
    print(f"Server 1 (Introducer): {server1.server_uuid}")
    print(f"  - Knows about {len(server1.servers)} server(s)")
    print(f"  - Has {len(server1.servers_websockets)} websocket(s)")
    print(f"  - Has {len(server1.local_users)} local user(s)")
    print()
    print(f"Server 2 (Normal): {server2.server_uuid}")
    print(f"  - Knows about {len(server2.servers)} server(s)")
    print(f"  - Has {len(server2.servers_websockets)} websocket(s)")
    print(f"  - Has {len(server2.local_users)} local user(s)")
    print("="*70)

    # Cleanup
    task1.cancel()
    task2.cancel()
    try:
        await asyncio.gather(task1, task2, return_exceptions=True)
    except asyncio.CancelledError:
        pass
# ====================
# Group Members
# ====================
# Ryan Khor - a1887993
# Lucy Fidock - a1884810
# Nicholas Brown - a1870629
# Luke Schaefer - a1852210
# Nelson Then - a1825642
