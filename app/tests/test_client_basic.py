import pytest
import asyncio
import json
import os
import tempfile
import hashlib
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from app.client_v1_3 import Client
import websockets
from cryptography.hazmat.primitives import serialization
import base64
from app.utils import codec as Codec

@pytest.fixture
def client():
    """Create a fresh client instance for testing"""
    return Client()


@pytest.fixture
def two_clients():
    """Create two client instances for testing interactions"""
    return Client(), Client()


# ============================================================================
# Encryption/Decryption Tests
# ============================================================================

@pytest.mark.asyncio
async def test_encrypt_decrypt_roundtrip():
    """Test basic encryption and decryption between two clients"""
    c1 = Client()
    c2 = Client()
    msg = "hello world"

    encrypted = await c1.encrypt_message(msg, c2.public_key_base64url)
    decrypted = await c2.decrypt_message(encrypted)
    assert decrypted == msg


@pytest.mark.asyncio
async def test_encrypt_decrypt_unicode():
    """Test encryption/decryption with unicode characters"""
    c1 = Client()
    c2 = Client()
    msg = "Hello 世界 🌍 émojis!"

    encrypted = await c1.encrypt_message(msg, c2.public_key_base64url)
    decrypted = await c2.decrypt_message(encrypted)
    assert decrypted == msg


@pytest.mark.asyncio
async def test_encrypt_decrypt_empty_string():
    """Test encryption/decryption of empty string"""
    c1 = Client()
    c2 = Client()
    msg = ""

    encrypted = await c1.encrypt_message(msg, c2.public_key_base64url)
    decrypted = await c2.decrypt_message(encrypted)
    assert decrypted == msg


@pytest.mark.asyncio
async def test_decrypt_wrong_key_fails():
    """Test that decryption with wrong key fails"""
    c1 = Client()
    c2 = Client()
    c3 = Client()
    msg = "secret message"

    encrypted = await c1.encrypt_message(msg, c2.public_key_base64url)
    
    with pytest.raises(Exception):
        await c3.decrypt_message(encrypted)


@pytest.mark.asyncio
async def test_encrypt_long_message():
    """Test encryption of message near RSA limits"""
    c1 = Client()
    c2 = Client()
    # RSA-OAEP with 4096-bit key can handle ~446 bytes
    msg = "A" * 400

    encrypted = await c1.encrypt_message(msg, c2.public_key_base64url)
    decrypted = await c2.decrypt_message(encrypted)
    assert decrypted == msg


# ============================================================================
# Signature Tests
# ============================================================================

@pytest.mark.asyncio
async def test_sign_message():
    """Test message signing"""
    c1 = Client()
    
    ciphertext = "encrypted_data"
    sender_id = "sender-123"
    recipient_id = "recipient-456"
    timestamp = 1234567890.123456
    plaintext = "test message"
    encrypted = await c1.encrypt_message(plaintext, c1.public_key_base64url)
    
    msg = {
        "type": "USER_DELIVER",
        "from": c1.client_id,
        "to": recipient_id,
        "ts": timestamp,
        "payload": {
            "ciphertext": encrypted,
            "sender_pub": c1.public_key_base64url,
            "content_sig":"",
            "sender": c1.client_id
        },
        "sig":""
    }
    
    signed_message = await c1.sign_message(msg, c1.private_key)
    
    # Check that content_sig exists and is properly encoded
    content_sig = signed_message["payload"]["content_sig"]
    assert content_sig
    assert isinstance(content_sig, str)
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" for c in content_sig)
    
    # Check that overall message sig exists and is properly encoded
    overall_sig = signed_message["sig"]
    assert overall_sig
    assert isinstance(overall_sig, str)
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" for c in overall_sig)
    
    # Placeholder fail to indicate further verification needed
    pytest.fail("Further checks for correctness of both signatures not implemented yet")
    
    
#TODO
@pytest.mark.asyncio
async def test_verify_message_valid():
    """Test verification of valid message"""
    c1 = Client()
    c1.client_id = "sender-123"
    recipient = "recipient-456"
    timestamp = 1234567890.123456
    message = "test message"
    
    encrypted = await c1.encrypt_message(message, c1.public_key_base64url)
    content_signature = await c1.sign_message(
        c1.private_key, encrypted, c1.client_id, recipient, timestamp
    )
    
    
    msg_direct = {
        "type": "USER_DELIVER",
        "from": c1.client_id,
        "to": recipient,
        "ts": timestamp,
        "payload": {
            "ciphertext": encrypted,
            "sender_pub": c1.public_key_base64url,
            "content_sig":content_signature,
            "sender": c1.client_id
        },
        "sig":""
    }
    
    signature = Codec.generate_payload_signature(msg_direct,  c1.private_key)
    msg_direct["sig"] = signature
    
    is_valid = await c1.verify_message(msg_direct)
    assert is_valid




#TODO
@pytest.mark.asyncio
async def test_verify_message_invalid_content_signature():
    """Test verification fails with tampered content_signature"""
    c1 = Client()
    c1.client_id = "sender-123"
    recipient = "recipient-456"
    timestamp = 1234567890.123456
    message = "test message"
    
    
    encrypted = await c1.encrypt_message(message, c1.public_key_base64url)
    
    
    msg_direct = {
        "type": "USER_DELIVER",
        "from": c1.client_id,
        "to": recipient,
        "ts": timestamp,
        "payload": {
            "ciphertext": encrypted,
            "sender_pub": c1.public_key_base64url,
            "content_sig": "invalid_signature_data",
            "sender": c1.client_id
        },
        "sig":""
    }
    
    signature = Codec.generate_payload_signature(msg_direct, c1.private_key)
    msg_direct["sig"] = signature
    
    
    is_valid = await c1.verify_message(msg_direct)
    assert not is_valid

    
#TODO
@pytest.mark.asyncio
async def test_verify_message_invalid_signature():
    """Test verification fails with tampered signature"""
    c1 = Client()
    c1.client_id = "sender-123"
    recipient = "recipient-456"
    timestamp = 1234567890.123456
    message = "test message"
    
    encrypted = await c1.encrypt_message(message, c1.public_key_base64url)
    signature = await c1.sign_message(
        c1.private_key, encrypted, c1.client_id, recipient, timestamp
    )
    
    msg_direct = {
        "type": "USER_DELIVER",
        "from": c1.client_id,
        "to": recipient,
        "ts": timestamp,
        "payload": {
            "ciphertext": encrypted,
            "sender_pub": c1.public_key_base64url,
            "content_sig": signature,
            "sender": c1.client_id
        },
        "sig":"invalid_content_sig"
    }
    
    is_valid = await c1.verify_message(msg_direct)
    assert not is_valid





# ============================================================================
# Friend Management Tests
# ============================================================================

def test_add_friend_new(client):
    """Test adding a new friend"""
    friend_id = "friend-uuid-123"
    friend_name = "Alice"
    
    client.add_friend(friend_id, friend_name)
    
    assert friend_id in client.friends_by_id
    assert client.friends_by_id[friend_id] == friend_name
    assert friend_name in client.friends_by_name
    assert client.friends_by_name[friend_name] == friend_id


def test_add_friend_update_name(client):
    """Test updating a friend's nickname"""
    friend_id = "friend-uuid-123"
    old_name = "Alice"
    new_name = "AliceUpdated"
    
    client.add_friend(friend_id, old_name)
    client.add_friend(friend_id, new_name)
    
    assert client.friends_by_id[friend_id] == new_name
    assert new_name in client.friends_by_name
    assert old_name not in client.friends_by_name


def test_add_friend_duplicate_name_different_uuid(client):
    """Test that duplicate names for different UUIDs are rejected"""
    friend1_id = "friend-uuid-123"
    friend2_id = "friend-uuid-456"
    friend_name = "Alice"
    
    client.add_friend(friend1_id, friend_name)
    client.add_friend(friend2_id, friend_name)
    
    # Second one should be rejected
    assert client.friends_by_name[friend_name] == friend1_id
    assert friend2_id not in client.friends_by_id


def test_add_friend_name_too_long(client):
    """Test that names longer than 12 characters are rejected"""
    friend_id = "friend-uuid-123"
    long_name = "ThisNameIsTooLong"
    
    client.add_friend(friend_id, long_name)
    
    assert friend_id not in client.friends_by_id
    assert long_name not in client.friends_by_name


def test_add_friend_reserved_name_group(client):
    """Test that 'Group' is a reserved name"""
    friend_id = "friend-uuid-123"
    
    client.add_friend(friend_id, "Group")
    
    assert friend_id not in client.friends_by_id
    assert "Group" not in client.friends_by_name


# ============================================================================
# File Encryption Tests
# ============================================================================

@pytest.mark.asyncio
async def test_encrypt_decrypt_blob():
    """Test blob encryption and decryption for file transfer"""
    c1 = Client()
    c2 = Client()
    data = b"This is binary file data"
    
    encrypted = await c1.encrypt_blob_for_recipient(data, c2.public_key_base64url)
    decrypted = await c2.decrypt_blob(encrypted)
    
    assert decrypted == data


@pytest.mark.asyncio
async def test_encrypt_decrypt_blob_max_size():
    """Test blob encryption with maximum chunk size"""
    c1 = Client()
    c2 = Client()
    # FILE_CHUNK_PLAINTEXT = 190 bytes
    data = b"X" * 190
    
    encrypted = await c1.encrypt_blob_for_recipient(data, c2.public_key_base64url)
    decrypted = await c2.decrypt_blob(encrypted)
    
    assert decrypted == data


@pytest.mark.asyncio
async def test_encrypt_decrypt_empty_blob():
    """Test empty blob encryption"""
    c1 = Client()
    c2 = Client()
    data = b""
    
    encrypted = await c1.encrypt_blob_for_recipient(data, c2.public_key_base64url)
    decrypted = await c2.decrypt_blob(encrypted)
    
    assert decrypted == data


# ============================================================================
# File Reception Tests
# ============================================================================

@pytest.mark.asyncio
async def test_file_start_message(client):
    """Test handling FILE_START message"""
    file_id = "file-123"
    filename = "test.txt"
    file_size = 1024
    sha256 = "abc123"
    
    msg = {
        "type": "FILE_START",
        "payload": {
            "file_id": file_id,
            "name": filename,
            "size": file_size,
            "sha256": sha256
        }
    }
    
    # Simulate processing
    p = msg.get("payload") or {}
    fid = p.get("file_id")
    client.file_rx[fid] = {
        "name": p.get("name") or f"file-{fid}",
        "size": int(p.get("size") or 0),
        "sha256": p.get("sha256") or "",
        "received": 0,
        "parts": {},
    }
    
    assert file_id in client.file_rx
    assert client.file_rx[file_id]["name"] == filename
    assert client.file_rx[file_id]["size"] == file_size
    assert client.file_rx[file_id]["sha256"] == sha256


@pytest.mark.asyncio
async def test_file_chunk_reception(client):
    """Test handling FILE_CHUNK message"""
    c2 = Client()
    file_id = "file-123"
    
    # Initialize file reception
    client.file_rx[file_id] = {
        "name": "test.txt",
        "size": 100,
        "sha256": "",
        "received": 0,
        "parts": {}
    }
    
    # Create encrypted chunk
    data = b"chunk data"
    encrypted = await client.encrypt_blob_for_recipient(data, c2.public_key_base64url)
    
    msg = {
        "type": "FILE_CHUNK",
        "payload": {
            "file_id": file_id,
            "index": 0,
            "ciphertext": encrypted
        }
    }
    
    # Simulate processing
    p = msg.get("payload") or {}
    fid = p.get("file_id")
    idx = int(p.get("index", 0))
    ct = p.get("ciphertext")
    
    plain = await c2.decrypt_blob(ct)
    client.file_rx[fid]["parts"][idx] = plain
    client.file_rx[fid]["received"] += len(plain)
    
    assert 0 in client.file_rx[file_id]["parts"]
    assert client.file_rx[file_id]["parts"][0] == data
    assert client.file_rx[file_id]["received"] == len(data)


# ============================================================================
# Key Management Tests
# ============================================================================

def test_client_has_keypair(client):
    """Test that client generates keypair on initialization"""
    assert client.private_key is not None
    assert client.public_key is not None
    assert client.public_key_base64url is not None


def test_public_key_is_base64url(client):
    """Test that public key is properly base64url encoded"""
    # Should be decodable
    decoded = base64.urlsafe_b64decode(client.public_key_base64url)
    
    # Should be valid PEM
    pubkey = serialization.load_pem_public_key(decoded)
    assert pubkey is not None


def test_different_clients_have_different_keys():
    """Test that each client gets unique keypair"""
    c1 = Client()
    c2 = Client()
    
    assert c1.public_key_base64url != c2.public_key_base64url
    assert c1.private_key != c2.private_key


# ============================================================================
# JSON Template Tests
# ============================================================================

def test_json_template_loaded(client):
    """Test that JSON template is loaded"""
    assert client.JSON_base_template is not None
    assert isinstance(client.JSON_base_template, dict)


# ============================================================================
# Server Discovery Tests
# ============================================================================

def test_discover_server_manual_uri():
    """Test manual server URI specification via command line"""
    with patch('sys.argv', ['client.py', 'ws://test.server:9000']):
        c = Client()
        assert c.server_uri == 'ws://test.server:9000'


def test_discover_server_no_manual_uri():
    """Test that server URI is None when not specified"""
    with patch('sys.argv', ['client.py']):
        c = Client()
        assert c.server_uri is None


@patch('socket.socket')
def test_discover_server_udp(mock_socket, client):
    """Test UDP server discovery"""
    mock_sock_instance = Mock()
    mock_socket.return_value = mock_sock_instance
    mock_sock_instance.recvfrom.return_value = (b"ws://192.168.1.100:9000", ("192.168.1.100", 9999))
    
    client.discover_server(timeout=1)
    
    assert client.server_uri == "ws://192.168.1.100:9000"
    mock_sock_instance.sendto.assert_called_once()


@patch('socket.socket')
def test_discover_server_timeout(mock_socket, client):
    """Test UDP discovery timeout"""
    mock_sock_instance = Mock()
    mock_socket.return_value = mock_sock_instance
    mock_sock_instance.recvfrom.side_effect = TimeoutError()
    
    client.discover_server(timeout=1)
    
    assert client.server_uri is None


@patch('socket.socket')
def test_discover_server_localhost_normalization(mock_socket, client):
    """Test localhost alias normalization"""
    mock_sock_instance = Mock()
    mock_socket.return_value = mock_sock_instance
    mock_sock_instance.recvfrom.return_value = (b"ws://127.0.1.1:9000", ("127.0.1.1", 9999))
    
    client.discover_server(timeout=1)
    
    assert client.server_uri == "ws://127.0.0.1:9000"


# ============================================================================
# Helper Method Tests
# ============================================================================

def test_list_commands(client, capsys):
    """Test that list_commands prints available commands"""
    client.list_commands()
    captured = capsys.readouterr()
    
    assert "chat" in captured.out
    assert "sendfile" in captured.out
    assert "all" in captured.out
    assert "add" in captured.out
    assert "friends" in captured.out
    assert "whoami" in captured.out
    assert "list" in captured.out
    assert "quit" in captured.out


# ============================================================================
# Download Directory Tests
# ============================================================================

def test_download_directory_created(client):
    """Test that download directory exists"""
    from app.client_v1_3 import DOWNLOAD_DIR
    assert os.path.exists(DOWNLOAD_DIR)


# ============================================================================
# Integration-style Tests (with mocked websocket)
# ============================================================================

@pytest.mark.asyncio
async def test_signin_flow():
    """Test the signin flow with mocked websocket"""
    client = Client()
    client.client_id = "test-uuid"
    
    mock_ws = AsyncMock()
    mock_ws.recv = AsyncMock(return_value=json.dumps({
        "type": "USER_WELCOME",
        "to": "assigned-uuid-123",
        "payload": {
            "server_pub_key": "server_public_key_here"
        }
    }))
    
    client.websocket = mock_ws
    
    await client.signin()
    
    assert client.client_id == "assigned-uuid-123"
    assert client.server_pub_key == "server_public_key_here"
    mock_ws.send.assert_called_once()

# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.asyncio
async def test_encrypt_message_invalid_pubkey():
    """Test encryption with invalid public key"""
    c1 = Client()
    
    with pytest.raises(Exception):
        await c1.encrypt_message("test", "invalid_base64url_key")


@pytest.mark.asyncio
async def test_decrypt_message_invalid_ciphertext():
    """Test decryption with invalid ciphertext"""
    c1 = Client()
    
    with pytest.raises(Exception):
        await c1.decrypt_message("invalid_base64_ciphertext")


def test_file_rx_initialization(client):
    """Test that file_rx dictionary is initialized"""
    assert isinstance(client.file_rx, dict)
    assert len(client.file_rx) == 0


def test_pending_key_requests_initialization(client):
    """Test that pending key requests dict is initialized"""
    assert isinstance(client._pending_key_requests, dict)
    assert len(client._pending_key_requests) == 0


def test_incoming_responses_queue_initialization(client):
    """Test that incoming responses queue is initialized"""
    assert client._incoming_responses is not None
    assert isinstance(client._incoming_responses, asyncio.Queue)



# ============================================================================
# Constants Tests
# ============================================================================

def test_constants_defined():
    """Test that required constants are defined"""
    from app.client_v1_3 import (
        UDP_DISCOVERY_PORT,
        HEARTBEAT_INTERVAL,
        FILE_CHUNK_PLAINTEXT,
        DOWNLOAD_DIR
    )
    
    assert UDP_DISCOVERY_PORT == 9999
    assert HEARTBEAT_INTERVAL == 10
    assert FILE_CHUNK_PLAINTEXT == 190
    assert DOWNLOAD_DIR == "app/downloads"

# ====================
# Group 40
# ====================
# Ryan Khor - a1887993
# Lucy Fidock - a1884810
# Nicholas Brown - a1870629
# Luke Schaefer - a1852210
# Nelson Then - a1825642
