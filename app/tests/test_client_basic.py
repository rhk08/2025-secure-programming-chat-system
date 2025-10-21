import pytest
from app.client_v1_3 import Client

@pytest.mark.asyncio
async def test_encrypt_decrypt_roundtrip():
    c1 = Client()
    c2 = Client()
    msg = "hello world"

    encrypted = await c1.encrypt_message(msg, c2.public_key_base64url)
    decrypted = await c2.decrypt_message(encrypted)
    assert decrypted == msg