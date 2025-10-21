
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

import base64

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    return private_key, public_key

def generate_payload_signature(message: dict, private_key):
    
    """
    Signs the 'payload' field of a message dictionary using the given RSA private key.
    
    Args:
        message (dict): The message containing a 'payload' field.
        private_key: RSAPrivateKey object used to sign.
    
    Returns:
        str: Base64URL-encoded signature.
    
    Raises:
        ValueError: If 'payload' field is missing from the message.
    """
    
    if 'payload' not in message:
        raise ValueError("Message does not contain a 'payload' field.")
    
    payload_canonical = json.dumps(message['payload'], separators=(',', ':'), sort_keys=True).encode('utf-8')
    signature_bytes = private_key.sign(
        payload_canonical, # the message bytes
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), # PSS padding with SHA256-based MGF
        hashes.SHA256() # hash function applied to message
    )
    
    return base64.urlsafe_b64encode(signature_bytes).decode('utf-8')

def verify_payload_signature(message: dict, public_key):
    """
    Verifies the 'sig' field of a message against its 'payload' using the given public key.
    
    Args:
        message (dict): The message containing 'payload' and 'sig'.
        public_key: RSAPublicKey object used to verify the signature.
    
    Returns:
        bool: True if signature is valid.
    
    Raises:
        ValueError: If 'payload' or 'sig' field is missing.
        cryptography.exceptions.InvalidSignature: If signature is invalid.
    """
    
    if 'payload' not in message:
        raise ValueError("Message does not contain a 'payload' field.")
    if 'sig' not in message:
        raise ValueError("Message does not contain a 'sig' field.")
    
    # Canonicalize the payload JSON (sorted keys, compact)
    payload_canonical = json.dumps(message['payload'], separators=(',', ':'), sort_keys=True).encode('utf-8')
    
    # Decode the Base64URL signature
    signature_bytes = base64.urlsafe_b64decode(message['sig'])
    
    # Verify the signature
    try:
        public_key.verify(
            signature_bytes,
            payload_canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        raise InvalidSignature("Signature verification failed.")

# THESE ONLY WORK FOR PUBLIC KEYS -----------
def encode_public_key_base64url(key_object):
    PEM_encoded_key = key_object.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    base64url_encoded_key = base64.urlsafe_b64encode(PEM_encoded_key).decode("utf-8")
    return base64url_encoded_key

def decode_public_key_base64url(key_base64url):
    decoded_key_object = serialization.load_pem_public_key(
        base64.urlsafe_b64decode(key_base64url)
    )
    return decoded_key_object
