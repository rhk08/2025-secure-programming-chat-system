import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json

# 1. Generate key pair
def get_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
            
            
    # Safe for sending but CANNOT be used for for encryption/decryption. key -> PEM -> base64url
    private_key_base64url = base64.urlsafe_b64encode(private_key_pem).decode("utf-8")
    public_key_base64url = base64.urlsafe_b64encode(public_key_pem).decode("utf-8")

    return private_key_base64url, public_key_base64url


keys_list = [get_keys() for _ in range(3)]

all_same = True

# Compare every pair
for i in range(len(keys_list)):
    for j in range(i + 1, len(keys_list)):
        if keys_list[i] != keys_list[j]:
            all_same = False
            print(f"Keys at index {i} and {j} are different:")
            print(f"{keys_list[i][0]}")
            print(f"{keys_list[j]}")

if all_same:
    print("what")
else:
    bootstrap_servers = [
        {
            "host": "127.0.0.1",
            "port": 9001,
            "private_key": keys_list[0][0],
            "public_key": keys_list[0][1]
        },
        {
            "host": "127.0.0.1",
            "port": 9002,
            "private_key": keys_list[1][0],
            "public_key": keys_list[1][1]
        },
        {
            "host": "127.0.0.1",
            "port": 9003,
            "private_key": keys_list[2][0],
            "public_key": keys_list[2][1]
        }
    ]

    # 4. Write to JSON file
    with open("bootstrap_servers.json", "w") as f:
        json.dump(bootstrap_servers, f, indent=4)

    print("Bootstrap servers JSON created successfully.")

# 2. Generate keys_list for each server

# ====================
# Group 40
# ====================
# Ryan Khor - a1887993
# Lucy Fidock - a1884810
# Nicholas Brown - a1870629
# Luke Schaefer - a1852210
# Nelson Then - a1825642
