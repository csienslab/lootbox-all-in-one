from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import argparse


def sign(key: Ed25519PrivateKey, data: bytes) -> bytes:
    H = hashes.Hash(hashes.SHA256())
    H.update(data)
    return key.sign(H.finalize())


def verify(key: Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    H = hashes.Hash(hashes.SHA256())
    H.update(data)
    try:
        key.verify(signature, H.finalize())
        return True
    except:
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("private_key", help="private key file destination")
    parser.add_argument("public_key", help="public key file destination")
    args = parser.parse_args()

    key = Ed25519PrivateKey.generate()
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(args.private_key, "wb") as f:
        f.write(private_key)
    with open(args.public_key, "wb") as f:
        f.write(public_key)
