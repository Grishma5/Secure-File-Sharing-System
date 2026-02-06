from hashlib import sha256
from cryptography.fernet import Fernet

# ────────────────────────────────────────────────
# CONFIG — must be same on client & server
# ────────────────────────────────────────────────

FERNET_KEY = b'epVKiOHn7J0sZcJ4-buWQ5ednv3csHdQHfvEKk0qVvk='
CHUNK_SIZE = 4096

fernet = Fernet(FERNET_KEY)


def encrypt_data(data: bytes) -> bytes:
    return fernet.encrypt(data)


def decrypt_data(encrypted: bytes) -> bytes:
    return fernet.decrypt(encrypted)


def chunk_bytes(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[bytes]:
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def merkle_root(chunks: list[bytes]) -> str:
    if not chunks:
        return sha256(b"").hexdigest()

    # Leaf level: hash raw bytes
    hashes = [sha256(chunk).hexdigest() for chunk in chunks]

    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])  # duplicate last hash if odd count

        new_hashes = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1]
            combined = (left + right).encode('ascii')  # hex strings → bytes
            new_hashes.append(sha256(combined).hexdigest())

        hashes = new_hashes

    return hashes[0]