from cryptography.fernet import Fernet
import hashlib
import os
from dotenv import load_dotenv

load_dotenv()

KEY = os.environ.get("FILE_TRANSFER_KEY")
if not KEY:
    raise ValueError("Please set FILE_TRANSFER_KEY")

fernet = Fernet(KEY.encode())


def encrypt_data(data: bytes) -> bytes:
    return fernet.encrypt(data)


def decrypt_data(data: bytes) -> bytes:
    return fernet.decrypt(data)


def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
