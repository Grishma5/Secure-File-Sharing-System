# crypto_utils.py
from cryptography.fernet import Fernet
import hashlib
import os
import os
from dotenv import load_dotenv

load_dotenv()
# Load key from environment variable (set it via export FILE_TRANSFER_KEY=your_base64_key)
KEY = os.environ.get("FILE_TRANSFER_KEY")
if not KEY:
    raise ValueError("Please set the FILE_TRANSFER_KEY environment variable with a valid Fernet key")

fernet = Fernet(KEY.encode())  # Ensure it's bytes


def encrypt_data(data: bytes) -> bytes:
    return fernet.encrypt(data)


def decrypt_data(data: bytes) -> bytes:
    return fernet.decrypt(data)


def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()