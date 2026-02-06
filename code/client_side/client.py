import socket
import tkinter as tk
from tkinter import filedialog, messagebox
import os

from crypto_utils import (
    CHUNK_SIZE, encrypt_data, decrypt_data,
    chunk_bytes, merkle_root
)

HOST = "192.168.56.1"
PORT = 4455


def recvall(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise RuntimeError("Socket closed prematurely")
        data += packet
    return data


def upload_file():
    path = filedialog.askopenfilename()
    if not path:
        return

    try:
        with open(path, "rb") as f:
            content = f.read()

        filename = os.path.basename(path)
        encrypted = encrypt_data(content)
        chunks = chunk_bytes(encrypted)
        root_hash = merkle_root(chunks)

        with socket.socket() as client:
            client.connect((HOST, PORT))
            client.sendall(b"UPLOAD")

            # filename
            name_b = filename.encode("utf-8")
            client.sendall(len(name_b).to_bytes(4, "big"))
            client.sendall(name_b)

            # encrypted data
            client.sendall(len(encrypted).to_bytes(8, "big"))
            client.sendall(encrypted)

            # merkle root (64 hex chars)
            client.sendall(root_hash.encode("ascii"))

            resp = client.recv(32).decode("ascii", errors="ignore").strip()

            if resp == "VERIFIED":
                messagebox.showinfo("Success", "File uploaded and integrity verified!")
            elif resp == "HASH_MISMATCH":
                messagebox.showerror("Error", "Integrity check failed (hash mismatch)")
            elif resp == "DECRYPT_FAILED":
                messagebox.showerror("Error", "Server could not decrypt file")
            else:
                messagebox.showerror("Error", f"Server responded: {resp}")

    except Exception as e:
        messagebox.showerror("Error", str(e))


def download_file():
    filename = entry.get().strip()
    if not filename:
        messagebox.showwarning("Input required", "Please enter a filename")
        return

    try:
        with socket.socket() as client:
            client.connect((HOST, PORT))
            client.sendall(b"DOWNLOAD")

            name_b = filename.encode("utf-8")
            client.sendall(len(name_b).to_bytes(4, "big"))
            client.sendall(name_b)

            status = client.recv(16).decode("ascii", errors="ignore").strip()

            if status != "FOUND":
                messagebox.showerror("Error", "File not found on server")
                return

            enc_len = int.from_bytes(recvall(client, 8), "big")
            encrypted = recvall(client, enc_len)

            root_hash = recvall(client, 64).decode("ascii").strip()

        content = decrypt_data(encrypted)
        chunks = chunk_bytes(content)
        computed = merkle_root(chunks)

        if computed != root_hash:
            messagebox.showerror("Error", "Integrity check failed after download")
            return

        os.makedirs("Downloaded", exist_ok=True)
        out_path = os.path.join("Downloaded", filename)

        with open(out_path, "wb") as f:
            f.write(content)

        messagebox.showinfo("Success", f"File downloaded and verified!\nSaved to: {out_path}")

    except Exception as e:
        messagebox.showerror("Error", str(e))


# ────────────────────────────────────────────────
# GUI
# ────────────────────────────────────────────────

root = tk.Tk()
root.title("Secure File Transfer — Merkle Tree")
root.geometry("380x220")

tk.Label(root, text="Secure File Transfer (Merkle + Fernet)", font=("Arial", 13, "bold")).pack(pady=12)

tk.Button(root, text="Upload File", font=("Arial", 11), width=20, command=upload_file).pack(pady=8)

tk.Label(root, text="Download filename:", font=("Arial", 10)).pack()
entry = tk.Entry(root, width=35, font=("Arial", 11))
entry.pack(pady=6)

tk.Button(root, text="Download File", font=("Arial", 11), width=20, command=download_file).pack(pady=12)

root.mainloop()