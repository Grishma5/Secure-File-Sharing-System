# client.py
import socket
import tkinter as tk
from tkinter import filedialog, messagebox
import os

from crypto_utils import encrypt_data, decrypt_data, compute_hash

HOST = "192.168.56.1"
PORT = 4455


def update_status(msg):
    status_box.insert(tk.END, msg + "\n")
    status_box.see(tk.END)


def upload_file():
    path = filedialog.askopenfilename()
    if not path:
        return

    try:
        with open(path, "rb") as f:
            data = f.read()

        filename = os.path.basename(path)
        encrypted = encrypt_data(data)
        file_hash = compute_hash(data)

        update_status(f"[INFO] Uploading {filename}")
        update_status(f"[INFO] File size: {len(data)} bytes")
        update_status(f"[INFO] Hash: {file_hash}")

        with socket.socket() as client:
            client.connect((HOST, PORT))
            client.sendall(b"UPLOAD".ljust(16))

            client.sendall(len(filename.encode()).to_bytes(4, "big"))
            client.sendall(filename.encode())

            client.sendall(len(encrypted).to_bytes(8, "big"))
            client.sendall(encrypted)

            client.sendall(file_hash.encode())

            response = client.recv(16).decode().strip()

        if response == "OK":
            update_status("[SUCCESS] File uploaded successfully")
        elif response == "TOOBIG":
            update_status("[ERROR] File too large for server")
        else:
            update_status(f"[ERROR] Upload failed: {response}")

    except Exception as e:
        messagebox.showerror("Error", str(e))
        update_status(f"[ERROR] {e}")


def download_file():
    filename = entry.get().strip()
    if not filename:
        messagebox.showwarning("Input Required", "Enter filename")
        return

    try:
        update_status(f"[INFO] Downloading {filename}")

        with socket.socket() as client:
            client.connect((HOST, PORT))
            client.sendall(b"DOWNLOAD".ljust(16))

            client.sendall(len(filename.encode()).to_bytes(4, "big"))
            client.sendall(filename.encode())

            status = client.recv(16).decode().strip()
            if status == "NOTFOUND":
                update_status("[ERROR] File not found on server")
                return
            elif status != "FOUND":
                update_status(f"[ERROR] Unexpected status: {status}")
                return

            enc_len = int.from_bytes(client.recv(8), "big")
            encrypted = b""
            while len(encrypted) < enc_len:
                packet = client.recv(min(4096, enc_len - len(encrypted)))
                if not packet:
                    raise ConnectionError("Connection closed during download")
                encrypted += packet

            server_hash = client.recv(64).decode()

        data = decrypt_data(encrypted)
        local_hash = compute_hash(data)

        if local_hash != server_hash:
            update_status("[ERROR] Integrity check failed")
            return

        os.makedirs("Downloaded", exist_ok=True)
        save_path = f"Downloaded/{filename}"
        with open(save_path, "wb") as f:
            f.write(data)

        update_status(f"[SUCCESS] File downloaded & verified to {save_path}")
        update_status(f"[INFO] Hash: {local_hash}")

    except Exception as e:
        messagebox.showerror("Error", str(e))
        update_status(f"[ERROR] {e}")

def refresh_downloaded_files():
    listbox.delete(0, tk.END)
    if not os.path.exists("Downloaded"):
        return
    for f in os.listdir("Downloaded"):
        listbox.insert(tk.END, f)

def list_server_files():
    listbox.delete(0, tk.END)

    with socket.socket() as client:
        client.connect((HOST, PORT))
        client.sendall(b"LIST".ljust(16))

        size = int.from_bytes(client.recv(4), "big")
        data = client.recv(size).decode()

    for line in data.splitlines():
        listbox.insert(tk.END, line)


# ───────── GUI ─────────

root = tk.Tk()
root.title("Secure File Transfer Client")
root.geometry("520x420")

tk.Label(root, text="Secure File Transfer System",
         font=("Arial", 16, "bold")).pack(pady=10)

tk.Button(root, text="Upload File", width=25,
          command=upload_file).pack(pady=5)

tk.Label(root, text="Download filename:").pack()
entry = tk.Entry(root, width=40)
entry.pack(pady=5)

tk.Button(root, text="Download File", width=25,
          command=download_file).pack(pady=5)

tk.Label(root, text="Status Log", font=("Arial", 12, "bold")).pack(pady=10)

status_box = tk.Text(root, height=10, width=60)
status_box.pack(padx=10)

tk.Label(root, text="Downloaded Files").pack(pady=5)

listbox = tk.Listbox(root, width=40, height=6)
listbox.pack()

tk.Button(root, text="Downloaded List",
          command=refresh_downloaded_files).pack(pady=5)

tk.Button(root, text="List Server Files",
          command=list_server_files).pack(pady=5)


root.mainloop()