import socket
import ssl
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import time
from crypto_utils import encrypt_data, decrypt_data, compute_hash

HOST = "127.0.0.1"
PORT = 4455

USERNAME = "admin"
PASSWORD = b"admin123"

# ───── Helper Functions ─────
def secure_socket():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return context.wrap_socket(sock, server_hostname=HOST)

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            raise ConnectionError("Connection closed unexpectedly")
        data += packet
    return data

def update_status(msg):
    status_box.insert(tk.END, msg + "\n")
    status_box.see(tk.END)

def authenticate(sock):
    sock.sendall(str(int(time.time())).encode().ljust(16))
    sock.sendall(len(USERNAME).to_bytes(4, "big"))
    sock.sendall(USERNAME.encode())
    sock.sendall(len(PASSWORD).to_bytes(4, "big"))
    sock.sendall(PASSWORD)
    response = sock.recv(16).decode().strip()
    return response == "AUTHOK"

# ───── File Operations ─────
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

        client = secure_socket()
        client.connect((HOST, PORT))

        if not authenticate(client):
            update_status("[ERROR] Authentication failed")
            client.close()
            return

        client.sendall(b"UPLOAD".ljust(16))
        client.sendall(len(filename.encode()).to_bytes(4, "big"))
        client.sendall(filename.encode())
        client.sendall(len(encrypted).to_bytes(8, "big"))
        client.sendall(encrypted)
        client.sendall(file_hash.encode())

        response = client.recv(16).decode().strip()
        update_status(f"[SERVER] {response}")
        client.close()
        list_downloaded_files()  # update downloaded files list

    except Exception as e:
        messagebox.showerror("Error", str(e))

def download_file():
    filename = server_listbox.get(tk.ACTIVE)
    if not filename:
        return

    try:
        update_status(f"[INFO] Downloading {filename}")

        client = secure_socket()
        client.connect((HOST, PORT))

        if not authenticate(client):
            update_status("[ERROR] Authentication failed")
            client.close()
            return

        client.sendall(b"DOWNLOAD".ljust(16))
        client.sendall(len(filename.encode()).to_bytes(4, "big"))
        client.sendall(filename.encode())

        status = client.recv(16).decode().strip()
        if status != "FOUND":
            update_status("[ERROR] File not found")
            client.close()
            return

        enc_len = int.from_bytes(recv_exact(client, 8), "big")
        encrypted = recv_exact(client, enc_len)
        server_hash = recv_exact(client, 64).decode()
        client.close()

        data = decrypt_data(encrypted)
        if compute_hash(data) != server_hash:
            update_status("[ERROR] Integrity check failed")
            return

        os.makedirs("Downloaded", exist_ok=True)
        save_path = os.path.join("Downloaded", filename)
        with open(save_path, "wb") as f:
            f.write(data)

        update_status(f"[SUCCESS] Saved to {save_path}")
        list_downloaded_files()

    except Exception as e:
        messagebox.showerror("Error", str(e))

def list_server_files():
    server_listbox.delete(0, tk.END)
    try:
        client = secure_socket()
        client.connect((HOST, PORT))

        if not authenticate(client):
            update_status("[ERROR] Authentication failed")
            client.close()
            return

        client.sendall(b"LIST".ljust(16))
        size = int.from_bytes(recv_exact(client, 4), "big")
        data = recv_exact(client, size).decode()
        client.close()

        for line in data.splitlines():
            server_listbox.insert(tk.END, line)

    except Exception as e:
        messagebox.showerror("Error", str(e))

def list_downloaded_files():
    downloaded_listbox.delete(0, tk.END)
    os.makedirs("Downloaded", exist_ok=True)
    for f in os.listdir("Downloaded"):
        downloaded_listbox.insert(tk.END, f)

# ───── GUI ─────
root = tk.Tk()
root.title("Secure File Transfer Client")
root.geometry("800x600")  # bigger window

tk.Label(root, text="Secure File Transfer System",
         font=("Arial", 18, "bold")).pack(pady=10)

tk.Button(root, text="Upload File", width=30,
          command=upload_file).pack(pady=5)

tk.Button(root, text="Download Selected Server File", width=30,
          command=download_file).pack(pady=5)

# Frame for side-by-side lists
list_frame = tk.Frame(root)
list_frame.pack(pady=10, fill=tk.BOTH, expand=True)

# Server files list
server_frame = tk.Frame(list_frame)
server_frame.pack(side=tk.LEFT, padx=20, fill=tk.BOTH, expand=True)
tk.Label(server_frame, text="Server Files", font=("Arial", 14, "bold")).pack()
server_listbox = tk.Listbox(server_frame, width=40, height=15)
server_listbox.pack(fill=tk.BOTH, expand=True)
tk.Button(server_frame, text="Refresh Server Files", command=list_server_files).pack(pady=5)

# Downloaded files list
downloaded_frame = tk.Frame(list_frame)
downloaded_frame.pack(side=tk.LEFT, padx=20, fill=tk.BOTH, expand=True)
tk.Label(downloaded_frame, text="Downloaded Files", font=("Arial", 14, "bold")).pack()
downloaded_listbox = tk.Listbox(downloaded_frame, width=40, height=15)
downloaded_listbox.pack(fill=tk.BOTH, expand=True)

# Status log
tk.Label(root, text="Status Log", font=("Arial", 14, "bold")).pack(pady=10)
status_box = tk.Text(root, height=10, width=100)
status_box.pack(padx=10, fill=tk.BOTH)

# Initial list of downloaded files
list_downloaded_files()
list_server_files()

root.mainloop()
