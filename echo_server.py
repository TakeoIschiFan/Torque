import socket
import time

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 6969  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        time.sleep(5)
        conn.sendall(b"hello from server")
        print("sent")
