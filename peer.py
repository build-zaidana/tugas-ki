"""
  python peer.py listen --key kunci123                   # Receiver
  python peer.py connect --host 127.0.0.1 --key kunci123 --port 5600 # Sender
"""
import argparse
import socket
import struct
import sys
import threading

import des


def send_message(connection, text, key, role):
    payload = des.encrypt_cbc(text.encode("utf-8"), key)
    print(f"[{role}] plaintext : {text}\n[{role}] ciphertext: {payload.hex()}  (IV+CT, {len(payload)} byte)")
    connection.sendall(struct.pack(">I", len(payload)) + payload)


def receive_exactly(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise ConnectionError
        data += chunk
    return data


def receive_loop(connection, key, role):
    try:
        while True:
            (payload_length,) = struct.unpack(">I", receive_exactly(connection, 4))
            payload = receive_exactly(connection, payload_length)
            print(f"\n[{role}] diterima  : {payload.hex()}")
            try:
                print(f"[{role}] didekripsi: {des.decrypt_cbc(payload, key).decode('utf-8')}")
            except ValueError as error:
                print(f"[{role}] gagal dekripsi: {error}")
    except (ConnectionError, OSError):
        print(f"\n[{role}] koneksi ditutup.")
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["listen", "connect"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--key", required=True, help="tepat 8 karakter")
    args = parser.parse_args()
    key = args.key.encode()
    des.generate_subkeys(key)

    if args.mode == "listen":
        server_socket = socket.socket()
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", args.port))
        server_socket.listen(1)
        print(f"Menunggu koneksi di port {args.port} ...")
        connection, address = server_socket.accept()
        role = "RECEIVER"
        print(f"Tersambung dari {address}")
    else:
        connection = socket.create_connection((args.host, args.port))
        role = "SENDER"
        print(f"Tersambung ke {args.host}:{args.port}")

    threading.Thread(target=receive_loop, args=(connection, key, role), daemon=True).start()
    try:
        for line in sys.stdin:
            message = line.rstrip("\n")
            if message == "quit":
                break
            if message:
                send_message(connection, message, key, role)
    except (BrokenPipeError, OSError):
        pass
    connection.close()


if __name__ == "__main__":
    main()
