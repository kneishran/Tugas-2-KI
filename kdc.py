import socket
import string
import sys
import threading
import secrets

from aes import encrypt_text, check_key

ALPHABET = string.ascii_letters + string.digits
keys = {}
lock = threading.Lock()

def new_session_key():
    return "".join(secrets.choice(ALPHABET) for _ in range(16))

def send_line(conn, text):
    conn.sendall((text + "\n").encode("ascii"))

def handle(conn, addr):
    with conn, conn.makefile("r") as f:
        line = f.readline().strip()
        print(f"\n[KDC] (1) dari {addr[0]}: {line}")
        parts = line.split("|")
        if len(parts) != 4 or parts[0] != "REQ":
            send_line(conn, "ERR|format salah")
            return
        _, ida, idb, n1 = parts
        with lock:
            ka, kb = keys.get(ida), keys.get(idb)
        if ka is None or kb is None:
            send_line(conn, "ERR|ID tidak terdaftar")
            print("[KDC] ID tidak terdaftar")
            return
        ks = new_session_key()
        for_a = encrypt_text(ka, f"{ks}|{ida}|{idb}|{n1}")
        for_b = encrypt_text(kb, f"{ks}|{ida}")
        send_line(conn, f"RESP|{for_a}|{for_b}")
        print(f"[KDC] session key {ks} dibuat untuk {ida} <-> {idb}")
        print(f"[KDC] (2) E(Ka,...) = {for_a}")
        print(f"[KDC] (2) E(Kb,...) = {for_b}")

def serve(port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen()
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    threading.Thread(target=serve, args=(port,), daemon=True).start()
    print(f"KDC berjalan di port {port}")
    print("perintah: set <id> <key> | list | quit")
    while True:
        try:
            cmd = input("kdc> ").split()
        except EOFError:
            break
        if not cmd:
            continue
        if cmd[0] == "set" and len(cmd) == 3:
            try:
                check_key(cmd[2])
            except ValueError as e:
                print(e)
                continue
            with lock:
                keys[cmd[1]] = cmd[2]
            print(f"master key {cmd[1]} diset")
        elif cmd[0] == "list":
            with lock:
                for k, v in keys.items():
                    print(f"{k}: {v}")
        elif cmd[0] == "quit":
            break
        else:
            print("perintah tidak dikenal")

if __name__ == "__main__":
    main()
