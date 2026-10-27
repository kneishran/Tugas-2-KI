import argparse
import socket
import threading
import secrets

from aes import encrypt_text, decrypt_text, check_key

def send_line(sock, text):
    sock.sendall((text + "\n").encode("ascii"))

class Peer:
    def __init__(self, my_id, master, kdc, port):
        self.id = my_id
        self.master = master
        self.kdc = kdc
        self.port = port
        self.session = None
        self.send_lock = threading.Lock()

    def start_listener(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen()
        threading.Thread(target=self.accept_loop, args=(srv,), daemon=True).start()

    def accept_loop(self, srv):
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.incoming, args=(conn, addr), daemon=True).start()

    def incoming(self, conn, addr):
        f = conn.makefile("r")
        try:
            line = f.readline().strip()
            print(f"\n[{self.id}] (3) dari {addr[0]}: {line}")
            tag, hx = line.split("|")
            ks, ida = decrypt_text(self.master, hx).split("|")
            n2 = str(secrets.randbelow(10 ** 9))
            send_line(conn, "NONCE|" + encrypt_text(ks, n2))
            print(f"[{self.id}] (4) nonce N2 dikirim")
            tag, hx = f.readline().strip().split("|")
            reply = decrypt_text(ks, hx)
            if tag != "AUTH" or reply != str(int(n2) + 1):
                send_line(conn, "FAIL")
                print(f"[{self.id}] (5) autentikasi gagal")
                conn.close()
                return
            send_line(conn, "READY")
            print(f"[{self.id}] (5) {ida} terautentikasi, session key {ks}")
            self.session = (conn, ks, ida)
            self.receive_loop(f, ks, ida)
        except Exception as e:
            print(f"\n[{self.id}] key distribution gagal: {e}")
            conn.close()

    def connect(self, ip, port, idb):
        n1 = str(secrets.randbelow(10 ** 9))
        k = socket.create_connection(self.kdc)
        kf = k.makefile("r")
        send_line(k, f"REQ|{self.id}|{idb}|{n1}")
        print(f"[{self.id}] (1) ke KDC: REQ|{self.id}|{idb}|{n1}")
        line = kf.readline().strip()
        k.close()
        parts = line.split("|")
        if parts[0] != "RESP":
            print("KDC menolak:", line)
            return
        print(f"[{self.id}] (2) dari KDC: {line}")
        ks, ida, idb2, n1r = decrypt_text(self.master, parts[1]).split("|")
        if (ida, idb2, n1r) != (self.id, idb, n1):
            print("respon KDC tidak cocok (kemungkinan replay)")
            return
        print(f"[{self.id}] session key diterima: {ks}")
        s = socket.create_connection((ip, port))
        f = s.makefile("r")
        send_line(s, "KEYDIST|" + parts[2])
        print(f"[{self.id}] (3) KEYDIST dikirim ke {ip}")
        tag, hx = f.readline().strip().split("|")
        n2 = decrypt_text(ks, hx)
        print(f"[{self.id}] (4) N2 diterima: {n2}")
        send_line(s, "AUTH|" + encrypt_text(ks, str(int(n2) + 1)))
        if f.readline().strip() != "READY":
            print("autentikasi ditolak oleh", idb)
            s.close()
            return
        print(f"[{self.id}] (5) selesai, siap berkomunikasi dengan {idb}")
        self.session = (s, ks, idb)
        threading.Thread(target=self.receive_loop, args=(f, ks, idb), daemon=True).start()

    def receive_loop(self, f, ks, pid):
        for line in f:
            try:
                tag, hx = line.strip().split("|")
                plain = decrypt_text(ks, hx)
                print(f"\n[{pid}] ciphertext: {hx}\n[{pid}] plaintext : {plain}\n{self.id}> ", end="", flush=True)
            except Exception as e:
                print(f"\npesan tidak valid: {e}")
        print(f"\nkoneksi dengan {pid} terputus")
        self.session = None

    def send(self, text):
        if not self.session:
            print("belum ada sesi, gunakan connect")
            return
        sock, ks, pid = self.session
        hx = encrypt_text(ks, text)
        with self.send_lock:
            send_line(sock, "MSG|" + hx)
        print(f"[{self.id}] ciphertext ke {pid}: {hx}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--kdc", required=True, help="ip:port KDC")
    ap.add_argument("--port", type=int, default=6000)
    a = ap.parse_args()
    host, kport = a.kdc.split(":")
    master = input("master key (16/24/32 karakter ASCII): ")
    check_key(master)
    peer = Peer(a.id, master, (host, int(kport)), a.port)
    peer.start_listener()
    print("perintah: connect <ip> <port> <id> | send <teks> | masterkey <key> | status | quit")
    while True:
        try:
            cmd = input(f"{a.id}> ").split(" ", 1)
        except EOFError:
            break
        try:
            if cmd[0] == "connect":
                ip, port, idb = cmd[1].split()
                peer.connect(ip, int(port), idb)
            elif cmd[0] == "send":
                peer.send(cmd[1])
            elif cmd[0] == "masterkey":
                check_key(cmd[1])
                peer.master = cmd[1]
                print("master key diganti")
            elif cmd[0] == "status":
                print("sesi:", peer.session[2:] if peer.session else None)
            elif cmd[0] == "quit":
                break
        except Exception as e:
            print("error:", e)

if __name__ == "__main__":
    main()
