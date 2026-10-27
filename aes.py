import secrets

def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r

def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def build_sbox():
    sbox = [0] * 256
    for a in range(256):
        inv = 0
        if a:
            for b in range(1, 256):
                if gmul(a, b) == 1:
                    inv = b
                    break
        sbox[a] = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
    return sbox

SBOX = build_sbox()
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]

def expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]

def add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]

def sub_bytes(s, box):
    return [box[b] for b in s]

def shift_rows(s):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out

def inv_shift_rows(s):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
    return out

def mix_columns(s, m):
    out = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            v = 0
            for k in range(4):
                v ^= gmul(m[r][k], col[k])
            out[r + 4 * c] = v
    return out

def encrypt_block(block, round_keys):
    nr = len(round_keys) - 1
    s = add_round_key(list(block), round_keys[0])
    for r in range(1, nr):
        s = sub_bytes(s, SBOX)
        s = shift_rows(s)
        s = mix_columns(s, MIX)
        s = add_round_key(s, round_keys[r])
    s = sub_bytes(s, SBOX)
    s = shift_rows(s)
    s = add_round_key(s, round_keys[nr])
    return bytes(s)

def decrypt_block(block, round_keys):
    nr = len(round_keys) - 1
    s = add_round_key(list(block), round_keys[nr])
    for r in range(nr - 1, 0, -1):
        s = inv_shift_rows(s)
        s = sub_bytes(s, INV_SBOX)
        s = add_round_key(s, round_keys[r])
        s = mix_columns(s, INV_MIX)
    s = inv_shift_rows(s)
    s = sub_bytes(s, INV_SBOX)
    s = add_round_key(s, round_keys[0])
    return bytes(s)

def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n

def unpad(data):
    if not data or len(data) % 16:
        raise ValueError("panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("padding salah (key salah?)")
    return data[:-n]

def check_key(key):
    if not key.isascii() or len(key) not in (16, 24, 32):
        raise ValueError("key harus ASCII dengan panjang 16, 24, atau 32 karakter")
    return key.encode("ascii")

def cbc_encrypt(key, plain):
    rks = expand_key(key)
    iv = secrets.token_bytes(16)
    prev = iv
    out = iv
    data = pad(plain)
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = encrypt_block(blk, rks)
        out += prev
    return out

def cbc_decrypt(key, data):
    if len(data) < 32 or len(data) % 16:
        raise ValueError("ciphertext tidak valid")
    rks = expand_key(key)
    prev = data[:16]
    out = b""
    for i in range(16, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(decrypt_block(blk, rks), prev))
        prev = blk
    return unpad(out)

def encrypt_text(key_str, text):
    return cbc_encrypt(check_key(key_str), text.encode("ascii")).hex()

def decrypt_text(key_str, hex_str):
    return cbc_decrypt(check_key(key_str), bytes.fromhex(hex_str)).decode("ascii")

if __name__ == "__main__":
    k = bytes(range(16))
    p = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = encrypt_block(p, expand_key(k)).hex()
    print("AES-128 :", ct, ct == "69c4e0d86a7b0430d8cdb78070b4c55a")
    k = bytes(range(32))
    ct = encrypt_block(p, expand_key(k)).hex()
    print("AES-256 :", ct, ct == "8ea2b7ca516745bfeafc49904b496089")
    print("CBC     :", decrypt_text("kunci-rahasia-16", encrypt_text("kunci-rahasia-16", "halo dunia")))
