from Crypto.Cipher import AES
from Crypto.Util import Counter
from sys import argv
import struct, os, glob, shutil

CHUNK = 8 * 1024 * 1024

rol = lambda val, r_bits, max_bits: (
    ((val << (r_bits % max_bits)) & (2**max_bits - 1))
    | ((val & (2**max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
)

def to_bytes(num):
    result = []
    tmp = num
    while len(result) < 16:
        result.append(tmp & 0xFF)
        tmp >>= 8
    return bytes(result[::-1])

def int128(tup):
    return int("%016X%016X" % tup, 16)

CONSTANT = int128(struct.unpack(">QQ", b"\x1F\xF9\xE9\xAA\xC5\xFE\x04\x08\x02\x45\x91\xDC\x5D\x52\x76\x8A"))

KEYX = {
    0x2C: int128(struct.unpack(">QQ", b"\xB9\x8E\x95\xCE\xCA\x3E\x4D\x17\x1F\x76\xA9\x4D\xE9\x34\xC0\x53")),
    0x25: int128(struct.unpack(">QQ", b"\xCE\xE7\xD8\xAB\x30\xC0\x0D\xAE\x85\x0E\xF5\xE3\x82\xAC\x5A\xF3")),
    0x18: int128(struct.unpack(">QQ", b"\x82\xE9\xC9\xBE\xBF\xB8\xBD\xB8\x75\xEC\xC0\xA0\x7D\x47\x43\x74")),
    0x1B: int128(struct.unpack(">QQ", b"\x45\xAD\x04\x95\x39\x92\xC7\xC8\x93\x72\x4A\x9A\x7B\xCE\x61\x82")),
}

CRYPTO_MAP = {0x00: 0x2C, 0x01: 0x25, 0x0A: 0x18, 0x0B: 0x1B}
KEYX_ORDER = [0x2C, 0x25, 0x18, 0x1B]

IV_PLAIN = struct.unpack(">Q", b"\x01\x00\x00\x00\x00\x00\x00\x00")
IV_EXEFS = struct.unpack(">Q", b"\x02\x00\x00\x00\x00\x00\x00\x00")
IV_ROMFS = struct.unpack(">Q", b"\x03\x00\x00\x00\x00\x00\x00\x00")

COMMON_KEYS = {
    0: bytes.fromhex("64C5FD55DD3AD988325BAAEC5243DB98"),
    1: bytes.fromhex("4AAA3D0E27D4D728D0B1B433F0F9CBC8"),
}

SIG_SIZES = {
    0x00010000: 0x200 + 0x3C,
    0x00010001: 0x100 + 0x3C,
    0x00010002: 0x3C  + 0x40,
    0x00010003: 0x200 + 0x3C,
    0x00010004: 0x100 + 0x3C,
    0x00010005: 0x3C  + 0x40,
}

def align64(x):
    return (x + 63) & ~63

def derive_key(keyx_id, keyy):
    return rol((rol(KEYX[keyx_id], 2, 128) ^ keyy) + CONSTANT, 87, 128)

def read_at(f, off, size):
    f.seek(off)
    return f.read(size)

def peek(g, offset, size=4):
    g.seek(offset)
    return g.read(size)

def is_plaintext_ncch(g, base):
    return peek(g, base + 0x100, 4) == b"NCCH"

def cbc_inplace(g, offset, size, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    done = 0
    while done < size:
        take = min(CHUNK, size - done)
        if done + take < size:
            take -= take % 16
        g.seek(offset + done)
        chunk = g.read(take)
        if len(chunk) % 16 != 0:
            pad = (-len(chunk)) % 16
            out = cipher.decrypt(chunk + b"\x00" * pad)[:len(chunk)]
        else:
            out = cipher.decrypt(chunk)
        g.seek(offset + done)
        g.write(out)
        done += take

def ctr_inplace(g, offset, size, key, counter_base):
    done = 0
    while done < size:
        take = min(CHUNK, size - done)
        g.seek(offset + done)
        chunk = g.read(take)
        ctr = Counter.new(128, initial_value=counter_base + done // 16)
        out = AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(chunk)
        g.seek(offset + done)
        g.write(out)
        done += take

def probe_romfs_key(g, offset, iv_base, keyy):
    g.seek(offset)
    sample = g.read(0x10)
    for keyx_id in KEYX_ORDER:
        nk = to_bytes(derive_key(keyx_id, keyy))
        ctr = Counter.new(128, initial_value=iv_base)
        out = AES.new(nk, AES.MODE_CTR, counter=ctr).decrypt(sample)
        if out[:4] == b"IVFC":
            return nk, keyx_id
    return None, None

def stamp_nocrypto(g, base, pf):
    g.seek(base + 0x18B)
    g.write(struct.pack("<B", 0x00))
    g.seek(base + 0x18F)
    g.write(struct.pack("<B", (pf[7] & ~(0x01 | 0x20)) | 0x04))

def decrypt_ncch(g, base):
    if peek(g, base + 0x100, 4) != b"NCCH":
        print("  Not a valid NCCH, skipping.")
        return

    g.seek(base)
    keyy = int128(struct.unpack(">QQ", g.read(0x10)))
    g.seek(base + 0x108)
    tid = struct.unpack("<Q", g.read(8))

    iv_plain = int("%016X%016X" % (tid + IV_PLAIN), 16)
    iv_exefs = int("%016X%016X" % (tid + IV_EXEFS), 16)
    iv_romfs = int("%016X%016X" % (tid + IV_ROMFS), 16)

    g.seek(base + 0x180); exhdr_len = struct.unpack("<L", g.read(4))[0]
    g.seek(base + 0x1A0); exefs_off = struct.unpack("<L", g.read(4))[0]
    g.seek(base + 0x1A4); exefs_len = struct.unpack("<L", g.read(4))[0]
    g.seek(base + 0x1B0); romfs_off = struct.unpack("<L", g.read(4))[0]
    g.seek(base + 0x1B4); romfs_len = struct.unpack("<L", g.read(4))[0]

    g.seek(base + 0x188)
    raw = g.read(8)
    if len(raw) < 8:
        return
    pf = struct.unpack("<BBBBBBBB", raw)

    if pf[7] & 0x04:
        print("  NCCH already decrypted (NoCrypto flag set).")
        return

    S = 0x200
    if exefs_off > 0:
        exefs_abs = base + exefs_off * S
        exefs_sample = peek(g, exefs_abs, 8)
        known_names = [b".code", b"icon\x00", b"banner", b"logo\x00", b"\x00\x00\x00\x00\x00\x00\x00\x00"]
        if any(exefs_sample.startswith(n) for n in known_names):
            print(f"  ExeFS plaintext detected ({exefs_sample[:6]!r}) — piratelegit pre-decrypted NCCH.")
            print("  Stamping NoCrypto, skipping all NCCH crypto.")
            stamp_nocrypto(g, base, pf)
            return

    if pf[3] not in CRYPTO_MAP and not (pf[7] & 0x01):
        print(f"  Unknown crypto_method {hex(pf[3])} — stamping NoCrypto, skipping.")
        stamp_nocrypto(g, base, pf)
        return

    nk2c = to_bytes(derive_key(0x2C, keyy))
    dual_key = False

    if pf[7] & 0x01:
        nk = b"\x00" * 16
        nk2c = b"\x00" * 16
        print("  Key: Zero Key")
    else:
        keyx_id = CRYPTO_MAP.get(pf[3], 0x2C)
        nk = to_bytes(derive_key(keyx_id, keyy))
        dual_key = (keyx_id != 0x2C)
        print(f"  Key: {hex(keyx_id)}{' (dual-key)' if dual_key else ''}")

    if exhdr_len > 0:
        ctr_inplace(g, base + S, 0x800, nk2c, iv_plain)
        print("  ExHeader decrypted.")

    if exefs_len > 0:
        exefs_abs = base + exefs_off * S
        ctr_inplace(g, exefs_abs, S, nk2c, iv_exefs)
        print("  ExeFS filename table decrypted.")
        body = (exefs_len - 1) * S
        if body > 0:
            ctr_inplace(g, exefs_abs + S, body, nk2c, iv_exefs + S // 16)
            print("  ExeFS decrypted.")
        if dual_key and body > 0:
            g.seek(exefs_abs)
            hdr = g.read(S)
            for i in range(10):
                entry = hdr[i * 0x10 : i * 0x10 + 0x10]
                name  = entry[0:8].rstrip(b"\x00")
                f_off = struct.unpack("<L", entry[8:12])[0]
                f_sz  = struct.unpack("<L", entry[12:16])[0]
                if not name or f_sz == 0:
                    continue
                if name == b".code":
                    abs_off  = exefs_abs + S + f_off
                    ctr_base = iv_exefs + (S + f_off) // 16
                    ctr_inplace(g, abs_off, f_sz, nk2c, ctr_base)
                    ctr_inplace(g, abs_off, f_sz, nk,   ctr_base)
                    print("  .code re-keyed (nk2c -> nk).")

    if romfs_off != 0:
        romfs_abs  = base + romfs_off * S
        romfs_size = romfs_len * S
        if peek(g, romfs_abs) == b"IVFC":
            print("  RomFS already plaintext, skipping.")
        else:
            g.seek(romfs_abs)
            sample = g.read(0x10)
            ctr   = Counter.new(128, initial_value=iv_romfs)
            trial = AES.new(nk, AES.MODE_CTR, counter=ctr).decrypt(sample)
            if trial[:4] == b"IVFC":
                ctr_inplace(g, romfs_abs, romfs_size, nk, iv_romfs)
                print("  RomFS decrypted.")
            else:
                print("  RomFS: probing all KeyX slots...")
                nk_romfs, found_id = probe_romfs_key(g, romfs_abs, iv_romfs, keyy)
                if nk_romfs is None:
                    print("  RomFS: no valid key found, skipping.")
                else:
                    print(f"  RomFS: key found at KeyX {hex(found_id)}")
                    ctr_inplace(g, romfs_abs, romfs_size, nk_romfs, iv_romfs)
                    print("  RomFS decrypted.")

    stamp_nocrypto(g, base, pf)

def parse_tmd(f, tmd_off):
    sig_type  = struct.unpack(">L", read_at(f, tmd_off, 4))[0]
    hdr_off   = tmd_off + 4 + SIG_SIZES.get(sig_type, 0x100 + 0x3C)
    count     = struct.unpack(">H", read_at(f, hdr_off + 0x9E, 2))[0]
    chunk_off = hdr_off + 0xC4 + 64 * 0x24
    contents  = []
    for i in range(count):
        row   = read_at(f, chunk_off + i * 0x30, 0x10)
        cid   = struct.unpack(">L", row[0:4])[0]
        cidx  = struct.unpack(">H", row[4:6])[0]
        ctype = struct.unpack(">H", row[6:8])[0]
        csz   = struct.unpack(">Q", row[8:16])[0]
        contents.append((cid, cidx, ctype, csz))
        print(f"  [TMD] Content {cidx}: ID={cid:08X}, size={csz}, encrypted={bool(ctype & 0x1)}")
    return contents, chunk_off

def patch_tmd_flags(path, chunk_off, contents):
    with open(path, "rb+") as g:
        for i, (_, _, ctype, _) in enumerate(contents):
            g.seek(chunk_off + i * 0x30 + 6)
            g.write(struct.pack(">H", ctype & ~0x1))
    print("  TMD encryption flags cleared.")

def patch_ticket(path, ticket_off, title_key):
    with open(path, "rb+") as g:
        g.seek(ticket_off + 0x1BF)
        g.write(title_key)
        g.seek(ticket_off + 0x1F1)
        g.write(b"\x00")
    print("  Ticket patched with plaintext title key.")

def decrypt_cia(cia_path):
    print(f"\nDecrypting: {cia_path}")
    out_path = os.path.splitext(cia_path)[0] + "-decrypted.cia"
    shutil.copy2(cia_path, out_path)

    with open(cia_path, "rb") as f:
        hdr         = read_at(f, 0, 0x20)
        header_size = struct.unpack("<L", hdr[0:4])[0]
        cert_size   = struct.unpack("<L", hdr[0x08:0x0C])[0]
        ticket_size = struct.unpack("<L", hdr[0x0C:0x10])[0]
        tmd_size    = struct.unpack("<L", hdr[0x10:0x14])[0]

        cert_off    = align64(header_size)
        ticket_off  = align64(cert_off + cert_size)
        tmd_off     = align64(ticket_off + ticket_size)
        content_off = align64(tmd_off + tmd_size)

        print(f"  ticket_off={ticket_off}, tmd_off={tmd_off}, content_off={content_off}")

        t              = read_at(f, ticket_off, 0x300)
        enc_title_key  = t[0x1BF:0x1CF]
        ck_index       = t[0x1F1]
        title_id_bytes = t[0x1DC:0x1E4]

        ck        = COMMON_KEYS.get(ck_index, COMMON_KEYS[0])
        title_key = AES.new(ck, AES.MODE_CBC, iv=title_id_bytes + b"\x00" * 8).decrypt(enc_title_key)
        print(f"  Common key index: {ck_index}, Title ID: {title_id_bytes.hex()}")

        contents, chunk_off = parse_tmd(f, tmd_off)

    with open(out_path, "rb+") as g:
        piratelegit = is_plaintext_ncch(g, content_off)
        if piratelegit:
            print("  NCCH magic visible before decryption — piratelegit format detected.")
            print("  Skipping CBC title-key layer for all contents.")

        patch_ticket(out_path, ticket_off, title_key)

        cur = content_off
        for cid, cidx, ctype, csz in contents:
            print(f"\nContent {cidx} (ID {cid:08X}, size {csz} bytes)")
            if (ctype & 0x1) and not piratelegit:
                iv = struct.pack(">H", cidx) + b"\x00" * 14
                cbc_inplace(g, cur, csz, title_key, iv)
                print(f"  CBC layer decrypted ({csz} bytes).")
            elif ctype & 0x1:
                print("  CBC layer skipped (piratelegit — content already plaintext).")
            decrypt_ncch(g, cur)
            cur += csz

    patch_tmd_flags(out_path, chunk_off, contents)
    print(f"\nDone: {out_path}")

if __name__ == "__main__":
    if len(argv) < 2:
        files = [f for f in glob.glob("*.cia") if "decrypted" not in f.lower()]
        if not files:
            print("No .cia files found.")
        for f in files:
            decrypt_cia(f)
    else:
        decrypt_cia(argv[1])
