from Crypto.Cipher import AES
from Crypto.Util import Counter
from sys import argv
import struct, os, glob, shutil

rol = lambda val, r_bits, max_bits: \
    (val << r_bits % max_bits) & (2**max_bits - 1) | \
    ((val & (2**max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

def to_bytes(num):
    result = []
    tmp = num
    while len(result) < 16:
        result.append(tmp & 0xFF)
        tmp >>= 8
    return bytes(result[::-1])

def int128(tup):
    return int("%016X%016X" % tup, 16)

Constant = int128(struct.unpack('>QQ', b'\x1F\xF9\xE9\xAA\xC5\xFE\x04\x08\x02\x45\x91\xDC\x5D\x52\x76\x8A'))
KeyX_table = {
    0x2C: int128(struct.unpack('>QQ', b'\xB9\x8E\x95\xCE\xCA\x3E\x4D\x17\x1F\x76\xA9\x4D\xE9\x34\xC0\x53')),
    0x25: int128(struct.unpack('>QQ', b'\xCE\xE7\xD8\xAB\x30\xC0\x0D\xAE\x85\x0E\xF5\xE3\x82\xAC\x5A\xF3')),
    0x18: int128(struct.unpack('>QQ', b'\x82\xE9\xC9\xBE\xBF\xB8\xBD\xB8\x75\xEC\xC0\xA0\x7D\x47\x43\x74')),
    0x1B: int128(struct.unpack('>QQ', b'\x45\xAD\x04\x95\x39\x92\xC7\xC8\x93\x72\x4A\x9A\x7B\xCE\x61\x82')),
}
CRYPTO_FLAG_MAP = {0x00: 0x2C, 0x01: 0x25, 0x0A: 0x18, 0x0B: 0x1B}
plain_counter = struct.unpack('>Q', b'\x01\x00\x00\x00\x00\x00\x00\x00')
exefs_counter = struct.unpack('>Q', b'\x02\x00\x00\x00\x00\x00\x00\x00')
romfs_counter = struct.unpack('>Q', b'\x03\x00\x00\x00\x00\x00\x00\x00')
common_keys = {
    0: bytes.fromhex('64C5FD55DD3AD988325BAAEC5243DB98'),
    1: bytes.fromhex('4AAA3D0E27D4D728D0B1B433F0F9CBC8'),
}

def align64(x):
    return (x + 63) & ~63

def derive_key(keyX_id, keyY):
    return rol((rol(KeyX_table[keyX_id], 2, 128) ^ keyY) + Constant, 87, 128)

def decrypt_ncch(g, part_offset):
    g.seek(part_offset + 0x100)
    if g.read(4) != b"NCCH":
        print("  Not a valid NCCH, skipping.")
        return
    g.seek(part_offset + 0x0)
    KeyY = int128(struct.unpack('>QQ', g.read(0x10)))
    g.seek(part_offset + 0x108)
    tid = struct.unpack('<Q', g.read(8))
    plain_iv = int("%016X%016X" % (tid + plain_counter), 16)
    exefs_iv = int("%016X%016X" % (tid + exefs_counter), 16)
    romfs_iv = int("%016X%016X" % (tid + romfs_counter), 16)
    g.seek(part_offset + 0x180)
    exhdr_len = struct.unpack('<L', g.read(4))[0]
    g.seek(part_offset + 0x1A0)
    exefs_off = struct.unpack('<L', g.read(4))[0]
    exefs_len = struct.unpack('<L', g.read(4))[0]
    g.seek(part_offset + 0x1B0)
    romfs_off = struct.unpack('<L', g.read(4))[0]
    romfs_len = struct.unpack('<L', g.read(4))[0]
    g.seek(part_offset + 0x188)
    raw = g.read(8)
    if len(raw) < 8:
        return
    pf = struct.unpack('<BBBBBBBB', raw)
    if pf[7] & 0x04:
        print("  NCCH already decrypted.")
        return
    NK2C = derive_key(0x2C, KeyY)
    if pf[7] & 0x01:
        NK = 0; NK2C = 0
        print("  Key: Zero Key")
    else:
        keyX_id = CRYPTO_FLAG_MAP.get(pf[3], 0x2C)
        NK = derive_key(keyX_id, KeyY)
        print(f"  Key: {hex(keyX_id)}")
    sectorsize = 0x200
    if exhdr_len > 0:
        g.seek(part_offset + sectorsize)
        data = g.read(0x800); g.seek(part_offset + sectorsize)
        ctr = Counter.new(128, initial_value=plain_iv)
        g.write(AES.new(to_bytes(NK2C), AES.MODE_CTR, counter=ctr).decrypt(data))
        print("  ExHeader decrypted.")
    if exefs_len > 0:
        pos = part_offset + exefs_off * sectorsize
        g.seek(pos); data = g.read(sectorsize); g.seek(pos)
        ctr = Counter.new(128, initial_value=exefs_iv)
        g.write(AES.new(to_bytes(NK2C), AES.MODE_CTR, counter=ctr).decrypt(data))
        print("  ExeFS filename table decrypted.")
        exefs_data_size = (exefs_len - 1) * sectorsize
        if exefs_data_size > 0:
            ctroffset = sectorsize // 0x10
            pos2 = part_offset + (exefs_off + 1) * sectorsize
            g.seek(pos2); data = g.read(exefs_data_size); g.seek(pos2)
            ctr = Counter.new(128, initial_value=exefs_iv + ctroffset)
            g.write(AES.new(to_bytes(NK2C), AES.MODE_CTR, counter=ctr).decrypt(data))
            print("  ExeFS decrypted.")
    if romfs_off != 0:
        romfs_size = romfs_len * sectorsize
        pos = part_offset + romfs_off * sectorsize
        g.seek(pos); data = g.read(romfs_size); g.seek(pos)
        ctr = Counter.new(128, initial_value=romfs_iv)
        g.write(AES.new(to_bytes(NK), AES.MODE_CTR, counter=ctr).decrypt(data))
        print("  RomFS decrypted.")
    g.seek(part_offset + 0x18B); g.write(struct.pack('<B', 0x00))
    g.seek(part_offset + 0x18F)
    flag = (pf[7] & ((0x01 | 0x20) ^ 0xFF)) | 0x04
    g.write(struct.pack('<B', flag))

def parse_tmd(data, tmd_offset):
    """Parse TMD to extract content entries using correct signature-aware offsets."""
    # Signature type determines header size
    sig_type = struct.unpack('>L', data[tmd_offset:tmd_offset+4])[0]
    sig_sizes = {
        0x00010000: 0x200 + 0x3C,  # RSA-4096 SHA1
        0x00010001: 0x100 + 0x3C,  # RSA-2048 SHA1
        0x00010002: 0x3C + 0x40,   # EC-SHA1
        0x00010003: 0x200 + 0x3C,  # RSA-4096 SHA256
        0x00010004: 0x100 + 0x3C,  # RSA-2048 SHA256
        0x00010005: 0x3C + 0x40,   # EC-SHA256
    }
    sig_size = sig_sizes.get(sig_type, 0x100 + 0x3C)
    tmd_header_off = tmd_offset + 4 + sig_size

    content_count = struct.unpack('>H', data[tmd_header_off + 0x9E:tmd_header_off + 0xA0])[0]
    # Content info records start at header+0xC4, each is 0x24 bytes (64 total)
    content_chunk_off = tmd_header_off + 0xC4 + (64 * 0x24)

    contents = []
    for i in range(content_count):
        off = content_chunk_off + i * 0x30
        cid   = struct.unpack('>L', data[off:off+4])[0]
        cidx  = struct.unpack('>H', data[off+4:off+6])[0]
        ctype = struct.unpack('>H', data[off+6:off+8])[0]
        csz   = struct.unpack('>Q', data[off+8:off+16])[0]
        contents.append((cid, cidx, ctype, csz))
        print(f"  [TMD] Content {cidx}: ID={cid:08X}, size={csz}, encrypted={bool(ctype & 0x1)}")
    return contents

def decrypt_cia(cia_path):
    print(f"\nDecrypting: {cia_path}")
    base = os.path.splitext(cia_path)[0]
    out_path = base + "-decrypted.cia"
    shutil.copy2(cia_path, out_path)

    with open(cia_path, 'rb') as f:
        raw = f.read()

    header_size  = struct.unpack('<L', raw[0:4])[0]
    cert_size    = struct.unpack('<L', raw[0x08:0x0C])[0]
    ticket_size  = struct.unpack('<L', raw[0x0C:0x10])[0]
    tmd_size     = struct.unpack('<L', raw[0x10:0x14])[0]

    cert_off    = align64(header_size)
    ticket_off  = align64(cert_off + cert_size)
    tmd_off     = align64(ticket_off + ticket_size)
    content_off = align64(tmd_off + tmd_size)

    print(f"  header={header_size}, cert_off={cert_off}, ticket_off={ticket_off}, tmd_off={tmd_off}, content_off={content_off}")

    # Read title key from ticket
    enc_title_key  = raw[ticket_off + 0x1BF: ticket_off + 0x1CF]
    ck_index       = raw[ticket_off + 0x1F1]
    title_id_bytes = raw[ticket_off + 0x1DC: ticket_off + 0x1E4]

    ck = common_keys.get(ck_index, common_keys[0])
    title_key = AES.new(ck, AES.MODE_CBC, iv=title_id_bytes + b'\x00'*8).decrypt(enc_title_key)
    print(f"  Common key index: {ck_index}, Title ID: {title_id_bytes.hex()}")

    contents = parse_tmd(raw, tmd_off)

    with open(out_path, 'rb+') as g:
        cur = content_off
        for cid, cidx, ctype, csz in contents:
            print(f"\nContent {cidx} (ID {cid:08X}, size {csz} bytes)")
            if ctype & 0x1:
                iv = struct.pack('>H', cidx) + b'\x00'*14
                data = raw[cur:cur+csz]
                cipher = AES.new(title_key, AES.MODE_CBC, iv=iv)
                blkM = csz // (1024*1024)
                blkB = csz % (1024*1024)
                dec = b''
                for i in range(blkM):
                    dec += cipher.decrypt(data[i*1024*1024:(i+1)*1024*1024])
                    print(f"\r  CBC: {i+1}/{blkM+1} MB...", end='', flush=True)
                if blkB:
                    chunk = data[blkM*1024*1024:]
                    pad = (-len(chunk)) % 16
                    dec += cipher.decrypt(chunk + b'\x00'*pad)[:len(chunk)]
                print(f"\r  CBC layer decrypted ({csz} bytes).     ")
                g.seek(cur); g.write(dec)
            decrypt_ncch(g, cur)
            cur += csz

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