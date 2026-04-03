# 3DS-Decrypt

Python scripts to decrypt `.3ds` and `.cia` ROM files for use in modern 3DS emulators such as [Azahar](https://azahar-emu.org/) (formerly Citra). No external binaries, no `boot9.bin` required. all cryptographic keys are hardcoded directly in the scripts. Built in Python for Linux and MacOs users. 

Alternatively you could replace the harcoded key bytes in the script with a key file loader using as explained here: 
https://r-roms.github.io/Nintendo/nintendo-3ds

***

## Scripts

| Script | Input | Output |
|--------|-------|--------|
| `decrypt_3ds.py` | `.3ds` (NCSD format) | Decrypted in-place |
| `decrypt_cia.py` | `.cia` | `*-decrypted.cia` alongside original |

***

## Requirements

```bash
pip install pycryptodome
```

That's the only dependency. `pycryptodome` provides AES-CTR and AES-CBC encryption used by both scripts.

> **Note:** Do not install `pycrypto` — it is abandoned and incompatible with Python 3.12+. Use `pycryptodome` only.

***

## Usage

### Decrypt a `.3ds` file

```bash
python decrypt_3ds.py "name-of-your-3ds-file.3ds"
```

The ROM is decrypted **in-place** (the original file is modified directly). Make a backup first if needed. 

### Decrypt a `.cia` file

```bash
# Single file
python decrypt_cia.py "game.cia"

# Batch — decrypts all .cia files in the current folder
python decrypt_cia.py
```

Output is saved as `game-decrypted.cia` alongside the original.

***

## How It Works

### 3DS Encryption Overview

3DS ROMs use **AES-128-CTR** encryption across three regions of each NCCH partition:

| Region | Counter IV | Key Used |
|--------|-----------|----------|
| ExHeader | TitleID + `0x01` | NormalKey2C |
| ExeFS | TitleID + `0x02` | NormalKey2C (NormalKey for `.code` if dual-key) |
| RomFS | TitleID + `0x03` | NormalKey |

The **NormalKey** is derived using the 3DS hardware key scrambler algorithm:

```
NormalKey = ROL( ROL(KeyX, 2, 128) XOR KeyY + Constant, 87, 128 )
```

Where:
- **KeyX** is determined by the partition's crypto flag (`0x2C`, `0x25`, `0x18`, or `0x1B`)
- **KeyY** is the first 16 bytes of the partition's RSA-2048 signature
- **Constant** is the fixed 3DS AES hardware constant `0x1FF9E9AAC5FE04080245 91DC5D52768A`

All KeyX values for retail ROMs are hardcoded in both scripts.

### `.3ds` Decryption (`x.py`)

A `.3ds` file is an **NCSD container** holding up to 8 NCCH partitions (Main, Manual, Download Play, Update Data, etc.). The script:

1. Reads the NCSD header at offset `0x100` to find partition offsets and sizes
2. For each partition, reads the crypto flags to determine the encryption method
3. Derives the NormalKey using the scrambler formula above
4. Decrypts ExHeader, ExeFS, and RomFS in-place using AES-CTR
5. Sets the `NoCrypto` flag (`0x04`) in the partition header so the emulator skips re-decrypting

### `.cia` Decryption (`decrypt_cia.py`)

A `.cia` (CTR Importable Archive) file has two layers of encryption:

**Layer 1 — Title Key (AES-CBC)**

The CIA ticket contains an encrypted **Title Key**, itself encrypted with one of Nintendo's **Common Keys** using AES-CBC with the Title ID as IV. The script decrypts the Title Key, then uses it to decrypt each content chunk.

**Layer 2 — NCCH (AES-CTR)**

After the CBC layer is removed, each content chunk is a standard NCCH partition — decrypted using the same key scrambler as `x.py`.

```
CIA file
 ├── Certificate Chain
 ├── Ticket           ← contains encrypted Title Key + Common Key index
 ├── TMD              ← lists content IDs, sizes, and types
 └── Contents
      ├── Content 0   ← AES-CBC (Title Key) → AES-CTR (NCCH NormalKey)
      ├── Content 1
      └── ...
```

### Supported Encryption Methods

| Flag | KeyX Slot | Used By |
|------|-----------|---------|
| `0x00` | `0x2C` | Original 3DS games (< firmware 6.x) |
| `0x01` | `0x25` | Games requiring firmware 7.x+ |
| `0x0A` | `0x18` | New 3DS exclusives (firmware 9.3) |
| `0x0B` | `0x1B` | New 3DS exclusives (firmware 9.6) |
| Zero Key | — | System titles with fixed-zero key |

***

## Notes

- Both scripts support **retail keys only**. Dev-encrypted ROMs require uncommenting the dev key lines in `x.py`.
- `decrypt_3ds.py` modifies the `.3ds` file **in-place** — there is no `-decrypted` copy created. Back up your ROM before running.
- `decrypt_cia.py` always creates a new `*-decrypted.cia` file and never touches the original.
- If a partition is already decrypted (NoCrypto flag set), both scripts skip it automatically.
