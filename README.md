# 3DS-Decrypt

> Python scripts to decrypt Nintendo 3DS `.3ds` and `.cia` ROM files — no external binaries, no `boot9.bin` required.

All cryptographic keys are hardcoded directly in the scripts. Compatible with modern 3DS emulators such as [Azahar](https://azahar-emu.org/) (formerly Citra). Works on **Linux**, **macOS**, and **Windows**.

---

## Table of Contents

- [Scripts](#scripts)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
  - [Key Derivation](#key-derivation)
  - [.3ds Decryption](#3ds-decryption)
  - [.cia Decryption](#cia-decryption)
- [Supported Encryption Methods](#supported-encryption-methods)
- [Notes](#notes)
- [License](#license)

---

## Scripts

| Script | Input | Output | Method |
|---|---|---|---|
| `decrypt_3ds.py` | `.3ds` (NCSD format) | Decrypted **in-place** | AES-128-CTR |
| `decrypt_cia.py` | `.cia` | `*-decrypted.cia` alongside original | AES-128-CBC + AES-128-CTR |

---

## Requirements

- Python 3.8+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/)

> **Note:** Do **not** install `pycrypto` — it is abandoned and incompatible with Python 3.12+. Use `pycryptodome` only.

---

## Installation

```bash
pip install pycryptodome
```

Then clone the repository:

```bash
git clone https://github.com/aszuraz/3DS-Decrypt.git
cd 3DS-Decrypt
```

---

## Usage

### Decrypt a `.3ds` file

```bash
python decrypt_3ds.py "name-of-your-rom.3ds"
```

The ROM is decrypted **in-place** — the original file is modified directly. Make a backup first if needed.

### Decrypt a `.cia` file

```bash
# Single file
python decrypt_cia.py "game.cia"

# Batch mode — decrypts all .cia files in the current folder
python decrypt_cia.py
```

Output is saved as `game-decrypted.cia` alongside the original. The source file is never modified.

---

## How It Works

### Key Derivation

3DS encryption uses a **hardware key scrambler** to derive the final AES key (NormalKey) from two components:

```
NormalKey = ROL( ROL(KeyX, 2, 128) XOR KeyY + Constant, 87, 128 )
```

| Component | Description |
|---|---|
| **KeyX** | Determined by the partition's crypto flag (`0x2C`, `0x25`, `0x18`, or `0x1B`) |
| **KeyY** | First 16 bytes of the partition's RSA-2048 signature |
| **Constant** | Fixed 3DS AES hardware constant `0x1FF9E9AAC5FE0408024591DC5D52768A` |

All retail KeyX values are hardcoded in both scripts.

---

### `.3ds` Decryption

A `.3ds` file is an **NCSD container** holding up to 8 NCCH partitions (Main, Manual, Download Play, Update Data, etc.).

The script:

1. Reads the NCSD header at offset `0x100` to find partition offsets and sizes
2. For each partition, reads the crypto flags to determine the encryption method
3. Derives the NormalKey using the key scrambler formula above
4. Decrypts ExHeader, ExeFS, and RomFS **in-place** using AES-128-CTR
5. Sets the `NoCrypto` flag (`0x04`) in the partition header so emulators skip re-decrypting

**NCCH regions and their counters:**

| Region | Counter IV | Key Used |
|---|---|---|
| ExHeader | TitleID + `0x01` | NormalKey2C |
| ExeFS | TitleID + `0x02` | NormalKey2C (NormalKey for `.code` if dual-key) |
| RomFS | TitleID + `0x03` | NormalKey |

---

### `.cia` Decryption

A `.cia` (CTR Importable Archive) file has two layers of encryption.

**CIA file structure:**

```
CIA file
├── Certificate Chain
├── Ticket          ← contains encrypted Title Key + Common Key index
├── TMD             ← lists content IDs, sizes, and encryption types
└── Contents
    ├── Content 0   ← AES-CBC (Title Key) → AES-CTR (NCCH NormalKey)
    ├── Content 1
    └── ...
```

**Layer 1 — Title Key (AES-CBC)**

The CIA ticket contains an encrypted Title Key, itself encrypted with one of Nintendo's Common Keys using AES-CBC with the Title ID as IV. The script decrypts the Title Key, then uses it to strip the CBC layer from each content chunk.

**Layer 2 — NCCH (AES-CTR)**

After the CBC layer is removed, each content chunk is a standard NCCH partition — decrypted using the same key scrambler as `decrypt_3ds.py`.

The script also:
- Detects and handles **"piratelegit"** pre-decrypted CIA files (NCCH magic visible before CBC decryption)
- Patches the **TMD encryption flags** to mark contents as decrypted
- Patches the **Ticket** with the plaintext title key
- Probes all KeyX slots when the RomFS key cannot be determined from crypto flags alone

---

## Supported Encryption Methods

| Crypto Flag | KeyX Slot | Used By |
|---|---|---|
| `0x00` | `0x2C` | Original 3DS games (firmware < 6.x) |
| `0x01` | `0x25` | Games requiring firmware 7.x+ |
| `0x0A` | `0x18` | New 3DS exclusives (firmware 9.3) |
| `0x0B` | `0x1B` | New 3DS exclusives (firmware 9.6) |
| Zero Key | — | System titles with a fixed-zero key |

---

## Notes

- Both scripts support **retail keys only**. Dev-encrypted ROMs require substituting the appropriate dev KeyX values.
- `decrypt_3ds.py` modifies the `.3ds` file **in-place** — no `-decrypted` copy is created. **Back up your ROM before running.**
- `decrypt_cia.py` always creates a new `*-decrypted.cia` file and **never touches the original**.
- If a partition already has the `NoCrypto` flag set, both scripts skip it automatically.
- Alternatively, you can replace the hardcoded key bytes with a key file loader as described here: [r-roms Nintendo 3DS guide](https://r-roms.github.io/Nintendo/nintendo-3ds)

---

## License

This project is licensed under the [GPL-3.0 License](LICENSE).
