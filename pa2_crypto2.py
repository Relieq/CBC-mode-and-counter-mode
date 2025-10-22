"""
Programming Assignment 2: CBC mode and counter mode (Python implementation)
- Implements AES-128/192/256 in CBC and CTR modes by composing AES-ECB.
- IV is 16 bytes, randomly chosen for encryption and *prepended* to the ciphertext.
- For CBC: PKCS#5/7 padding is used. For CTR: no padding (stream-like).
- CLI supports encrypt/decrypt; the assignment will only test decryption.
- Author: Hoàng Văn Nhân (20235542)
"""

import argparse
import sys
from typing import List, Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except Exception as e:
    print("ERROR: pycryptodome is required. Install with: pip install pycryptodome", file=sys.stderr)
    raise


BLOCK_SIZE = 16  # AES block size in bytes

# --------------------------- Built-in batch test vectors ---------------------------
BATCH: List[dict] = [
    {
        "label": "Q1 CBC",
        "mode": "cbc",
        "key_hex": "140b41b22a29beb4061bda66b6747e14",
        "ct_hex": (
            "4ca00ff4c898d61e1edbf1800618fb28"
            "28a226d160dad07883d04e008a7897ee"
            "2e4b7465d5290d0c0e6c6822236e1daa"
            "fb94ffe0c5da05d9476be028ad7c1d81"
        )
    },
    {
        "label": "Q2 CBC",
        "mode": "cbc",
        "key_hex": "140b41b22a29beb4061bda66b6747e14",
        "ct_hex": (
            "5b68629feb8606f9a6667670b75b38a5"
            "b4832d0f26e1ab7da33249de7d4afc48"
            "e713ac646ace36e872ad5fb8a512428a"
            "6e21364b0c374df45503473c5242a253"
        )
    },
    {
        "label": "Q3 CTR",
        "mode": "ctr",
        "key_hex": "36f18357be4dbd77f050515c73fcf9f2",
        "ct_hex": (
            "69dda8455c7dd4254bf353b773304eec"
            "0ec7702330098ce7f7520d1cbbb20fc3"
            "88d1b0adb5054dbd7370849dbf0b88d3"
            "93f252e764f1f5f7ad97ef79d59ce29f"
            "5f51eeca32eabedd9afa9329"
        )
    },
    {
        "label": "Q4 CTR",
        "mode": "ctr",
        "key_hex": "36f18357be4dbd77f050515c73fcf9f2",
        "ct_hex": (
            "770b80259ec33beb2561358a9f2dc617"
            "e46218c0a53cbeca695ae45faa8952aa"
            "0e311bde9d4e01726d3184c34451"
        )
    },
]


# --------------------------- Byte helpers ---------------------------

def from_hex(s: str) -> bytes:
    s = s.strip()
    s = s.removeprefix("0x").replace(" ", "").replace("_", "").replace("\n", "")
    if len(s) % 2 != 0:
        raise SystemExit("Odd-length hex string. Make sure ciphertext/key hex has even number of digits.")
    return bytes.fromhex(s)


def to_hex(b: bytes) -> str:
    return b.hex()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


# --------------------------- PKCS#5/7 padding ---------------------------

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    n = block_size - (len(data) % block_size)
    if n == 0:
        n = block_size
    return data + bytes([n]) * n


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if len(padded) == 0 or len(padded) % block_size != 0:
        raise ValueError("Invalid padded data length.")
    n = padded[-1]
    if n < 1 or n > block_size:
        raise ValueError("Invalid PKCS#7 padding byte value.")
    if padded[-n:] != bytes([n]) * n:
        raise ValueError("Invalid PKCS#7 padding content.")
    return padded[:-n]


# --------------------------- AES-ECB primitive ---------------------------

def aes_ecb_encrypt_block(key: bytes, block16: bytes) -> bytes:
    if len(block16) != BLOCK_SIZE:
        raise ValueError("ECB encrypt expects a single 16-byte block.")
    return AES.new(key, AES.MODE_ECB).encrypt(block16)


def aes_ecb_decrypt_block(key: bytes, block16: bytes) -> bytes:
    if len(block16) != BLOCK_SIZE:
        raise ValueError("ECB decrypt expects a single 16-byte block.")
    return AES.new(key, AES.MODE_ECB).decrypt(block16)


# --------------------------- CBC mode (manual) ---------------------------

def cbc_encrypt(key: bytes, plaintext: bytes, iv: Optional[bytes] = None) -> bytes:
    """
    Encrypts using AES-CBC with PKCS#7 padding. Returns IV||C.
    If iv is None, generates a random 16-byte IV.
    """
    if iv is None:
        iv = get_random_bytes(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes for AES-CBC.")
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    C_prev = iv
    out_blocks = []
    for P in split_blocks(padded, BLOCK_SIZE):
        X = xor_bytes(P, C_prev)
        C = aes_ecb_encrypt_block(key, X)
        out_blocks.append(C)
        C_prev = C
    return iv + b''.join(out_blocks)


def cbc_decrypt(key: bytes, iv_and_ct: bytes) -> bytes:
    """
    Decrypts AES-CBC with PKCS#7 unpadding. Expects input IV||C.
    Returns plaintext (bytes). Raises ValueError on padding or format problems.
    """
    if len(iv_and_ct) < BLOCK_SIZE:
        raise ValueError("Ciphertext too short; missing IV.")
    iv = iv_and_ct[:BLOCK_SIZE]
    ct = iv_and_ct[BLOCK_SIZE:]
    if len(ct) % BLOCK_SIZE != 0:
        raise ValueError("CBC ciphertext length (without IV) must be a multiple of 16.")
    C_prev = iv
    out_blocks = []
    for C in split_blocks(ct, BLOCK_SIZE):
        M = aes_ecb_decrypt_block(key, C)
        P = xor_bytes(M, C_prev)
        out_blocks.append(P)
        C_prev = C
    padded_plain = b''.join(out_blocks)
    return pkcs7_unpad(padded_plain, BLOCK_SIZE)


# --------------------------- CTR mode (manual) ---------------------------

def int_from_be(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big', signed=False)


def int_to_be(x: int, length: int) -> bytes:
    return x.to_bytes(length, byteorder='big', signed=False)


def ctr_keystream_block(key: bytes, counter_block: bytes) -> bytes:
    # CTR keystream uses AES-ENC(counter) (never dec; same for enc/dec)
    if len(counter_block) != BLOCK_SIZE:
        raise ValueError("Counter block must be 16 bytes.")
    return aes_ecb_encrypt_block(key, counter_block)


def ctr_process(key: bytes, iv_and_data: bytes, encrypting: bool) -> bytes:
    """
    CTR enc/dec (same function) by XOR with keystream.
    - For encryption: plaintext -> returns IV||ciphertext
    - For decryption: expects IV||ciphertext -> returns plaintext
    IV is a 16-byte initial counter-value (big-endian). We increment modulo 2^128.
    """
    if encrypting:
        iv = get_random_bytes(BLOCK_SIZE)
        data = iv_and_data
        start_counter = int_from_be(iv)
    else:
        if len(iv_and_data) < BLOCK_SIZE:
            raise ValueError("Ciphertext too short; missing IV.")
        iv = iv_and_data[:BLOCK_SIZE]
        data = iv_and_data[BLOCK_SIZE:]
        start_counter = int_from_be(iv)

    out = bytearray()
    counter = start_counter
    for i, block in enumerate(split_blocks(data, BLOCK_SIZE)):
        counter_block = int_to_be((counter + i) % (1 << (BLOCK_SIZE * 8)), BLOCK_SIZE)
        ks = ctr_keystream_block(key, counter_block)
        out.extend(xor_bytes(block, ks[:len(block)]))

    if encrypting:
        return iv + bytes(out)
    else:
        return bytes(out)


def ctr_encrypt(key: bytes, plaintext: bytes, iv: Optional[bytes] = None) -> bytes:
    """
    If iv is provided, it is used as the initial counter (for determinism/testing).
    Otherwise, a new random IV is generated. Returns IV||C.
    """
    if iv is not None:
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV must be 16 bytes for AES-CTR.")
        start_counter = int_from_be(iv)
        out = bytearray()
        for i, block in enumerate(split_blocks(plaintext, BLOCK_SIZE)):
            counter_block = int_to_be((start_counter + i) % (1 << (BLOCK_SIZE * 8)), BLOCK_SIZE)
            ks = ctr_keystream_block(key, counter_block)
            out.extend(xor_bytes(block, ks[:len(block)]))
        return iv + bytes(out)
    else:
        return ctr_process(key, plaintext, encrypting=True)


def ctr_decrypt(key: bytes, iv_and_ct: bytes) -> bytes:
    """Expects IV||C; returns plaintext (bytes)."""
    return ctr_process(key, iv_and_ct, encrypting=False)


# --------------------------- CLI glue ---------------------------

def validate_key(key_hex: str) -> bytes:
    key = from_hex(key_hex)
    if len(key) not in (16, 24, 32):
        raise SystemExit("Key must be 16/24/32 bytes (32/48/64 hex chars).")
    return key


def run_batch():
    if not BATCH:
        print("BATCH is empty. Edit pa2_crypto.py to add your cases under BATCH[] and rerun with --batch.", file=sys.stderr)
        return
    for i, item in enumerate(BATCH, 1):
        label = item.get("label", f"Case {i}")
        mode = item.get("mode", "").lower()
        key_hex = item.get("key_hex", "")
        ct_hex = item.get("ct_hex", "")
        if mode not in ("cbc", "ctr"):
            print(f"[{label}] ERROR: invalid mode '{mode}'", file=sys.stderr)
            continue
        try:
            key = validate_key(key_hex)
            ct = from_hex(ct_hex)
            pt = cbc_decrypt(key, ct) if mode == "cbc" else ctr_decrypt(key, ct)
            print(f"=== {label} ===")
            try:
                print(pt.decode("utf-8"))
            except UnicodeDecodeError:
                print(pt.decode("latin-1"))
        except Exception as e:
            print(f"[{label}] ERROR: {e}", file=sys.stderr)


# Don't pay too much attention to this CLI part
def read_bytes_from_args(args: argparse.Namespace) -> bytes:
    """
    Input policy (decrypt):
      - --ct-hex HEX       : read from flag
      - --ct-file FILE     : read hex from file
      - --stdin            : read hex from STDIN (e.g., echo HEX | python ... --stdin)
    Input policy (encrypt):
      - --pt TEXT | --pt-file FILE | --pt-hex HEX
    """
    if args.op == "dec":
        if args.ct_hex is not None:
            return from_hex(args.ct_hex)
        if args.ct_file is not None:
            with open(args.ct_file, "rt", encoding="utf-8") as f:
                h = f.read()
            return from_hex(h)
        if args.stdin:
            data = sys.stdin.read()
            return from_hex(data)
        raise SystemExit("Missing ciphertext input. Use --ct-hex HEX, --ct-file FILE, or --stdin.")
    else:
        if args.pt_hex is not None:
            return from_hex(args.pt_hex)
        if args.pt is not None:
            return args.pt.encode("utf-8")
        if args.pt_file is not None:
            with open(args.pt_file, "rb") as f:
                return f.read()
        raise SystemExit("Missing plaintext input. Use --pt TEXT, --pt-file FILE, or --pt-hex HEX.")


def write_output_bytes(args: argparse.Namespace, data: bytes, is_plaintext: bool):
    if args.out_file:
        with open(args.out_file, "wb") as f:
            f.write(data)
        return

    if is_plaintext:
        try:
            sys.stdout.write(data.decode("utf-8"))
        except UnicodeDecodeError:
            sys.stdout.write(data.decode("latin-1"))
        sys.stdout.flush()
    else:
        sys.stdout.write(data.hex() + "\n")
        sys.stdout.flush()


def run_cli():
    p = argparse.ArgumentParser(description="AES-CBC and AES-CTR (manual modes) with IV prepended.")
    p.add_argument("--mode", choices=["cbc", "ctr"], help="Cipher mode.")
    p.add_argument("--op", choices=["enc", "dec"], default="dec", help="Operation: encrypt or decrypt (default: dec).")
    p.add_argument("--key", help="Hex-encoded AES key (16/24/32 bytes).")

    gdec = p.add_mutually_exclusive_group()
    gdec.add_argument("--ct-hex", help="Hex-encoded ciphertext (IV||C).")
    gdec.add_argument("--ct-file", help="File containing hex-encoded ciphertext (IV||C).")
    p.add_argument("--stdin", action="store_true", help="Read hex ciphertext from STDIN (decrypt).")

    genc = p.add_mutually_exclusive_group()
    genc.add_argument("--pt", help="Plaintext text (UTF-8).")
    genc.add_argument("--pt-file", help="Plaintext file (raw bytes).")
    genc.add_argument("--pt-hex", help="Hex-encoded plaintext.")

    p.add_argument("--out-file", help="Write output bytes to this file instead of printing.")
    p.add_argument("--iv-hex", help="Hex-encoded 16-byte IV to use for encryption only (deterministic tests).")

    p.add_argument("--sanity", action="store_true", help="Run known-answer test for AES-ECB (0^128).")
    p.add_argument("--batch", action="store_true", help="Run built-in batch test vectors embedded in this file.")

    args = p.parse_args()

    if args.sanity:
        key = b'\x00' * 16
        blk = b'\x00' * 16
        out = AES.new(key, AES.MODE_ECB).encrypt(blk)
        print(out.hex())
        return

    if args.batch:
        run_batch()
        return

    if not args.mode or not args.key:
        print("Missing required flags. Examples:\n"
              "  python pa2_crypto.py --mode cbc --op dec --key <HEX> --ct-hex <HEX>\n"
              "  python pa2_crypto.py --mode ctr --op dec --key <HEX> --stdin\n"
              "  echo <HEX_CT> | python pa2_crypto.py --mode cbc --op dec --key <HEX> --stdin\n"
              "  python pa2_crypto.py --mode cbc --op enc --key <HEX> --pt 'Hello'\n",
              file=sys.stderr)
        sys.exit(2)

    key = validate_key(args.key)
    data = read_bytes_from_args(args)

    if args.op == "dec":
        if args.mode == "cbc":
            pt = cbc_decrypt(key, data)
            write_output_bytes(args, pt, is_plaintext=True)
        else:
            pt = ctr_decrypt(key, data)
            write_output_bytes(args, pt, is_plaintext=True)
    else:
        if args.mode == "cbc":
            if args.iv_hex:
                iv = from_hex(args.iv_hex)
                c = cbc_encrypt(key, data, iv=iv)
            else:
                c = cbc_encrypt(key, data)
            write_output_bytes(args, c, is_plaintext=False)
        else:
            if args.iv_hex:
                iv = from_hex(args.iv_hex)
                c = ctr_encrypt(key, data, iv=iv)
            else:
                c = ctr_encrypt(key, data)
            write_output_bytes(args, c, is_plaintext=False)


# --------------------------- Self-tests ---------------------------

def _self_test():
    assert AES.new(b'\x00'*16, AES.MODE_ECB).encrypt(b'\x00'*16).hex() == "66e94bd4ef8a2c3b884cfa59ca342b2e"
    key = b"K"*16
    pt = b"hello CBC" * 3 + b"!"
    c = cbc_encrypt(key, pt, iv=b"\x11"*16)
    assert c[:16] == b"\x11"*16
    dec = cbc_decrypt(key, c)
    assert dec == pt
    key2 = b"C"*16
    pt2 = b"CTR mode test \x00\x01\x02"
    c2 = ctr_encrypt(key2, pt2, iv=b"\x22"*16)
    assert c2[:16] == b"\x22"*16
    dec2 = ctr_decrypt(key2, c2)
    assert dec2 == pt2
    try:
        pkcs7_unpad(b"1234567890abcdef")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected padding error not raised.")
    print("All self-tests passed.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_batch()
    else:
        run_cli()
