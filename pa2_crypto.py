from Crypto.Cipher import AES

B = 16


def _unpad_pkcs7(s: bytes) -> bytes:
    """Remove PKCS#7 padding (aka PKCS#5 for 16B block). Rises on invalid padding."""
    n = s[-1]
    if n < 1 or n > B or s[-n:] != bytes([n]) * n:
        raise ValueError("Bad PKCS#7 padding")
    return s[:-n]


def _ecb_enc(k: bytes, blk: bytes) -> bytes:
    return AES.new(k, AES.MODE_ECB).encrypt(blk)


def _ecb_dec(k: bytes, blk: bytes) -> bytes:
    return AES.new(k, AES.MODE_ECB).decrypt(blk)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def dec_cbc_hex(key_hex: str, ct_hex: str) -> bytes:
    """
    Decrypt AES-CBC with PKCS#7 unpadding.
    Input: key/ciphertext as hex strings, where ct has IV prepended.
    Logic: P[i] = AES_dec(C[i]) XOR C[i-1], with C[-1] = IV.
    """
    k = bytes.fromhex(key_hex)
    c = bytes.fromhex(ct_hex)
    iv, body = c[:B], c[B:]
    out = bytearray()
    prev = iv
    for i in range(0, len(body), B):
        block = body[i:i+B]                  # C[i]
        out.extend(_xor(_ecb_dec(k, block),  # AES_dec(C[i])
                        prev))               # XOR with C[i-1] (or IV for i=0)
        prev = block
    return _unpad_pkcs7(bytes(out))          # remove PKCS#7 padding


def dec_ctr_hex(key_hex: str, ct_hex: str) -> bytes:
    """
    Decrypt AES-CTR (same as encrypt) by XOR with keystream.
    Input: key/ciphertext as hex strings, where ct has IV (initial counter) prepended.
    Logic: keystream[i] = AES_enc((IV + i) mod 2^128), P[i] = C[i] XOR keystream[i].
    """
    k = bytes.fromhex(key_hex)
    c = bytes.fromhex(ct_hex)
    ctr0 = int.from_bytes(c[:B], "big")      # treat IV as 128-bit big-endian counter
    body = c[B:]
    out = bytearray()
    for i in range(0, len(body), B):
        # counter for block i
        ks = _ecb_enc(k, (ctr0 + i // B).to_bytes(B, "big"))
        chunk = body[i:i+B]
        out.extend(x ^ y for x, y in zip(chunk, ks))  # XOR partial if last chunk < 16
    return bytes(out)


def main():
    CBC_KEY = "140b41b22a29beb4061bda66b6747e14"
    CBC1 = ("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee"
            "2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
    CBC2 = ("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48"
            "e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")

    CTR_KEY = "36f18357be4dbd77f050515c73fcf9f2"
    CTR1 = ("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d3"
            "93f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")
    CTR2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

    for label, fn, k, ct in [
        ("=== Q1 CBC ===", dec_cbc_hex, CBC_KEY, CBC1),
        ("=== Q2 CBC ===", dec_cbc_hex, CBC_KEY, CBC2),
        ("=== Q3 CTR ===", dec_ctr_hex, CTR_KEY, CTR1),
        ("=== Q4 CTR ===", dec_ctr_hex, CTR_KEY, CTR2),
    ]:
        print(label)
        print(fn(k, ct).decode("utf-8"))


if __name__ == "__main__":
    main()
