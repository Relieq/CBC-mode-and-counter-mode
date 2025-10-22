# Programming Assignment 2 — AES in CBC and CTR

## Implementation of AES in CBC mode and counter mode (CTR)

In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR).  In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.

For CBC encryption we use the PKCS5 padding scheme discussed  in the lecture. While we ask that you implement both encryption and decryption, we will only test the decryption function.   In the following questions you are given an AES key and a ciphertext (both are  hex encoded ) and **your goal is to recover the plaintext**.

For an implementation of AES you may use an existing crypto library such as PyCrypto  (Python), Crypto++  (C++), or any other. While it is fine to use the built-in AES functions, we ask that as a learning experience you implement CBC and CTR modes yourself.


### Question 1

- CBC key: `140b41b22a29beb4061bda66b6747e14`
- CBC Ciphertext 1: 

```
4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81
```

- What is the plaintext?

### Question 2

- CBC key: `140b41b22a29beb4061bda66b6747e14`
- CBC Ciphertext 2:

```
5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253
```
- What is the plaintext?

### Question 3

- CTR key: `36f18357be4dbd77f050515c73fcf9f2`
- CTR Ciphertext 1: 

```
69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329
```

### Question 4

- CTR key: `36f18357be4dbd77f050515c73fcf9f2`
- CTR Ciphertext 2:

```
770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451
```
- What is plaintext?


**Course:** Introduction to Cryptography and Security  
**Submission:** two files — `pa2_crypto.py` (source) and `README.md`

This solution focuses on **decryption** (as requested). It **implements modes manually** using AES‑ECB as the block primitive:

- **CBC** with **PKCS#7** unpadding (a.k.a PKCS#5 for 16‑byte blocks)
- **CTR** (no padding) with a **128‑bit big‑endian counter**

The **IV is prepended** to each ciphertext and is the **first 16 bytes**.

---

# My solving

## How to run

1) Install dependency:
```bash
pip install pycryptodome
```

2) Run the program (prints four plaintexts):
```bash
python pa2_crypto.py
```

---

## Libraries used
- **pycryptodomex** — `from Crypto.Cipher import AES`

---

## How the decryption works (logic/steps)

### AES (ECB as primitive)
AES is a 16‑byte block cipher. We never use library CBC/CTR; we call **AES‑ECB on single blocks** and build the modes ourselves.

### CBC (Cipher Block Chaining)
- The ciphertext is `IV || C[0] || C[1] || …`.  
- **Decrypt per block:** `P[i] = AES_dec(C[i]) XOR C[i-1]`, with `C[-1] = IV`.  
- After concatenating all `P[i]`, remove **PKCS#7** padding:
  - Let `n = last_byte`; verify last `n` bytes are all `n`, then strip them.

### CTR (Counter mode)
- Treat the 16‑byte IV as a **128‑bit big‑endian counter**.  
- For block index `i`:
  - `keystream[i] = AES_enc( IV + i )` (mod 2^128)
  - `P[i] = C[i] XOR keystream[i]`  
- No padding; the last block may be partial.

### IV handling
- In both modes, the **IV is the first 16 bytes** of the provided ciphertext (prepended).  
- The code slices `iv = ct[:16]` and `body = ct[16:]` accordingly.

---

## All recovered plaintexts
Run `python pa2_crypto.py` and paste the outputs here if required by grading.
- **Q1 (CBC):** _Basic CBC mode encryption needs padding._
- **Q2 (CBC):** _Our implementation uses rand. IV_
- **Q3 (CTR):** _CTR mode lets you build a stream cipher from a block cipher._
- **Q4 (CTR):** _Always avoid the two time pad!_

---

## Source code quality (I think 👍)
- Minimal, readable functions: `_ecb_enc/_ecb_dec`, `_xor`, `_unpad_pkcs7`, `dec_cbc_hex`, `dec_ctr_hex`.
- Clear IV slicing and block processing; explicit PKCS#7 checks.
- Different organization and naming from any shared reference; concise but well‑commented.
