# TrustSeal -  RSA Encryption, Decryption, and Digital Signature Tool

## Overview
This project implements a simple RSA-based cryptographic tool with the following features:
- Prime number generation using the Miller-Rabin primality test
- RSA key pair generation (public and private keys)
- Message encryption and decryption
- Digital signature signing and verification
- A GUI built with Tkinter to facilitate user interaction

## Features
- **Key Generation**: Generates primes (p and q) of 3 digits or more, computes modulus (n), public key (e), and private key (d).
- **Encryption/Decryption**: Encrypt messages using the public key and decrypt with the private key.
- **Digital Signatures**: Sign a message using the private key and verify it with the public key.
- **Validation**: Ensures user inputs meet RSA mathematical conditions (prime numbers, modulus consistency, and modular inverses).

## Requirements
- Python 3.x
- Tkinter (standard with Python installation)

## How to Run
1. Ensure you have Python 3.x installed.
2. Run the script `TrustSeal.py` using the command:
    ```bash
    python TrustSeal.py
    ```
3. Use the GUI to generate keys, encrypt/decrypt messages, and sign/verify digital signatures.
