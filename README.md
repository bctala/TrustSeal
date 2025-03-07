# TrustSeal - Digital Signature Verifier Tool

## Overview
TrustSeal is a Python-based cryptographic tool that allows users to **digitally sign messages** using a private key and **verify signatures** with a public key. This ensures message authenticity and integrity.

## Features
- Generate RSA key pairs (public & private keys)
- Digitally sign messages using the private key
- Verify message signatures using the public key
- User-friendly command-line interface with ASCII art header

## Installation
### Prerequisites
Ensure you have Python installed. You can download it from [python.org](https://www.python.org/).

### Install Dependencies
Use the following command to install the required libraries:

```bash
pip install cryptography pyfiglet
```

## Usage
Run the script using:

```bash
python digital_signature_verifier.py
```

### Options:
1. **Generate Key Pair**
   - Creates a private key and corresponding public key.
   - Saves them as `private_key.pem` and `public_key.pem`.

2. **Sign a Message**
   - Prompts the user to enter a message.
   - Generates a digital signature using the private key.

3. **Verify a Signature**
   - Verifies a given signature with the corresponding public key.

## Example Usage
**Step 1:** Generate a key pair
```bash
python digital_signature_verifier.py --generate
```

**Step 2:** Sign a message
```bash
python digital_signature_verifier.py --sign "Hello, TrustSeal!"
```

**Step 3:** Verify a signature
```bash
python digital_signature_verifier.py --verify "Hello, TrustSeal!" signature.txt public_key.pem
```

---
### 🚀 Secure Your Messages with TrustSeal! 🚀
