# CRYPTORA

Cryptographic Attribution & Immutable Decryption Provenance for Multi-Recipient Encrypted Documents.

## MVP

- Face enrollment using OpenCV LBPH
- RSA-2048 recipient key generation
- AES-256-GCM document encryption
- RSA-OAEP recipient-specific AES key wrapping
- Face verification before decryption
- SHA-256 document fingerprinting
- Signed decryption events
- Hash-chained audit ledger

## Run

### 1. Create virtual environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

### 2. Install

```bash
pip install -r requirements.txt
```

### 3. Start

```bash
python app.py
```

Open:

http://127.0.0.1:8000

## Demo flow

1. Register `rahul`.
2. Register `priya`.
3. Upload a PDF.
4. Enter recipients: `rahul,priya`.
5. Encrypt.
6. Copy the Document ID.
7. Enter `rahul`.
8. Face Rahul to the camera.
9. Click Verify Face & Decrypt.
10. Verify the audit ledger.
11. Demonstrate failure by entering `rahul` while another enrolled person is in front of the camera.

## Important

This is a hackathon proof-of-concept. LBPH face recognition is not production-grade biometric authentication. A production system should add liveness detection, stronger face embeddings, secure key management/HSM or KMS, proper authentication, encrypted storage, consent/privacy controls, rate limiting, and secure secret handling.
