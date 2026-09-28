import os
import json
import base64
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

KEY_DIR = "data/keys"
DOCUMENT_DIR = "data/documents"
DECRYPTED_DIR = "data/decrypted"
AUDIT_DIR = "data/audit"

for directory in [KEY_DIR, DOCUMENT_DIR, DECRYPTED_DIR, AUDIT_DIR]:
    os.makedirs(directory, exist_ok=True)

AUDIT_FILE = os.path.join(AUDIT_DIR, "audit.json")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_rsa_keypair(username: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_path = os.path.join(KEY_DIR, f"{username}_private.pem")
    public_path = os.path.join(KEY_DIR, f"{username}_public.pem")

    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_path, public_path


def load_private_key(username: str):
    with open(os.path.join(KEY_DIR, f"{username}_private.pem"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(username: str):
    with open(os.path.join(KEY_DIR, f"{username}_public.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())


def encrypt_document(data: bytes):
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    encrypted = AESGCM(aes_key).encrypt(nonce, data, None)
    return aes_key, nonce, encrypted


def decrypt_document(aes_key: bytes, nonce: bytes, encrypted: bytes):
    return AESGCM(aes_key).decrypt(nonce, encrypted, None)


def wrap_key_for_recipient(aes_key: bytes, username: str):
    public_key = load_public_key(username)
    wrapped = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(wrapped).decode()


def unwrap_key_for_recipient(wrapped_key_b64: str, username: str):
    private_key = load_private_key(username)
    wrapped = base64.b64decode(wrapped_key_b64)
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def sign_event(event_data: str, username: str):
    private_key = load_private_key(username)
    signature = private_key.sign(
        event_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(event_data: str, signature_b64: str, username: str):
    try:
        public_key = load_public_key(username)
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            event_data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def load_audit():
    if not os.path.exists(AUDIT_FILE):
        return []
    try:
        with open(AUDIT_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_audit(events):
    with open(AUDIT_FILE, "w") as f:
        json.dump(events, f, indent=4)


def add_audit_event(event_type, username, document_name, document_hash, signature=None):
    events = load_audit()
    previous_hash = events[-1]["event_hash"] if events else "GENESIS"

    event = {
        "event_id": f"EVT-{len(events)+1:04d}",
        "event_type": event_type,
        "username": username,
        "document": document_name,
        "document_hash": document_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_hash": previous_hash,
        "signature": signature
    }

    event_string = json.dumps(event, sort_keys=True)
    event["event_hash"] = sha256_bytes(event_string.encode())

    events.append(event)
    save_audit(events)
    return event


def verify_audit_chain():
    events = load_audit()
    previous_hash = "GENESIS"

    for event in events:
        if event["previous_hash"] != previous_hash:
            return False

        copied = event.copy()
        stored_hash = copied.pop("event_hash")
        event_string = json.dumps(copied, sort_keys=True)

        if sha256_bytes(event_string.encode()) != stored_hash:
            return False

        previous_hash = stored_hash

    return True
