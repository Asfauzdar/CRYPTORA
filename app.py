import os
import json
import uuid
import base64

from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from crypto_utils import (
    generate_rsa_keypair,
    encrypt_document,
    decrypt_document,
    wrap_key_for_recipient,
    unwrap_key_for_recipient,
    sign_event,
    add_audit_event,
    sha256_bytes,
    load_audit,
    verify_audit_chain,
)
from face_utils import enroll_user, verify_user
from database import add_user, user_exists, get_user

app = FastAPI(title="CRYPTORA")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

DOCUMENT_META = "data/documents/metadata.json"
os.makedirs("data/documents", exist_ok=True)


def load_metadata():
    if not os.path.exists(DOCUMENT_META):
        return {}
    with open(DOCUMENT_META, "r") as f:
        return json.load(f)


def save_metadata(data):
    with open(DOCUMENT_META, "w") as f:
        json.dump(data, f, indent=4)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/enroll")
async def enroll(username: str = Form(...), image: UploadFile = File(...)):
    username = username.strip().lower()

    if not username:
        return {"success": False, "message": "Username required."}

    if user_exists(username):
        return {"success": False, "message": "User already exists."}

    image_bytes = await image.read()
    success, message = enroll_user(username, image_bytes)

    if not success:
        return {"success": False, "message": message}

    add_user(username)
    generate_rsa_keypair(username)

    add_audit_event(
        "RECIPIENT_REGISTERED",
        username,
        "identity",
        sha256_bytes(username.encode())
    )

    return {"success": True, "message": f"{username} registered successfully."}


@app.post("/encrypt")
async def encrypt(document: UploadFile = File(...), recipients: str = Form(...)):
    data = await document.read()

    recipient_list = [
        x.strip().lower() for x in recipients.split(",") if x.strip()
    ]

    if not recipient_list:
        return {"success": False, "message": "Add at least one recipient."}

    for recipient in recipient_list:
        if not user_exists(recipient):
            return {
                "success": False,
                "message": f"{recipient} is not registered."
            }

    aes_key, nonce, encrypted = encrypt_document(data)

    document_id = str(uuid.uuid4())
    encrypted_path = os.path.join(
        "data/documents", f"{document_id}.enc"
    )

    with open(encrypted_path, "wb") as f:
        f.write(encrypted)

    document_hash = sha256_bytes(data)

    wrapped_keys = {
        recipient: wrap_key_for_recipient(aes_key, recipient)
        for recipient in recipient_list
    }

    metadata = load_metadata()
    metadata[document_id] = {
        "document_id": document_id,
        "name": document.filename,
        "encrypted_file": encrypted_path,
        "nonce": base64.b64encode(nonce).decode(),
        "document_hash": document_hash,
        "recipients": recipient_list,
        "wrapped_keys": wrapped_keys,
    }
    save_metadata(metadata)

    add_audit_event(
        "DOCUMENT_ENCRYPTED",
        "owner",
        document.filename,
        document_hash
    )

    return {
        "success": True,
        "document_id": document_id,
        "document": document.filename,
        "recipients": recipient_list,
        "hash": document_hash,
    }


@app.post("/decrypt")
async def decrypt(
    document_id: str = Form(...),
    username: str = Form(...),
    image: UploadFile = File(...)
):
    username = username.strip().lower()
    user = get_user(username)

    if not user:
        return {"success": False, "message": "User not found."}

    if not user["active"]:
        return {"success": False, "message": "User access revoked."}

    metadata = load_metadata()
    if document_id not in metadata:
        return {"success": False, "message": "Document not found."}

    document = metadata[document_id]

    if username not in document["recipients"]:
        add_audit_event(
            "UNAUTHORIZED_DECRYPTION_ATTEMPT",
            username,
            document["name"],
            document["document_hash"]
        )
        return {
            "success": False,
            "message": "You are not authorized for this document."
        }

    image_bytes = await image.read()
    matched, confidence = verify_user(username, image_bytes)

    if not matched:
        add_audit_event(
            "FACE_VERIFICATION_FAILED",
            username,
            document["name"],
            document["document_hash"]
        )
        return {
            "success": False,
            "message": "Face verification failed.",
            "confidence": round(confidence, 2)
        }

    try:
        wrapped_key = document["wrapped_keys"][username]
        aes_key = unwrap_key_for_recipient(wrapped_key, username)

        with open(document["encrypted_file"], "rb") as f:
            encrypted_data = f.read()

        nonce = base64.b64decode(document["nonce"])

        decrypted = decrypt_document(
            aes_key, nonce, encrypted_data
        )

        if sha256_bytes(decrypted) != document["document_hash"]:
            return {
                "success": False,
                "message": "Document integrity verification failed."
            }

        event_text = (
            f"{document_id}|{username}|{document['document_hash']}"
        )
        signature = sign_event(event_text, username)

        event = add_audit_event(
            "DOCUMENT_DECRYPTED",
            username,
            document["name"],
            document["document_hash"],
            signature
        )

        output_name = f"{username}_{document['name']}"
        output_path = os.path.join(
            "data/decrypted", output_name
        )

        with open(output_path, "wb") as f:
            f.write(decrypted)

        return {
            "success": True,
            "message": "Face verified and document decrypted.",
            "confidence": round(confidence, 2),
            "event_id": event["event_id"],
            "signature": "VALID",
            "download": f"/download/{output_name}",
        }

    except Exception as e:
        return {
            "success": False,
            "message": f"Decryption error: {str(e)}"
        }


@app.get("/download/{filename}")
async def download(filename: str):
    path = os.path.join("data/decrypted", filename)

    if not os.path.exists(path):
        return JSONResponse({"error": "File not found"}, status_code=404)

    return FileResponse(path, filename=filename)


@app.get("/audit")
async def audit():
    events = load_audit()
    return {
        "ledger_status": "VALID" if verify_audit_chain() else "COMPROMISED",
        "events": events,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
