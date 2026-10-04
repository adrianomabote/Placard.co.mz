import hmac
import os
import re
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_file, send_from_directory


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("RECEIPT_STORAGE_DIR", "/tmp/membrs-receipts"))
UPLOAD_DIR = DATA_DIR / "uploads"
DATABASE_PATH = DATA_DIR / "receipts.sqlite3"
MAX_RECEIPT_BYTES = 10 * 1024 * 1024
PHONE_PATTERN = re.compile(r"(?:82|83|84|85|86|87|88)\d{7}")
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s.]+(?:\.[^@\s.]{2,})+")

PRODUCTS = {
    "codigo-oculto": ("Código Oculto", 447),
    "combo": ("Combo Código Oculto + Mentoria em grupo", 5000),
}
PROVIDERS = {"M-Pesa", "e-Mola"}
IMAGE_TYPES = {
    "jpeg": ("image/jpeg", ".jpg"),
    "png": ("image/png", ".png"),
    "webp": ("image/webp", ".webp"),
}
STATUS_MESSAGES = {
    "pending": "Pagamento em análise.",
    "confirmed": "Pagamento confirmado.",
    "not_found": "Nenhum pagamento detectado.",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_RECEIPT_BYTES + 512 * 1024


def connect_db():
    connection = sqlite3.connect(DATABASE_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 20000")
    return connection


def initialize_storage():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with closing(connect_db()) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY,
                phone TEXT NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL,
                product_key TEXT NOT NULL,
                product_name TEXT NOT NULL,
                amount_mzn INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                received_at TEXT NOT NULL,
                reviewed_at TEXT,
                file_type TEXT NOT NULL,
                file_extension TEXT NOT NULL
            )
            """
        )
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(receipts)").fetchall()
        }
        if "email" not in columns:
            connection.execute(
                "ALTER TABLE receipts ADD COLUMN email TEXT NOT NULL DEFAULT ''"
            )
        connection.commit()


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def identify_image(data):
    if data.startswith(b"\xff\xd8\xff"):
        return IMAGE_TYPES["jpeg"]
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return IMAGE_TYPES["png"]
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return IMAGE_TYPES["webp"]
    return None


def valid_receipt_id(receipt_id):
    return re.fullmatch(r"[a-f0-9]{32}", receipt_id) is not None


def is_valid_phone(value):
    return PHONE_PATTERN.fullmatch(value) is not None


def is_valid_email(value):
    return EMAIL_PATTERN.fullmatch(value) is not None


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        expected = os.environ.get("ADMIN_PASSWORD", "")
        if not expected:
            return jsonify(error="ADMIN_PASSWORD não está configurada no servidor."), 503

        authorization = request.headers.get("Authorization", "")
        supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not supplied or not hmac.compare_digest(supplied, expected):
            return jsonify(error="Acesso de administração não autorizado."), 401
        return view(*args, **kwargs)

    return wrapped


def find_receipt(receipt_id):
    if not valid_receipt_id(receipt_id):
        return None
    with closing(connect_db()) as connection:
        return connection.execute(
            "SELECT * FROM receipts WHERE id = ?", (receipt_id,)
        ).fetchone()


def receipt_status_payload(record):
    return {
        "id": record["id"],
        "status": record["status"],
        "message": STATUS_MESSAGES[record["status"]],
    }


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if request.path.startswith("/api/") or request.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="O ficheiro excede o limite de 10 MB."), 413


@app.get("/")
def home():
    return send_from_directory(APP_DIR, "index.html")


@app.get("/payment.html")
def payment_page():
    return send_from_directory(APP_DIR, "payment.html")


@app.get("/admin")
@app.get("/admin.html")
@app.get("/admin/office")
@app.get("/admin/office/")
def admin_page():
    return send_from_directory(APP_DIR, "admin.html")


@app.get("/placard.html")
def placard_page():
    return send_from_directory(APP_DIR, "placard.html")


@app.get("/favicon.svg")
def favicon():
    return send_from_directory(APP_DIR, "favicon.svg")


@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.post("/api/receipts")
def submit_receipt():
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip().lower()
    provider = request.form.get("provider", "").strip()
    product_key = request.form.get("product", "").strip()
    upload = request.files.get("receipt")

    if not is_valid_phone(phone):
        return (
            jsonify(
                error=(
                    "Número inválido. Usa 9 dígitos começando por "
                    "82, 83, 84, 85, 86, 87 ou 88."
                )
            ),
            400,
        )
    if email and not is_valid_email(email):
        return jsonify(error="E-mail inválido. Confirma o formato, por exemplo nome@dominio.com."), 400
    if provider not in PROVIDERS:
        return jsonify(error="Escolhe M-Pesa ou e-Mola."), 400
    if product_key not in PRODUCTS:
        return jsonify(error="Escolhe o produto que pagaste."), 400
    if upload is None or not upload.filename:
        return jsonify(error="Anexa o comprovativo do pagamento."), 400

    data = upload.read(MAX_RECEIPT_BYTES + 1)
    if not data:
        return jsonify(error="O ficheiro enviado está vazio."), 400
    if len(data) > MAX_RECEIPT_BYTES:
        return jsonify(error="O ficheiro excede o limite de 10 MB."), 413

    image = identify_image(data)
    if image is None:
        return jsonify(error="Envia um comprovativo em JPG, PNG ou WebP."), 415

    file_type, extension = image
    product_name, amount_mzn = PRODUCTS[product_key]
    receipt_id = uuid.uuid4().hex
    receipt_path = UPLOAD_DIR / f"{receipt_id}{extension}"
    received_at = now_utc()

    try:
        with receipt_path.open("xb") as receipt_file:
            receipt_file.write(data)
        with closing(connect_db()) as connection:
            connection.execute(
                """
                INSERT INTO receipts (
                    id, phone, email, provider, product_key, product_name,
                    amount_mzn, status, received_at, file_type, file_extension
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                """,
                (
                    receipt_id,
                    phone,
                    email,
                    provider,
                    product_key,
                    product_name,
                    amount_mzn,
                    received_at,
                    file_type,
                    extension,
                ),
            )
            connection.commit()
    except OSError:
        receipt_path.unlink(missing_ok=True)
        app.logger.exception("Unable to save uploaded receipt")
        return jsonify(error="Não foi possível guardar o comprovativo. Tenta novamente."), 503
    except sqlite3.Error:
        receipt_path.unlink(missing_ok=True)
        app.logger.exception("Unable to record uploaded receipt")
        return jsonify(error="Não foi possível registar o comprovativo. Tenta novamente."), 503

    return (
        jsonify(
            id=receipt_id,
            status="pending",
            message=STATUS_MESSAGES["pending"],
        ),
        201,
    )


@app.post("/api/payment-status")
def lookup_payment_status():
    json_payload = request.get_json(silent=True)
    payload = json_payload if isinstance(json_payload, dict) else request.form
    identifier = str(payload.get("identifier", "")).strip()

    if is_valid_phone(identifier):
        column = "phone"
        value = identifier
    elif is_valid_email(identifier):
        column = "email"
        value = identifier.lower()
    else:
        return (
            jsonify(
                error=(
                    "Indica um e-mail válido ou um número de 9 dígitos começando por "
                    "82, 83, 84, 85, 86, 87 ou 88."
                )
            ),
            400,
        )

    with closing(connect_db()) as connection:
        record = connection.execute(
            f"SELECT status FROM receipts WHERE {column} = ? "
            "ORDER BY received_at DESC LIMIT 1",
            (value,),
        ).fetchone()

    status = record["status"] if record else "not_found"
    return jsonify(
        status=status,
        found=record is not None,
        message=STATUS_MESSAGES[status],
    )


@app.get("/api/receipts/<receipt_id>/status")
def public_receipt_status(receipt_id):
    record = find_receipt(receipt_id)
    if record is None:
        return jsonify(error="Comprovativo não encontrado."), 404
    return jsonify(receipt_status_payload(record))


@app.get("/api/admin/receipts")
@admin_required
def admin_receipts():
    with closing(connect_db()) as connection:
        records = connection.execute(
            """
            SELECT id, phone, email, provider, product_name, amount_mzn,
                   status, received_at, reviewed_at, file_type
            FROM receipts
            ORDER BY received_at DESC
            LIMIT 200
            """
        ).fetchall()
    return jsonify(receipts=[dict(record) for record in records])


@app.get("/api/admin/receipts/<receipt_id>/file")
@admin_required
def admin_receipt_file(receipt_id):
    record = find_receipt(receipt_id)
    if record is None:
        return jsonify(error="Comprovativo não encontrado."), 404

    receipt_path = UPLOAD_DIR / f"{receipt_id}{record['file_extension']}"
    if not receipt_path.is_file():
        return jsonify(error="O ficheiro deste comprovativo já não está disponível."), 404

    return send_file(
        receipt_path,
        mimetype=record["file_type"],
        as_attachment=True,
        download_name=f"comprovativo-{receipt_id}{record['file_extension']}",
        max_age=0,
    )


@app.patch("/api/admin/receipts/<receipt_id>/status")
@admin_required
def update_receipt_status(receipt_id):
    if not valid_receipt_id(receipt_id):
        return jsonify(error="Comprovativo não encontrado."), 404
    payload = request.get_json(silent=True) or {}
    new_status = payload.get("status")
    if new_status not in {"confirmed", "not_found"}:
        return jsonify(error="Escolhe confirmado ou não encontrado."), 400

    with closing(connect_db()) as connection:
        cursor = connection.execute(
            """
            UPDATE receipts SET status = ?, reviewed_at = ?
            WHERE id = ?
            """,
            (new_status, now_utc(), receipt_id),
        )
        connection.commit()
        if cursor.rowcount == 0:
            return jsonify(error="Comprovativo não encontrado."), 404

    return jsonify(id=receipt_id, status=new_status, message=STATUS_MESSAGES[new_status])


@app.delete("/api/admin/receipts/<receipt_id>")
@admin_required
def delete_receipt(receipt_id):
    record = find_receipt(receipt_id)
    if record is None:
        return jsonify(error="Comprovativo não encontrado."), 404

    with closing(connect_db()) as connection:
        connection.execute("DELETE FROM receipts WHERE id = ?", (receipt_id,))
        connection.commit()

    receipt_path = UPLOAD_DIR / f"{receipt_id}{record['file_extension']}"
    receipt_path.unlink(missing_ok=True)
    return jsonify(id=receipt_id, deleted=True)


initialize_storage()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
