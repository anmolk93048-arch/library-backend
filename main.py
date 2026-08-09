import os
import json
import time
import uuid
import hashlib

from flask import Flask, request, jsonify
from flask_cors import CORS
from google.cloud import firestore
from google.cloud import storage as gcs_storage

app = Flask(_name_)

# मजबूत CORS और प्रीफ्लाइट सेटिंग्स
CORS(
    app,
    resources={r"/": {"origins": ""}},
    methods=["GET", "POST", "DELETE", "OPTIONS", "PUT"],
    allow_headers="*",
    supports_credentials=False,
)

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS, PUT")
        return response, 200

@app.after_request
def _ensure_cors_headers(response):
    response.headers.setdefault("Access-Control-Allow-Origin", "*")
    response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept")
    response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS, PUT")
    response.headers.setdefault("Vary", "Origin")
    return response


@app.errorhandler(Exception)
def _handle_uncaught_error(err):
    import traceback
    from werkzeug.exceptions import HTTPException

    if isinstance(err, HTTPException):
        return jsonify(error=err.description), err.code

    print("UNHANDLED ERROR:", traceback.format_exc())
    return jsonify(error="Internal server error", detail=str(err)), 500


db = firestore.Client()

GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET", "digital-library-21663-uploads")
_gcs_client = gcs_storage.Client()

ALLOWED_UPLOAD_FOLDERS = {"homepage", "login-pages", "apps"}


NODES = "rtdb_nodes"
SESSIONS = "sessions"


def _doc_id(namespace, key):
    return f"{namespace}__{key}"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@app.route("/api/health")
def health():
    firestore_status = "ok"
    try:
        db.collection(NODES).document("_health_check_").get()
    except Exception as e:
        firestore_status = "error: " + str(e)
    return jsonify(status="ok", firestore=firestore_status, time=int(time.time() * 1000))


from werkzeug.security import generate_password_hash, check_password_hash

LOGIN_ATTEMPTS = "login_attempts"
MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 15 * 60
SESSION_TTL_SECONDS = 12 * 60 * 60


def _looks_hashed(pw):
    return isinstance(pw, str) and (pw.startswith("pbkdf2:") or pw.startswith("scrypt:"))


def _last10(s):
    return "".join(ch for ch in str(s or "") if ch.isdigit())[-10:]


def _attempt_key(role, username):
    return f"{role}|{(username or '').strip().lower()}"


def _check_lockout(role, username):
    doc = db.collection(LOGIN_ATTEMPTS).document(_attempt_key(role, username)).get()
    if not doc.exists:
        return False, 0
    data = doc.to_dict()
    count = data.get("count", 0)
    window_start = data.get("windowStart", 0)
    now = time.time()
    if count >= MAX_ATTEMPTS and (now - window_start) < LOCKOUT_WINDOW_SECONDS:
        return True, int(LOCKOUT_WINDOW_SECONDS - (now - window_start))
    return False, 0


def _record_failed_attempt(role, username):
    ref = db.collection(LOGIN_ATTEMPTS).document(_attempt_key(role, username))
    doc = ref.get()
    now = time.time()
    if doc.exists:
        data = doc.to_dict()
        if (now - data.get("windowStart", 0)) >= LOCKOUT_WINDOW_SECONDS:
            ref.set({"count": 1, "windowStart": now})
        else:
            ref.set({"count": data.get("count", 0) + 1, "windowStart": data.get("windowStart", now)})
    else:
        ref.set({"count": 1, "windowStart": now})


def _clear_attempts(role, username):
    db.collection(LOGIN_ATTEMPTS).document(_attempt_key(role, username)).delete()


def _verify_admin(username, password):
    admins = _plain_get("shdl", "admins") or []
    for i, a in enumerate(admins):
        if a.get("username") == username:
            stored = a.get("password", "")
            ok = check_password_hash(stored, password) if _looks_hashed(stored) else (stored == password)
            if ok and not _looks_hashed(stored):
                admins[i]["password"] = generate_password_hash(password)
                _plain_set("shdl", "admins", admins)
            if ok:
                return {"id": a.get("id"), "name": a.get("name"), "username": a.get("username"), "role": "admin"}
            return None
    return None


def _verify_agent_or_staff(username, password):
    users = _plain_get("shdl", "agent_logins") or []
    for i, u in enumerate(users):
        if (u.get("user") or "").lower() == (username or "").lower():
            stored = u.get("pass", "")
            ok = check_password_hash(stored, password) if _looks_hashed(stored) else (stored == password)
            if ok and not _looks_hashed(stored):
                users[i]["pass"] = generate_password_hash(password)
                _plain_set("shdl", "agent_logins", users)
            if ok:
                return {"user": u.get("user"), "name": u.get("name"), "role": u.get("role"), "access": u.get("access")}
            return None
    return None


def _verify_hrms_employee(emp_id, mobile):
    employees = _plain_get("shdl", "employees") or []
    for e in employees:
        if str(e.get("empId") or "").strip().upper() == (emp_id or "").strip().upper():
            if e.get("status") == "inactive":
                return None
            registered = _last10(e.get("phone"))
            if registered and registered == _last10(mobile):
                return {"empId": e.get("empId"), "name": e.get("name"), "role": "hrms_employee"}
            return None
    return None


def _verify_student(username, mobile):
    students = _plain_get("shdl", "students") or []
    for s in students:
        sid = (s.get("studentId") or s.get("id") or "")
        if sid.upper() == (username or "").upper():
            registered = _last10(s.get("mobile") or s.get("phone"))
            if registered and registered == _last10(mobile):
                return {"id": sid, "name": s.get("name"), "role": "student"}
            return None
    return None


def _plain_get(namespace, key):
    snap = db.collection(NODES).document(_doc_id(namespace, key)).get()
    return snap.to_dict().get("value") if snap.exists else None


def _plain_set(namespace, key, value):
    db.collection(NODES).document(_doc_id(namespace, key)).set({
        "namespace": namespace, "key": key, "value": value,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    })


@app.route("/api/auth/login", methods=["POST"])
def login():
    body = request.get_json(force=True, silent=True) or {}
    role = body.get("role")
    username = body.get("username")
    password = body.get("password")
    mobile = body.get("mobile")

    if not role or not username or (role not in ("student", "hrms_employee") and not password) \
            or (role in ("student", "hrms_employee") and not mobile):
        return jsonify(error="Missing required fields"), 400

    locked, seconds_remaining = _check_lockout(role, username)
    if locked:
        return jsonify(error=f"Too many failed attempts. Try again in {seconds_remaining // 60 + 1} minute(s).",
                    code="LOCKED"), 429

    if role == "gate":
        profile = _verify_admin(username, password)
        matched_role = "admin"
        if not profile:
            profile = _verify_agent_or_staff(username, password)
            matched_role = profile.get("role", "agent").lower() if profile else None
            if matched_role not in ("agent", "staff"):
                matched_role = "agent"
    elif role == "admin":
        profile = _verify_admin(username, password)
        matched_role = "admin"
    elif role in ("agent", "staff"):
        profile = _verify_agent_or_staff(username, password)
        matched_role = role
    elif role == "hrms_employee":
        profile = _verify_hrms_employee(username, mobile)
        matched_role = "hrms_employee"
    elif role == "student":
        profile = _verify_student(username, mobile)
        matched_role = "student"
    else:
        return jsonify(error="Unknown role"), 400

    if not profile:
        _record_failed_attempt(role, username)
        return jsonify(error="Invalid credentials"), 401

    _clear_attempts(role, username)
    token = uuid.uuid4().hex
    now = time.time()
    db.collection(SESSIONS).document(token).set({
        "role": matched_role,
        "username": username,
        "profile": profile,
        "createdAt": now,
        "expiresAt": now + SESSION_TTL_SECONDS,
    })
    return jsonify(token=token, profile=profile)


def _auth_session():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[len("Bearer "):]
    ref = db.collection(SESSIONS).document(token)
    snap = ref.get()
    if not snap.exists:
        return None
    data = snap.to_dict()
    if data.get("expiresAt", 0) < time.time():
        ref.delete()
        return None
    return data


def _auth_role():
    session = _auth_session()
    return session.get("role") if session else None


def require_role(*roles):
    import functools

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            role = _auth_role()
            if role not in roles:
                return jsonify(error="Authentication required for this action."), 401
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.route("/api/node/<namespace>/<key>", methods=["GET"])
def get_node(namespace, key):
    snap = db.collection(NODES).document(_doc_id(namespace, key)).get()
    if not snap.exists:
        return jsonify(value=None)
    return jsonify(value=snap.to_dict().get("value"))


@app.route("/api/node/<namespace>/<key>", methods=["POST"])
def set_node(namespace, key):
    body = request.get_json(force=True, silent=True) or {}
    value = body.get("value")
    db.collection(NODES).document(_doc_id(namespace, key)).set({
        "namespace": namespace,
        "key": key,
        "value": value,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    })
    return jsonify(ok=True)


@app.route("/api/node/<namespace>/<key>", methods=["DELETE"])
def delete_node(namespace, key):
    db.collection(NODES).document(_doc_id(namespace, key)).delete()
    return jsonify(ok=True)


@app.route("/api/node/<namespace>", methods=["DELETE"])
@require_role("admin")
def delete_namespace(namespace):
    docs = db.collection(NODES).where("namespace", "==", namespace).stream()
    batch = db.batch()
    count = 0
    for d in docs:
        batch.delete(d.reference)
        count += 1
        if count % 400 == 0:
            batch.commit()
            batch = db.batch()
    batch.commit()
    return jsonify(ok=True, deleted=count)


ADMIN_ENTITY_KEYS = {"admins", "staff", "agents", "students"}
BLOB_KEYS = {
    "settings", "activity", "notices", "mem_plans", "members",
    "hrms_registrations", "staff_att", "leave_requests", "agent_plans",
    "agent_payments", "razorpay_config", "sms_api_config",
}


@app.route("/api/admin-entities/<key>", methods=["GET"])
def get_admin_entity(key):
    if key not in ADMIN_ENTITY_KEYS:
        return jsonify(error="Unknown entity key: " + key), 404
    try:
        value = _plain_get("shdl", key)
        return jsonify(value if value is not None else [])
    except Exception as e:
        print(f"Error fetching admin entity {key}: {str(e)}")
        return jsonify([])


@app.route("/api/admin-entities/<key>", methods=["POST"])
@require_role("admin")
def set_admin_entity(key):
    if key not in ADMIN_ENTITY_KEYS:
        return jsonify(error="Unknown entity key: " + key), 404
    body = request.get_json(force=True, silent=True)
    if body is None:
        body = []
    _plain_set("shdl", key, body)
    return jsonify(ok=True)


@app.route("/api/blob/<key>", methods=["GET"])
def get_blob(key):
    if key not in BLOB_KEYS:
        return jsonify(error="Unknown blob key: " + key), 404
    try:
        value = _plain_get("shdl", key)
        return jsonify(value if value is not None else {})
    except Exception as e:
        print(f"Error fetching blob {key}: {str(e)}")
        return jsonify(None)


@app.route("/api/blob/<key>", methods=["POST"])
def set_blob(key):
    if key not in BLOB_KEYS:
        return jsonify(error="Unknown blob key: " + key), 404
    body = request.get_json(force=True, silent=True)
    _plain_set("shdl", key, body)
    return jsonify(ok=True)


@app.route("/api/blob/<key>", methods=["DELETE"])
def delete_blob(key):
    if key not in BLOB_KEYS:
        return jsonify(error="Unknown blob key: " + key), 404
    db.collection(NODES).document(_doc_id("shdl", key)).delete()
    return jsonify(ok=True)


@app.route("/api/register", methods=["POST"])
def register():
    body = request.get_json(force=True, silent=True) or {}
    role = (body.get("role") or "").strip().lower()
    if role not in ("admin", "agent", "staff", "student"):
        return jsonify(error="role must be one of: admin, agent, staff, student"), 400

    now_ms = int(time.time() * 1000)
    new_id = uuid.uuid4().hex

    if role == "admin":
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        if not username or not password:
            return jsonify(error="username and password are required"), 400
        admins = _plain_get("shdl", "admins") or []
        if any(a.get("username") == username for a in admins):
            return jsonify(error="Username already exists"), 409
        record = {
            "id": new_id, "name": body.get("name") or username,
            "username": username, "password": generate_password_hash(password),
            "createdAt": now_ms,
        }
        admins.append(record)
        _plain_set("shdl", "admins", admins)
        return jsonify({k: v for k, v in record.items() if k != "password"})

    if role in ("agent", "staff"):
        username = (body.get("username") or body.get("user") or "").strip()
        password = body.get("password") or body.get("pass") or ""
        if not username or not password:
            return jsonify(error="username and password are required"), 400
        users = _plain_get("shdl", "agent_logins") or []
        if any((u.get("user") or "").lower() == username.lower() for u in users):
            return jsonify(error="Username already exists"), 409
        record = {
            "id": new_id, "user": username, "pass": generate_password_hash(password),
            "name": body.get("name") or username, "role": role,
            "access": body.get("access"), "createdAt": now_ms,
        }
        users.append(record)
        _plain_set("shdl", "agent_logins", users)
        roster_key = "staff" if role == "staff" else "agents"
        roster = _plain_get("shdl", roster_key) or []
        roster.append({
            "id": new_id, "name": record["name"], "role": role,
            "mobile": body.get("mobile"), "status": "active", "created": now_ms,
        })
        _plain_set("shdl", roster_key, roster)
        return jsonify({k: v for k, v in record.items() if k != "pass"})

    if role == "student":
        student_id = (body.get("studentId") or body.get("id") or "").strip()
        mobile = body.get("mobile") or body.get("phone") or ""
        if not student_id or not mobile:
            return jsonify(error="studentId and mobile are required"), 400
        students = _plain_get("shdl", "students") or []
        if any((s.get("studentId") or s.get("id") or "").upper() == student_id.upper() for s in students):
            return jsonify(error="Student ID already exists"), 409
        record = {
            "id": new_id, "studentId": student_id, "name": body.get("name") or "",
            "mobile": mobile, "status": "active", "createdAt": now_ms,
        }
        students.append(record)
        _plain_set("shdl", "students", students)
        return jsonify(record)


@app.route("/api/node-cas/<namespace>/<key>", methods=["POST"])
def cas_node(namespace, key):
    body = request.get_json(force=True, silent=True) or {}
    expected = body.get("expected", None)
    new_value = body.get("value", None)

    doc_ref = db.collection(NODES).document(_doc_id(namespace, key))

    @firestore.transactional
    def _run(transaction):
        snap = doc_ref.get(transaction=transaction)
        current = snap.to_dict().get("value") if snap.exists else None
        if _canonical(current) != _canonical(expected):
            return False, current
        transaction.set(doc_ref, {
            "namespace": namespace,
            "key": key,
            "value": new_value,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        })
        return True, new_value

    transaction = db.transaction()
    committed, current = _run(transaction)
    return jsonify(committed=committed, current=current)


DEFAULT_COMMISSION_RATE = 10


def _get_node_value(transaction, namespace, key):
    snap = db.collection(NODES).document(_doc_id(namespace, key)).get(transaction=transaction)
    return snap.to_dict().get("value") if snap.exists else None


def _set_node_value(transaction, namespace, key, value):
    transaction.set(db.collection(NODES).document(_doc_id(namespace, key)), {
        "namespace": namespace,
        "key": key,
        "value": value,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    })


@app.route("/api/payments/student-transaction", methods=["POST"])
def create_student_transaction():
    body = request.get_json(force=True, silent=True) or {}
    agent_id = body.get("agentId")
    amount = body.get("amount")
    if not agent_id or not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify(error="agentId and a positive amount are required"), 400

    txn_id = uuid.uuid4().hex

    @firestore.transactional
    def _run(transaction):
        txns = _get_node_value(transaction, "shdl", "transactions") or {}
        wallets = _get_node_value(transaction, "shdl", "agent_wallets") or {}

        record = {
            "txnId": txn_id,
            "studentId": body.get("studentId"),
            "studentName": body.get("studentName"),
            "agentId": agent_id,
            "amount": amount,
            "paymentMode": body.get("paymentMode"),
            "gatewayRefId": body.get("gatewayRefId"),
            "status": "Pending_HRMS",
            "createdAt": int(time.time() * 1000),
        }
        txns[txn_id] = record

        wallet = wallets.get(agent_id) or {"pendingBalance": 0, "approvedBalance": 0, "totalEarned": 0}
        wallet["pendingBalance"] = (wallet.get("pendingBalance") or 0) + amount
        wallet["lastUpdated"] = int(time.time() * 1000)
        wallets[agent_id] = wallet

        _set_node_value(transaction, "shdl", "transactions", txns)
        _set_node_value(transaction, "shdl", "agent_wallets", wallets)

    _run(db.transaction())
    return jsonify(txnId=txn_id)


@app.route("/api/payments/transactions/<txn_id>/verify", methods=["POST"])
@require_role("admin", "hrms_employee")
def verify_transaction(txn_id):
    @firestore.transactional
    def _run(transaction):
        txns = _get_node_value(transaction, "shdl", "transactions") or {}
        record = txns.get(txn_id)
        if not record:
            return {"error": "Transaction not found", "code": "NOT_FOUND"}
        if record.get("status") != "Pending_HRMS":
            return {"error": "Transaction is not pending.", "code": "NOT_PENDING"}

        amount = record.get("amount") or 0
        agent_id = record.get("agentId")

        rate = _get_node_value(transaction, "shdl", "commission_rate")
        rate = rate if isinstance(rate, (int, float)) else DEFAULT_COMMISSION_RATE
        commission = round(amount * rate / 100, 2)
        agent_share = round(amount - commission, 2)

        wallets = _get_node_value(transaction, "shdl", "agent_wallets") or {}
        wallet = wallets.get(agent_id) or {"pendingBalance": 0, "approvedBalance": 0, "totalEarned": 0}
        wallet["pendingBalance"] = (wallet.get("pendingBalance") or 0) - amount
        wallet["approvedBalance"] = (wallet.get("approvedBalance") or 0) + agent_share
        wallet["totalEarned"] = (wallet.get("totalEarned") or 0) + agent_share
        wallet["lastUpdated"] = int(time.time() * 1000)
        wallets[agent_id] = wallet

        admin_wallet = _get_node_value(transaction, "shdl", "admin_wallet") or {"totalCommission": 0}
        admin_wallet["totalCommission"] = (admin_wallet.get("totalCommission") or 0) + commission

        ledger = _get_node_value(transaction, "shdl", "commission_ledger") or {}
        verified_at = int(time.time() * 1000)
        ledger[txn_id] = {
            "txnId": txn_id, "agentId": agent_id, "amount": amount,
            "commission": commission, "agentShare": agent_share, "verifiedAt": verified_at,
        }

        record["status"] = "Approved"
        record["verifiedAt"] = verified_at
        record["commission"] = commission
        record["agentShare"] = agent_share
        txns[txn_id] = record

        _set_node_value(transaction, "shdl", "transactions", txns)
        _set_node_value(transaction, "shdl", "agent_wallets", wallets)
        _set_node_value(transaction, "shdl", "admin_wallet", admin_wallet)
        _set_node_value(transaction, "shdl", "commission_ledger", ledger)

        return {"status": "Approved", "commission": commission, "agentShare": agent_share}

    result = _run(db.transaction())
    if result.get("error"):
        code = 404 if result.get("code") == "NOT_FOUND" else 409
        return jsonify(error=result["error"], code=result.get("code")), code
    return jsonify(result)


@app.route("/api/payments/transactions/<txn_id>/reject", methods=["POST"])
@require_role("admin", "hrms_employee")
def reject_transaction(txn_id):
    body = request.get_json(force=True, silent=True) or {}
    reason = body.get("reason", "")

    @firestore.transactional
    def _run(transaction):
        txns = _get_node_value(transaction, "shdl", "transactions") or {}
        record = txns.get(txn_id)
        if not record:
            return {"error": "Transaction not found", "code": "NOT_FOUND"}
        if record.get("status") != "Pending_HRMS":
            return {"error": "Transaction is not pending.", "code": "NOT_PENDING"}

        amount = record.get("amount") or 0
        agent_id = record.get("agentId")

        wallets = _get_node_value(transaction, "shdl", "agent_wallets") or {}
        wallet = wallets.get(agent_id) or {"pendingBalance": 0, "approvedBalance": 0, "totalEarned": 0}
        wallet["pendingBalance"] = (wallet.get("pendingBalance") or 0) - amount
        wallet["lastUpdated"] = int(time.time() * 1000)
        wallets[agent_id] = wallet

        record["status"] = "Rejected"
        record["reason"] = reason
        record["rejectedAt"] = int(time.time() * 1000)
        txns[txn_id] = record

        _set_node_value(transaction, "shdl", "transactions", txns)
        _set_node_value(transaction, "shdl", "agent_wallets", wallets)

        return {"status": "Rejected"}

    result = _run(db.transaction())
    if result.get("error"):
        code = 404 if result.get("code") == "NOT_FOUND" else 409
        return jsonify(error=result["error"], code=result.get("code")), code
    return jsonify(result)


SITE_DATA_NAMESPACE = "site_data"
SITE_DATA_KEYS = {
    "nav_buttons",
    "login_options",
    "homepage",
    "apps",
    "ticker",
    "stats",
    "footer",
}


@app.route("/api/site-data", methods=["GET"])
def get_all_site_data():
    result = {key: _plain_get(SITE_DATA_NAMESPACE, key) for key in SITE_DATA_KEYS}
    return jsonify(result)


@app.route("/api/site-data/<key>", methods=["GET"])
def get_site_data(key):
    if key not in SITE_DATA_KEYS:
        return jsonify(error="Unknown site-data key"), 404
    return jsonify(value=_plain_get(SITE_DATA_NAMESPACE, key))


@app.route("/api/site-data/<key>", methods=["POST"])
@require_role("admin")
def set_site_data(key):
    if key not in SITE_DATA_KEYS:
        return jsonify(error="Unknown site-data key"), 404
    body = request.get_json(force=True, silent=True) or {}
    if "value" not in body:
        return jsonify(error="value is required"), 400
    _plain_set(SITE_DATA_NAMESPACE, key, body.get("value"))
    return jsonify(ok=True)


from werkzeug.utils import secure_filename


@app.route("/api/site-content/upload-file", methods=["POST"])
@require_role("admin")
def upload_site_file():
    if "file" not in request.files:
        return jsonify(error="file is required"), 400
    f = request.files["file"]
    folder = request.form.get("folder", "")
    if folder not in ALLOWED_UPLOAD_FOLDERS:
        return jsonify(error="folder not allowed"), 400
    if not f.filename:
        return jsonify(error="empty filename"), 400

    safe_name = f"{int(time.time() * 1000)}_{secure_filename(f.filename)}"
    path = f"{folder}/{safe_name}"

    bucket = _gcs_client.bucket(GCS_BUCKET_NAME)
    blob = bucket.blob(path)
    blob.upload_from_file(f.stream, content_type=f.content_type or "application/octet-stream")

    return jsonify(
        url=f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/{path}",
        path=path,
        name=f.filename,
        size=blob.size,
    )

@app.route("/")
def home():
    return "Anmol Digital Library Backend is Running Successfully!"

if _name_ == "_main_":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8081)), debug=True)