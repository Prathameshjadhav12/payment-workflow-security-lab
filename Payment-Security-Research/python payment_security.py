
import sqlite3
import hashlib
import hmac
import json
import secrets
import tempfile

from pathlib import Path


# -----------------------------------------
# CONFIGURATION
# -----------------------------------------

KEY = secrets.token_bytes(32)

TRUSTED_SUPPLIERS = {
    "ABC_SUPPLIES": "DEMO-ACCOUNT-4821"
}

AUTHORIZED_CHECKERS = {
    "manager01",
    "manager02"
}


# -----------------------------------------
# CRYPTOGRAPHIC FUNCTIONS
# -----------------------------------------

def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def sign_record(record):
    return hmac.new(
        KEY,
        canonical_json(record),
        hashlib.sha256
    ).hexdigest()


def verify_signature(record, signature):
    expected = sign_record(record)

    return hmac.compare_digest(
        expected,
        signature
    )


# -----------------------------------------
# DATABASE
# -----------------------------------------

def initialize_db(db):
    conn = sqlite3.connect(db)

    conn.execute("""
        CREATE TABLE payments (
            payment_id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            signature TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE audit_log (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------------------
# HASH-CHAIN AUDIT LOG
# -----------------------------------------

def audit_event(db, event):
    conn = sqlite3.connect(db)

    previous = conn.execute(
        "SELECT entry_hash FROM audit_log "
        "ORDER BY sequence DESC LIMIT 1"
    ).fetchone()

    previous_hash = previous[0] if previous else "GENESIS"

    material = previous_hash + event

    entry_hash = hashlib.sha256(
        material.encode()
    ).hexdigest()

    conn.execute(
        "INSERT INTO audit_log "
        "(event, previous_hash, entry_hash) "
        "VALUES (?, ?, ?)",
        (event, previous_hash, entry_hash)
    )

    conn.commit()
    conn.close()


def verify_audit_log(db):
    conn = sqlite3.connect(db)

    rows = conn.execute(
        "SELECT event, previous_hash, entry_hash "
        "FROM audit_log ORDER BY sequence"
    ).fetchall()

    conn.close()

    previous = "GENESIS"

    for event, stored_previous, stored_hash in rows:

        expected = hashlib.sha256(
            (previous + event).encode()
        ).hexdigest()

        if stored_previous != previous:
            return False

        if not hmac.compare_digest(
            expected, stored_hash
        ):
            return False

        previous = stored_hash

    return True


# -----------------------------------------
# PAYMENT CREATION
# -----------------------------------------

def create_payment(db, payment_id, maker):

    record = {
        "supplier": "ABC_SUPPLIES",
        "beneficiary": TRUSTED_SUPPLIERS["ABC_SUPPLIES"],
        "amount": 50000,
        "currency": "INR",
        "maker": maker,
        "checker": None,
        "status": "PENDING"
    }

    signature = sign_record(record)

    conn = sqlite3.connect(db)

    conn.execute(
        "INSERT INTO payments VALUES (?, ?, ?)",
        (
            payment_id,
            json.dumps(record),
            signature
        )
    )

    conn.commit()
    conn.close()

    audit_event(
        db,
        f"PAYMENT_CREATED:{payment_id}:{maker}"
    )

    print("[CREATE] Payment request created.")


# -----------------------------------------
# PAYMENT APPROVAL
# -----------------------------------------

def approve_payment(db, payment_id, checker):

    if checker not in AUTHORIZED_CHECKERS:
        print("[REJECT] Unauthorized checker.")
        return

    conn = sqlite3.connect(db)

    result = conn.execute(
        "SELECT payload, signature "
        "FROM payments WHERE payment_id=?",
        (payment_id,)
    ).fetchone()

    if not result:
        conn.close()
        print("[ERROR] Payment not found.")
        return

    record = json.loads(result[0])
    old_signature = result[1]

    # Detect pre-existing modification.
    if not verify_signature(record, old_signature):
        conn.close()
        print("[ALERT] Payment record integrity failure.")
        return

    if record["maker"] == checker:
        conn.close()
        print("[REJECT] Maker cannot approve own payment.")
        return

    if record["status"] != "PENDING":
        conn.close()
        print("[REJECT] Invalid payment status.")
        return

    if record["beneficiary"] != TRUSTED_SUPPLIERS[
        record["supplier"]
    ]:
        conn.close()
        print("[REJECT] Beneficiary mismatch.")
        return

    record["checker"] = checker
    record["status"] = "APPROVED"

    new_signature = sign_record(record)

    conn.execute(
        "UPDATE payments SET payload=?, signature=? "
        "WHERE payment_id=?",
        (
            json.dumps(record),
            new_signature,
            payment_id
        )
    )

    conn.commit()
    conn.close()

    audit_event(
        db,
        f"PAYMENT_APPROVED:{payment_id}:{checker}"
    )

    print("[APPROVED] Security checks passed.")


# -----------------------------------------
# SECURITY VERIFICATION
# -----------------------------------------

def inspect_payment(db, payment_id):

    conn = sqlite3.connect(db)

    result = conn.execute(
        "SELECT payload, signature "
        "FROM payments WHERE payment_id=?",
        (payment_id,)
    ).fetchone()

    conn.close()

    if not result:
        print("[ERROR] Payment not found.")
        return

    record = json.loads(result[0])

    if not verify_signature(record, result[1]):
        print("[ALERT] HMAC signature mismatch!")
        return

    if record["supplier"] not in TRUSTED_SUPPLIERS:
        print("[ALERT] Unknown supplier!")
        return

    if record["beneficiary"] != TRUSTED_SUPPLIERS[
        record["supplier"]
    ]:
        print("[ALERT] Beneficiary account mismatch!")
        return

    if record["status"] == "APPROVED":
        if record["checker"] not in AUTHORIZED_CHECKERS:
            print("[ALERT] Invalid approver!")
            return

        if record["maker"] == record["checker"]:
            print("[ALERT] Separation-of-duties violation!")
            return

    print("[SECURE] Payment record passed checks.")


# -----------------------------------------
# SAFE ATTACK SIMULATION
# -----------------------------------------

def simulate_tampering(db, payment_id):

    conn = sqlite3.connect(db)

    result = conn.execute(
        "SELECT payload FROM payments "
        "WHERE payment_id=?",
        (payment_id,)
    ).fetchone()

    record = json.loads(result[0])

    # Modify only the fictional local database record.
    record["beneficiary"] = "DEMO-ACCOUNT-9999"

    conn.execute(
        "UPDATE payments SET payload=? "
        "WHERE payment_id=?",
        (json.dumps(record), payment_id)
    )

    conn.commit()
    conn.close()

    print("[SIMULATION] Local record modified.")
    print("[SIMULATION] No real transaction occurred.")


# -----------------------------------------
# MAIN DEMONSTRATION
# -----------------------------------------

def main():

    with tempfile.TemporaryDirectory() as folder:

        db = Path(folder) / "payment_lab.db"

        initialize_db(db)

        print("\n=== PAYMENT SECURITY LAB ===")

        create_payment(
            db,
            "PAY-001",
            "employee01"
        )

        inspect_payment(db, "PAY-001")

        approve_payment(
            db,
            "PAY-001",
            "manager01"
        )

        inspect_payment(db, "PAY-001")

        print("\n=== TAMPERING SIMULATION ===")

        simulate_tampering(db, "PAY-001")

        inspect_payment(db, "PAY-001")

        print("\n=== AUDIT VERIFICATION ===")

        if verify_audit_log(db):
            print("[PASS] Audit chain is intact.")
        else:
            print("[ALERT] Audit log tampering detected.")

        print("\n=== LAB COMPLETE ===")


if __name__ == "__main__":
    main()
