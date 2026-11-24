# Payment Workflow Security Lab 🔐

A Python-based cybersecurity research project exploring payment workflow manipulation and defensive security controls through safe, isolated local simulations.

## Project Overview

This project demonstrates how weaknesses in payment workflows can affect transaction integrity, beneficiary information, approval permissions and audit records.

The objective is to understand common security weaknesses and develop defensive mechanisms to identify suspicious modifications.

## Technologies Used

- Python 3
- SQLite
- HMAC-SHA256
- SHA-256
- Python `hashlib`, `hmac` and `secrets`
- Linux / Kali Linux

## Security Experiments

### 1. Normal Payment Workflow
Created and approved a fictional payment using a maker-checker workflow.

**Result:** Normal payment processing worked.

### 2. Amount Manipulation
Simulated modification of a payment amount in the local database.

**Result:** HMAC signature mismatch detected the modification.

### 3. Approver Manipulation
Tested an unauthorised employee attempting to approve a payment.

**Result:** The application rejected the unauthorised checker.

### 4. Audit Log Tampering
Modified an existing audit event in the local SQLite database.

**Result:** Hash-chain verification detected a mismatch at audit entry 2.

### 5. Beneficiary Manipulation
Simulated modification of a supplier beneficiary account.

**Result:** The current implementation incorrectly accepted the modified record. This identified an important validation gap requiring further development.

## Key Security Concepts

- Payment integrity
- HMAC-SHA256 verification
- Role-based access control
- Maker-checker authorization
- Audit-log integrity
- Hash chaining
- Security testing

## How to Run

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/payment-workflow-security-lab.git
cd payment-workflow-security-lab
```

Run the Python application:

```bash
python payment_security.py
```

No external payment gateway or real financial account is used.

## Project Structure

```text
payment-workflow-security-lab/
│
├── payment_security.py
├── README.md
└── screenshots/
    ├── normal.png
    ├── amount-manipulation.png
    ├── approver-manipulation.png
    ├── beneficiary-manipulation.png
    └── audit-tampering.png
```

## Future Improvements

- Improve beneficiary validation.
- Implement secure HMAC key management.
- Add key rotation.
- Improve role-based authorization.
- Protect audit logs against privileged modification.
- Add automated unit tests.

## Disclaimer

This project is strictly for educational cybersecurity research and defensive security learning.

All experiments were performed using fictional payment records in a local environment. No real financial systems, organisations or third-party infrastructure were targeted.

## Author

Created as a hands-on cybersecurity learning and research project.