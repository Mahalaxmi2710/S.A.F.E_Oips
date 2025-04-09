# SAFE OIPS (Secure Access for Enforcement)

SAFE OIPS (Secure Access Framework for Enhanced Online Integrated Police Services) is a high-assurance security framework designed to protect sensitive law enforcement systems against modern cyber threats. Built upon the foundational OIPS platform, it introduces advanced security protocols such as Multi-Factor Authentication (MFA), Role-Based Access Control (RBAC), and hybrid cryptographic techniques using AES and RSA.

---

## 🔐 Key Features

- **Multi-Factor Authentication (MFA):** 
  - Password + Console-based OTP (TOTP, RFC 6238 compliant)
  - Prevents brute-force and credential reuse attacks

- **Role-Based Access Control (RBAC):**
  - NIST RBAC standard with hierarchical roles and dynamic session-based permissions
  - Ensures least-privilege access and separation of duties

- **Hybrid Cryptography:**
  - AES in EAX mode (confidentiality + integrity)
  - RSA for secure key exchange
  - PBKDF2 for key strengthening with salt

- **Non-Cryptographic Defenses:**
  - Login attempt thresholds and session timeouts
  - Bleach library for input sanitization against XSS and SQLi

---

## 🧩 Modules Overview

1. **Authentication Module**
   - Handles MFA using password and TOTP-based OTP.
2. **Authorization Module**
   - Implements RBAC to restrict access based on user roles.
3. **Encryption/Decryption Module**
   - Encrypts data using AES (EAX) with key derived via PBKDF2.
4. **Session Management**
   - Enforces session timeout and login limits to reduce attack window.
5. **Web Input Validation**
   - Secures HTML inputs with the Bleach sanitization library.

---

## ⚙️ Technologies Used

- **Python** (Core language)
- **AES (EAX mode)** via `pycryptodome`
- **RSA** for asymmetric key distribution
- **PBKDF2** for password-based key derivation
- **Bleach** for input sanitization
- **Console I/O** for OTP simulation

---

## 🛡️ Security Architecture

- **Tri-Layered Security Design**
  - Authentication → Authorization → Encryption
- **Zero Trust Principles**
  - No user or process is trusted by default
- **Defense-in-Depth**
  - Combines cryptographic and non-cryptographic techniques for holistic security

---
## 🚀 Getting Started

To get a local copy of the project up and running:

### Step 1: Clone the repository

```bash
git clone https://github.com/Mahalaxmi2710/S.A.F.E_Oips.git
cd SAFE-OIPS
```

### Step 2: Install required libraries
``` bash
pip install -r requirements.txt
```
### Step 3: Run the project
``` bash
python app.py
```


---

## 👥 Team Members

- **K. Thanushree** – 23011103021  
- **Kavya I** – 23011103024  
- **Mahalaxmi R** – 23011103030  

---

