# 🔐 Secure Data Encryption System

A **Streamlit**-based web application that allows users to **register**, **login**, **securely store**, and **retrieve encrypted data** using custom passkeys. Includes user authentication, brute-force lockout protection, and secure encryption using the `cryptography` library.

---

## 🚀 Features

- ✅ User Registration & Login
- 🔒 PBKDF2 password hashing with salt
- 🔐 Data encryption & decryption with Fernet symmetric encryption
- 🔁 Custom passkey for data retrieval
- ⏳ Lockout after 3 failed login or passkey attempts (5-minute timeout)
- 📦 Persistent encrypted data storage in `encrypted_data.json`

---

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   https://github.com/Hira-Tech-GenAi/assignment_5_giaic.git
   cd secure-data-encryption-app
