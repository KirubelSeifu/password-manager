# 🔐 Secure Password Manager

A Python-based, locally-run password manager that securely stores your login credentials using **AES-256 encryption**. Built with the `cryptography` library, it ensures your passwords are encrypted before they are ever saved to disk. Your master password is the only key to your vault—it is never stored or transmitted.

## ✨ Features

- **🔒 End-to-End Encryption**: All passwords are encrypted with a key derived from your master password using **PBKDF2HMAC** before being saved to a file.
- **🔑 Master Password Protection**: A single master password locks your entire vault. The application uses a cryptographically secure **salt** to defend against rainbow table attacks.
- **💾 Local & Offline**: Your data never leaves your computer. Everything is stored in encrypted files (`vault.key`, `passwords.enc`) in the project directory.
- **🛡️ Security-First Design**: Implements the **Fernet** recipe from the `cryptography` library, which provides authenticated encryption.
- **📝 Clean Console Interface**: Simple, menu-driven interface for adding, viewing, and managing credentials.

## 📋 Prerequisites

- **Python 3.7 or higher**
- **`pip`** package installer

## ⚙️ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/KirubelSeifu/password-manager.git
   cd password-manager
2. **Install the required cryptography library**
   pip install cryptography
3. **Run the application**
   python password_manager.py


🚀 Usage
First Run:
The program will prompt you to create a master password. This password encrypts your entire vault.

⚠️ IMPORTANT: Do not forget this password. It cannot be recovered. If lost, all stored passwords become permanently inaccessible.

Main Menu:
You will be presented with a simple menu:

=== Secure Password Manager ===
--- Password Manager Menu ---
1. Add New Password
2. View All Passwords
3. Exit
   
Add New Password: Enter the service/website name, your username/email, and the password. It will be encrypted and saved instantly.

View All Passwords: Decrypts and displays all stored credentials. You will need to enter your master password on startup to enable this.

Exit: Safely closes the application.

🔧 How It Works (Security Model)
Key Derivation: Your master password is combined with a random salt (stored in vault.key) and processed through the PBKDF2 algorithm with 480,000 iterations to generate a strong encryption key.

Encryption: This key is used to instantiate a Fernet cipher. When you save a password, it is encrypted by this cipher.

Storage: The encrypted data is stored as a base64-encoded string in a JSON file (passwords.enc).

Decryption: To view passwords, you must provide the correct master password to regenerate the same key and decrypt the data file.

## 📁 Project Structure

```
password-manager/
├── password_manager.py
├── vault.key                 # Auto-generated, contains salt
├── passwords.enc             # Auto-generated, encrypted database
├── README.md
├── .gitignore
└── requirements.txt
```

⚠️ Important Security Notes
This is a learning project. While it uses strong, modern cryptography, it has not undergone a professional security audit.

Never commit or share your vault.key or passwords.enc files. The .gitignore file prevents this.

The strength of your vault depends on the strength of your master password. Use a long, unique passphrase.

🛠️ Built With
cryptography - The core Python library providing cryptographic primitives and recipes.

Fernet (Symmetric Encryption) - For authenticated encryption of passwords.

PBKDF2HMAC - For deriving a secure key from the master password.

Developer: Kirubel Seifu


**3. File: `requirements.txt`**
This file allows anyone to install the exact dependency needed to run your project.
```txt
cryptography>=42.0.0