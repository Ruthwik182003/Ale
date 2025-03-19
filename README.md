# Altheos - Secure File Storage 🛡️

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.0.0-green)
![Cryptography](https://img.shields.io/badge/Cryptography-41.0.5-orange)

Welcome to **Altheos** – your go-to solution for securely storing and managing files! Whether you're encrypting sensitive documents or decrypting them with peace of mind, Altheos has got your back. Built with **Flask** and powered by **hybrid cryptography**, this app ensures your files are safe, secure, and tamper-proof. 🔒

---

## ✨ Features

- **Military-Grade Encryption**:
  - Uses **AES-256** for super-secure symmetric encryption.
  - Uses **RSA-2048** to lock down the encryption keys.
- **File Integrity Check**:
  - Every file is hashed with **SHA-256** to make sure it hasn’t been tampered with.
- **Easy-to-Use Web Interface**:
  - Upload, encrypt, decrypt, and download files with just a few clicks.
- **Automatic Key Management**:
  - No need to worry about keys – Altheos generates and manages them for you.

---

## 🚀 Getting Started

### What You’ll Need

- **Python 3.12** (because we like to stay updated!)
- **pip** (to install all the cool stuff)

### Let’s Set It Up!

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/altheos.git
   cd altheos

   
Create a Virtual Environment (optional but highly recommended):
python -m venv venv

On Windows:
venv\Scripts\activate

On macOS/Linux:
source venv/bin/activate

Install the Dependencies

Run the App:
python app.py

Open Your Browser:
Head over to http://127.0.0.1:5000 and start securing your files!

🛠️ How to Use
Encrypt a File
Go to the Encrypt page.

Upload your file.
Download the encrypted file and its hash for safekeeping.

Decrypt a File
Go to the Decrypt page.

Upload the encrypted file.
Altheos will decrypt it and verify its integrity using the hash.

Download Files
After encrypting or decrypting, you can download the processed file from the Download page.

📂 Project Structure
Here’s what’s inside the project:

altheos/
├── app.py                  # The heart of the app – Flask magic lives here!
├── requirements.txt        # All the Python packages we need
├── private_key.pem         # Your secret RSA key (auto-generated)
├── public_key.pem          # Your public RSA key (auto-generated)
├── uploads/                # Where your uploaded and processed files live
├── static/
│   └── style.css           # Makes everything look pretty
└── templates/
    ├── index.html          # The home page
    ├── encrypt.html        # The encrypt page
    ├── decrypt.html        # The decrypt page
    └── download.html       # The download page
