from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB file size limit
app.secret_key = 'supersecretkey'  # Required for flashing messages

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Save keys to files
def save_keys(private_key, public_key, private_key_file="private_key.pem", public_key_file="public_key.pem"):
    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_file, "wb") as f:
        f.write(pem_private)

    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_file, "wb") as f:
        f.write(pem_public)


# Encrypt file using hybrid cryptography (with hashing)
def encrypt_file(file_path, public_key_file="public_key.pem"):
    try:
        # Generate a symmetric key
        symmetric_key = os.urandom(32)  # AES-256
        iv = os.urandom(16)  # Initialization vector

        # Encrypt the file data
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()

        with open(file_path, "rb") as f:
            file_data = f.read()

        # Generate SHA-256 hash of the original file
        file_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        file_hash.update(file_data)
        file_hash_digest = file_hash.finalize()

        # Pad and encrypt the file data
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Load the public key
        with open(public_key_file, "rb") as f:
            public_key_data = f.read()
            public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())

        # Encrypt the symmetric key with RSA public key
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Save the encrypted file, encrypted symmetric key, and hash
        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(file_path) + ".enc")
        with open(encrypted_file_path, "wb") as f:
            f.write(iv)
            f.write(encrypted_symmetric_key)
            f.write(encrypted_data)

        # Save the hash to a separate file
        hash_file_path = encrypted_file_path + ".hash"
        with open(hash_file_path, "wb") as f:
            f.write(file_hash_digest)
        print(f"Hash file saved as {hash_file_path}")

        print(f"File encrypted and saved as {encrypted_file_path}")
        return encrypted_file_path

    except Exception as e:
        print(f"Error during encryption: {e}")
        return None


# Decrypt file using hybrid cryptography (with hashing)
def decrypt_file(encrypted_file_path, private_key_file="private_key.pem"):
    try:
        with open(encrypted_file_path, "rb") as f:
            iv = f.read(16)  # Read the IV
            encrypted_symmetric_key = f.read(256)  # Read the encrypted symmetric key
            encrypted_data = f.read()  # Read the encrypted file data

        # Load the private key
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        # Decrypt the symmetric key with RSA private key
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the file data
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()

        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        # Save the decrypted file
        decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        # Verify file integrity using the hash
        hash_file_path = encrypted_file_path + ".hash"
        if not os.path.exists(hash_file_path):
            print("Warning: Hash file not found. Integrity check skipped.")
        else:
            with open(hash_file_path, "rb") as f:
                original_hash = f.read()

            # Generate SHA-256 hash of the decrypted file
            file_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            file_hash.update(decrypted_data)
            decrypted_hash = file_hash.finalize()

            if original_hash == decrypted_hash:
                print("File integrity verified. Decryption successful.")
            else:
                print("File integrity check failed. The file may have been tampered with.")

        print(f"File decrypted and saved as {decrypted_file_path}")
        return decrypted_file_path

    except Exception as e:
        print(f"Error during decryption: {e}")
        return None


# Flask routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if request.method == "POST":
        if 'file' not in request.files:
            flash("No file uploaded.")
            return redirect(url_for('encrypt'))

        file = request.files['file']
        if file.filename == '':
            flash("No file selected.")
            return redirect(url_for('encrypt'))

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Encrypt the file
        encrypted_file_path = encrypt_file(file_path)
        if encrypted_file_path:
            return redirect(url_for('download', filename=os.path.basename(encrypted_file_path)))
        else:
            flash("Encryption failed. Please check the logs.")
            return redirect(url_for('encrypt'))

    return render_template("encrypt.html")


@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "POST":
        if 'file' not in request.files:
            flash("No file uploaded.")
            return redirect(url_for('decrypt'))

        file = request.files['file']
        if file.filename == '':
            flash("No file selected.")
            return redirect(url_for('decrypt'))

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Decrypt the file
        decrypted_file_path = decrypt_file(file_path)
        if decrypted_file_path:
            return redirect(url_for('download', filename=os.path.basename(decrypted_file_path)))
        else:
            flash("Decryption failed. Please check the logs.")
            return redirect(url_for('decrypt'))

    return render_template("decrypt.html")


@app.route("/download/<filename>")
def download(filename):
    return render_template("download.html", filename=filename)


@app.route("/download_file/<filename>")
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)


if __name__ == "__main__":
    # Generate and save RSA keys if they don't exist
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        print("Generating new RSA keys...")
        private_key, public_key = generate_rsa_keys()
        save_keys(private_key, public_key)
        print("RSA keys generated and saved.")

    # Run the Flask app
    app.run(debug=True)