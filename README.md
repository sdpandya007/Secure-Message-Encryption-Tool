# 🔐 Secure Message Encryption Tool

A simple and interactive **Streamlit-based web application** to encrypt, decrypt, and hash messages using secure cryptographic techniques.  
This project demonstrates core **Cyber Security and Cryptography concepts** in an easy-to-use interface.

---

## 🌐 Live Demo

Try out the live demo of the **Secure Message Encryption Tool** by visiting the link below:

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Click%20Here-brightgreen)](https://secure-message-encryption-tool-i8b2wmzxqrzbjnykgx7skt.streamlit.app/)

This demo provides a fully functional version of the application hosted online.  
You can use it directly in your browser without installing anything locally.

---

## 🚀 Features

- 🔒 **Fernet (AES) Encryption**
  - Password-based symmetric encryption
  - Secure key derivation using PBKDF2 with SHA-256

- 🔓 **Fernet Decryption**
  - Decrypt messages using the same password

- 🔁 **Base64 Encoding & Decoding**
  - Converts messages into Base64 format (not secure encryption)

- 🧾 **SHA-256 Hashing**
  - One-way hashing for data integrity verification

- 🎨 **Modern UI**
  - Custom CSS styling
  - Sidebar navigation
  - Responsive Streamlit layout

---

## 🛠️ Technologies Used

- **Python**
- **Streamlit** – Web application framework
- **Cryptography** – Fernet (AES) encryption
- **Hashlib** – SHA-256 hashing
- **Base64** – Encoding and decoding

---

## 📦 Requirements

Create a `requirements.txt` file with the following content:

```txt
streamlit
cryptography
Install dependencies using:

bash
Copy code
pip install -r requirements.txt
▶️ How to Run the Application Locally
Clone the repository or download the source code

Open a terminal in the project directory

Run the application using:

bash
Copy code
streamlit run app.py
The app will open automatically in your web browser 🌐

📘 How to Use
🔒 Encrypt a Message
Select Encrypt Message from the sidebar

Choose an encryption method:

Fernet (AES)

Base64 Encoding

SHA-256 Hash

Enter your message

Enter a password (required for Fernet)

Click Encrypt Message

🔓 Decrypt a Message
Select Decrypt Message from the sidebar

Choose a decryption method:

Fernet (AES)

Base64 Decoding

Paste the encrypted message

Enter the same password used for encryption

Click Decrypt Message

⚠️ Important Notes
🔐 Fernet encryption is symmetric — the same password is required for encryption and decryption

❌ SHA-256 hashing is one-way and cannot be decrypted

⚠️ Base64 is not encryption, only encoding

🔑 Passwords are not stored anywhere

🔒 Losing the password means losing access to encrypted data

🔐 Security Best Practices
Use strong and unique passwords

Never share your encryption password

Avoid Base64 for sensitive information

Use professional security tools for real-world applications

📌 Use Cases
Cyber Security mini-project

Cryptography practical demonstration

Educational encryption tool

Secure message handling practice

👨‍💻 Author
Shreyans Pandya
Cyber Security & Computer Science Student

📄 License
This project is developed for educational purposes.
Free to use and modify for learning and academic projects.

🔐 Secure your messages. Protect your data.

yaml
Copy code

---

If you want next:
- 📄 **Project Report (GTU format)**
- 📸 **Screenshots section**
- ⭐ **GitHub badges**
- 🚀 **Deployment guide explanation**

Just say it 😄
