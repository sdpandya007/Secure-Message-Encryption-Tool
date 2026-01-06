# 🔐 Secure Message Encryption Tool

A simple and user-friendly **Streamlit web application** to encrypt, decrypt, and hash messages using secure cryptographic techniques.  
This project is designed for **educational and personal use**, focusing on basic concepts of cybersecurity.

---

## 🚀 Features

- 🔒 **Fernet (AES) Encryption**
  - Password-based symmetric encryption
  - Uses PBKDF2 with SHA-256 for key derivation

- 🔓 **Fernet Decryption**
  - Decrypt encrypted messages using the same password

- 🔁 **Base64 Encoding & Decoding**
  - Converts messages to/from Base64 format (not secure encryption)

- 🧾 **SHA-256 Hashing**
  - One-way hashing for data integrity verification

- 🎨 **Attractive UI**
  - Custom CSS styling
  - Sidebar navigation
  - Responsive layout

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
▶️ How to Run the Application
Clone the repository or download the source code

Open terminal in the project directory

Run the Streamlit app:

bash
Copy code
streamlit run app.py
The app will open automatically in your browser 🌐

📘 How to Use
🔒 Encrypt Message
Select Encrypt Message from sidebar

Choose encryption method:

Fernet (AES)

Base64 Encoding

SHA-256 Hash

Enter your message

Enter password (for Fernet only)

Click Encrypt Message

🔓 Decrypt Message
Select Decrypt Message from sidebar

Choose decryption method:

Fernet (AES)

Base64 Decoding

Paste encrypted message

Enter the same password (for Fernet)

Click Decrypt Message

⚠️ Important Notes
🔐 Fernet encryption is symmetric – same password is required for encryption and decryption

❌ SHA-256 hashes cannot be decrypted

⚠️ Base64 is not encryption, only encoding

🔑 Passwords are never stored

🔒 Keep your password safe; data cannot be recovered without it

🔐 Security Best Practices
Use strong and unique passwords

Do not share encryption passwords

Avoid using Base64 for sensitive data

For critical systems, use advanced security mechanisms

📌 Use Cases
Cyber Security mini-project

Cryptography demonstration

Educational encryption tool

Message privacy practice

👨‍💻 Author
Shreyans Pandya
Cyber Security & Computer Science Student

📄 License
This project is for educational purposes only.
Free to use and modify for learning.

🔐 Secure your messages. Protect your data.

yaml
Copy code

---

If you want, I can also:
- Customize it for **GTU / college project format**
- Add **screenshots section**
- Make a **project report (PDF/Word)**
- Optimize wording for **GitHub stars ⭐**

Just say the word 😄