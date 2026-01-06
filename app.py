import streamlit as st
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Page configuration
st.set_page_config(
    page_title="Message Encryption App",
    page_icon="🔐",
    layout="wide"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 1.5rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #3B82F6;
        margin-top: 1.5rem;
        margin-bottom: 0.5rem;
    }
    .info-box {
        background-color: #F0F9FF;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #3B82F6;
        margin-bottom: 1.5rem;
    }
    .success-box {
        background-color: #D1FAE5;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #10B981;
        margin-bottom: 1.5rem;
    }
    .warning-box {
        background-color: #FEF3C7;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #F59E0B;
        margin-bottom: 1.5rem;
    }
    .stButton button {
        width: 100%;
        background-color: #3B82F6;
        color: white;
        font-weight: bold;
    }
    .stButton button:hover {
        background-color: #2563EB;
        color: white;
    }
    .footer {
        text-align: center;
        margin-top: 3rem;
        color: #6B7280;
        font-size: 0.8rem;
    }
</style>
""", unsafe_allow_html=True)

# App header
st.markdown('<h1 class="main-header">🔐 Secure Message Encryption Tool</h1>', unsafe_allow_html=True)
st.markdown("Encrypt and decrypt messages using secure algorithms. Keep your sensitive information safe!")

# Sidebar for navigation
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/3067/3067256.png", width=100)
    st.markdown("### Navigation")
    app_mode = st.radio(
        "Choose mode:",
        ["Encrypt Message", "Decrypt Message", "About"]
    )
    
    st.markdown("---")
    st.markdown("### 🔒 Encryption Methods")
    st.markdown("""
    - **Fernet (AES)**: Symmetric encryption using a password
    - **Base64**: Encoding (not true encryption)
    - **SHA-256**: Hashing (one-way, cannot be decrypted)
    """)
    
    st.markdown("---")
    st.markdown("### ℹ️ Instructions")
    st.markdown("""
    1. Select your mode (Encrypt/Decrypt)
    2. Choose encryption method
    3. Enter your message
    4. Enter password (if required)
    5. Click the action button
    """)

# Function to generate key from password
def generate_key(password, salt=b'salt_'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to encrypt with Fernet
def encrypt_fernet(message, password):
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message.decode()

# Function to decrypt with Fernet
def decrypt_fernet(encrypted_message, password):
    try:
        key = generate_key(password)
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message.encode())
        return decrypted_message.decode()
    except Exception:
        return None

# Function for Base64 encoding
def encode_base64(message):
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes.decode('ascii')

# Function for Base64 decoding
def decode_base64(encoded_message):
    try:
        base64_bytes = encoded_message.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes.decode('ascii')
    except Exception:
        return None

# Function for SHA-256 hashing
def hash_sha256(message):
    hash_object = hashlib.sha256(message.encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig

# Main app logic
if app_mode == "Encrypt Message":
    st.markdown('<h2 class="sub-header">🔒 Encrypt a Message</h2>', unsafe_allow_html=True)
    
    # Method selection
    encryption_method = st.selectbox(
        "Select encryption method:",
        ["Fernet (AES) - Recommended", "Base64 Encoding", "SHA-256 Hash"]
    )
    
    # Message input
    message = st.text_area("Enter your message to encrypt:", height=150, 
                          placeholder="Type your secret message here...")
    
    # Password input (if needed)
    password = ""
    if encryption_method.startswith("Fernet"):
        password = st.text_input("Enter a password for encryption:", type="password")
        st.markdown('<div class="info-box">For Fernet encryption, remember your password! You\'ll need it to decrypt the message.</div>', unsafe_allow_html=True)
    
    # Encrypt button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        encrypt_button = st.button("🚀 Encrypt Message")
    
    # Encryption logic
    if encrypt_button and message:
        if encryption_method.startswith("Fernet") and not password:
            st.markdown('<div class="warning-box">⚠️ Please enter a password for Fernet encryption.</div>', unsafe_allow_html=True)
        else:
            with st.spinner("Encrypting your message..."):
                try:
                    if encryption_method.startswith("Fernet"):
                        encrypted = encrypt_fernet(message, password)
                        method_used = "Fernet (AES) Encryption"
                    elif encryption_method == "Base64 Encoding":
                        encrypted = encode_base64(message)
                        method_used = "Base64 Encoding"
                    elif encryption_method == "SHA-256 Hash":
                        encrypted = hash_sha256(message)
                        method_used = "SHA-256 Hash"
                    
                    st.markdown('<div class="success-box">✅ Message encrypted successfully!</div>', unsafe_allow_html=True)
                    
                    # Display results
                    st.markdown("### 📋 Encryption Results")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Encryption Method:**")
                        st.info(method_used)
                        
                        if encryption_method.startswith("Fernet"):
                            st.markdown("**Password Used:**")
                            st.warning(password if password else "None")
                    
                    with col2:
                        st.markdown("**Encrypted Output:**")
                        st.code(encrypted, language="text")
                    
                    # Copy to clipboard functionality
                    st.markdown("### 📋 Copy Encrypted Message")
                    st.code(encrypted, language="text")
                    
                except Exception as e:
                    st.error(f"Error during encryption: {str(e)}")
    elif encrypt_button and not message:
        st.warning("Please enter a message to encrypt.")

elif app_mode == "Decrypt Message":
    st.markdown('<h2 class="sub-header">🔓 Decrypt a Message</h2>', unsafe_allow_html=True)
    
    # Method selection
    decryption_method = st.selectbox(
        "Select decryption method:",
        ["Fernet (AES)", "Base64 Decoding"]
    )
    
    # Encrypted message input
    encrypted_message = st.text_area("Enter encrypted message to decrypt:", height=150,
                                    placeholder="Paste your encrypted message here...")
    
    # Password input (if needed)
    password = ""
    if decryption_method == "Fernet (AES)":
        password = st.text_input("Enter the password for decryption:", type="password")
        st.markdown('<div class="info-box">Make sure to use the same password that was used for encryption.</div>', unsafe_allow_html=True)
    
    # Decrypt button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        decrypt_button = st.button("🔓 Decrypt Message")
    
    # Decryption logic
    if decrypt_button and encrypted_message:
        if decryption_method == "Fernet (AES)" and not password:
            st.markdown('<div class="warning-box">⚠️ Please enter the password for decryption.</div>', unsafe_allow_html=True)
        else:
            with st.spinner("Decrypting your message..."):
                try:
                    if decryption_method == "Fernet (AES)":
                        decrypted = decrypt_fernet(encrypted_message, password)
                        if decrypted is None:
                            st.error("Decryption failed! Please check your password and ensure the encrypted message is valid.")
                        else:
                            st.markdown('<div class="success-box">✅ Message decrypted successfully!</div>', unsafe_allow_html=True)
                            
                            # Display results
                            st.markdown("### 📋 Decryption Results")
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown("**Decryption Method:**")
                                st.info("Fernet (AES) Decryption")
                            
                            with col2:
                                st.markdown("**Decrypted Message:**")
                                st.success(decrypted)
                    
                    elif decryption_method == "Base64 Decoding":
                        decrypted = decode_base64(encrypted_message)
                        if decrypted is None:
                            st.error("Decoding failed! Please ensure the encoded message is valid Base64.")
                        else:
                            st.markdown('<div class="success-box">✅ Message decoded successfully!</div>', unsafe_allow_html=True)
                            
                            # Display results
                            st.markdown("### 📋 Decoding Results")
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown("**Decoding Method:**")
                                st.info("Base64 Decoding")
                            
                            with col2:
                                st.markdown("**Decoded Message:**")
                                st.success(decrypted)
                
                except Exception as e:
                    st.error(f"Error during decryption: {str(e)}")
    elif decrypt_button and not encrypted_message:
        st.warning("Please enter an encrypted message to decrypt.")

else:  # About page
    st.markdown('<h2 class="sub-header">ℹ️ About This Application</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔒 Security Features")
        st.markdown("""
        - **Fernet Encryption**: Uses AES-128 in CBC mode with PKCS7 padding
        - **Password-based Key Derivation**: Uses PBKDF2 with SHA256 and 100,000 iterations
        - **Base64 Encoding**: Converts binary data to ASCII text format
        - **SHA-256 Hashing**: Creates a unique fingerprint of your message
        """)
        
        st.markdown("### 📝 How to Use")
        st.markdown("""
        1. **Encryption**:
           - Choose encryption method
           - Enter your message
           - Set a password (for Fernet)
           - Copy the encrypted output
        
        2. **Decryption**:
           - Choose the matching decryption method
           - Paste the encrypted message
           - Enter the same password (for Fernet)
           - View your original message
        """)
    
    with col2:
        st.markdown("### ⚠️ Important Notes")
        st.markdown("""
        - **Fernet encryption is symmetric**: You need the same password to encrypt and decrypt
        - **SHA-256 is a hash function**: It's one-way only (cannot be decrypted)
        - **Base64 is encoding, not encryption**: It doesn't provide security, just converts format
        - **Passwords are not stored**: They're only used to generate encryption keys
        - **Keep your passwords safe**: Without them, encrypted data cannot be recovered
        """)
        
        st.markdown("### 🔐 Security Best Practices")
        st.markdown("""
        - Use strong, unique passwords for encryption
        - Never share your encryption passwords
        - For highly sensitive data, consider additional security measures
        - This tool is for educational and personal use
        """)
    
    st.markdown("---")
    st.markdown("### 🛠️ Technical Details")
    st.markdown("""
    This application is built with:
    - **Streamlit**: For the web interface
    - **Cryptography**: For Fernet encryption implementation
    - **Python Standard Library**: For Base64 and hashing functions
    
    All encryption happens locally in your browser. No data is sent to external servers.
    """)

# Footer
st.markdown("---")
st.markdown('<div class="footer">🔒 Secure Message Encryption Tool | Made with Streamlit | For educational purposes</div>', unsafe_allow_html=True)
