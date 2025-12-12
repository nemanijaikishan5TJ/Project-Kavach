import os
import io
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
CORS(app)  # This enables the browser to talk to this python script

# ==========================================
#  LAYER 1: AES-256 ENCRYPTION LOGIC
# ==========================================

def get_key_from_password(password, salt):
    """Derives a 32-byte (256-bit) key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_message_logic(plain_text, password):
    """Encrypts text using AES-256-CBC."""
    salt = os.urandom(16)
    key = get_key_from_password(password, salt)
    iv = os.urandom(16)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return Salt + IV + Ciphertext
    return salt + iv + ciphertext

def decrypt_message_logic(encrypted_data, password):
    """Decrypts AES-256-CBC data."""
    try:
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        key = get_key_from_password(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plain_text = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plain_text = unpadder.update(padded_plain_text) + unpadder.finalize()
        return plain_text.decode()
    except Exception as e:
        raise ValueError("Invalid Password or Corrupted Data")

# ==========================================
#  LAYER 2: STEGANOGRAPHY LOGIC (LSB)
# ==========================================

def bits_from_bytes(data_bytes):
    bits = []
    for byte in data_bytes:
        bits.extend([int(b) for b in f'{byte:08b}'])
    return bits

def bytes_from_bits(bits):
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte_chunk = bits[i:i+8]
        if len(byte_chunk) < 8: break
        byte_val = int(''.join(map(str, byte_chunk)), 2)
        byte_array.append(byte_val)
    return bytes(byte_array)

def embed_data_logic(image_file, secret_data):
    # Load image strictly from memory
    img = Image.open(image_file)
    img = img.convert("RGB")
    pixels = img.load()
    width, height = img.size
    
    # Create header (4 bytes for length) + data
    data_length = len(secret_data)
    full_data = data_length.to_bytes(4, byteorder='big') + secret_data
    
    data_bits = bits_from_bytes(full_data)
    total_pixels = width * height
    
    if len(data_bits) > total_pixels * 3:
        raise ValueError("Image too small to hold data.")
    
    data_idx = 0
    for y in range(height):
        for x in range(width):
            if data_idx >= len(data_bits): break
            
            r, g, b = pixels[x, y]
            
            if data_idx < len(data_bits):
                r = (r & ~1) | data_bits[data_idx]
                data_idx += 1
            if data_idx < len(data_bits):
                g = (g & ~1) | data_bits[data_idx]
                data_idx += 1
            if data_idx < len(data_bits):
                b = (b & ~1) | data_bits[data_idx]
                data_idx += 1
                
            pixels[x, y] = (r, g, b)
        if data_idx >= len(data_bits): break
    
    # Save to memory buffer
    output = io.BytesIO()
    img.save(output, format="PNG")
    output.seek(0)
    return output

def extract_data_logic(image_file):
    img = Image.open(image_file)
    img = img.convert("RGB")
    pixels = img.load()
    width, height = img.size
    
    extracted_bits = []
    header_bits_needed = 32
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            extracted_bits.append(r & 1)
            extracted_bits.append(g & 1)
            extracted_bits.append(b & 1)
            
            # Optimization: Check if we have enough bits for the header
            if len(extracted_bits) > header_bits_needed:
                header_bytes = bytes_from_bits(extracted_bits[:32])
                msg_length = int.from_bytes(header_bytes, byteorder='big')
                total_bits_needed = 32 + (msg_length * 8)
                
                # If we have enough bits for the whole message, stop
                if len(extracted_bits) >= total_bits_needed:
                    all_bytes = bytes_from_bits(extracted_bits[:total_bits_needed])
                    return all_bytes[4:] # Return data excluding header
    return None

# ==========================================
#  WEB ROUTES (API)
# ==========================================

@app.route('/encode', methods=['POST'])
def encode_route():
    try:
        msg = request.form.get('message')
        pwd = request.form.get('password')
        image_file = request.files.get('image')

        if not msg or not pwd or not image_file:
            return jsonify({"error": "Missing fields"}), 400

        # Layer 1: Encrypt
        encrypted_bytes = encrypt_message_logic(msg, pwd)

        # Layer 2: Embed
        output_image_io = embed_data_logic(image_file, encrypted_bytes)

        return send_file(output_image_io, mimetype='image/png', as_attachment=False, download_name='kavach_result.png')

    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

@app.route('/decode', methods=['POST'])
def decode_route():
    try:
        pwd = request.form.get('password')
        image_file = request.files.get('image')

        if not pwd or not image_file:
            return jsonify({"error": "Missing password or image"}), 400

        # Layer 2: Extract
        encrypted_bytes = extract_data_logic(image_file)
        
        if not encrypted_bytes:
            return jsonify({"error": "No hidden message found"}), 400

        # Layer 1: Decrypt
        decrypted_text = decrypt_message_logic(encrypted_bytes, pwd)

        return jsonify({"secret_message": decrypted_text})

    except Exception as e:
        print(e)
        return jsonify({"error": "Decryption failed. Check password."}), 500

@app.route('/')
def serve_index():
    return app.send_static_file('index.html')

# Add static file serving
@app.route('/<path:path>')
def serve_static(path):
    return app.send_static_file(path)

if __name__ == '__main__':
    import os
    # Set the static folder to the current directory
    app.static_folder = os.path.abspath(os.path.dirname(__file__))
    print("-------------------------------------------------")
    print(" PROJECT KAVACH: BACKEND SERVER RUNNING")
    print(" Open in browser: http://127.0.0.1:5000")
    print("-------------------------------------------------")
    app.run(debug=True, port=5000)