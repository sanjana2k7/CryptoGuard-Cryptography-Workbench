from flask import Flask, render_template, request, jsonify, send_file
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
import hashlib, base64, io, os, secrets

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB upload limit


def b64e(data): return base64.b64encode(data).decode('ascii')
def b64d(data): return base64.b64decode(data, validate=True)

def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError('Enter a password first.')
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000).derive(password.encode('utf-8'))

@app.get('/')
def index():
    return render_template('index.html')

@app.post('/api/aes/encrypt')
def aes_encrypt():
    data = request.get_json(silent=True) or {}
    try:
        salt, nonce = os.urandom(16), os.urandom(12)
        key = derive_key(data.get('password', ''), salt)
        ciphertext = AESGCM(key).encrypt(nonce, data.get('text', '').encode('utf-8'), None)
        return jsonify(result='CG1:' + b64e(salt + nonce + ciphertext), note='AES-256-GCM authenticated ciphertext')
    except Exception as e: return jsonify(error=str(e)), 400

@app.post('/api/aes/decrypt')
def aes_decrypt():
    data = request.get_json(silent=True) or {}
    try:
        raw = data.get('text', '')
        if not raw.startswith('CG1:'): raise ValueError('This is not a CryptoGuard AES payload (CG1:).')
        packed = b64d(raw[4:])
        if len(packed) < 44: raise ValueError('Ciphertext is incomplete.')
        key = derive_key(data.get('password', ''), packed[:16])
        plain = AESGCM(key).decrypt(packed[16:28], packed[28:], None)
        return jsonify(result=plain.decode('utf-8'), note='Decrypted and authentication verified')
    except (InvalidTag, ValueError) as e: return jsonify(error='Decryption failed. Check the password and ciphertext. ' + str(e)), 400
    except Exception as e: return jsonify(error=str(e)), 400

@app.post('/api/rsa/generate')
def rsa_generate():
    try:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        pub = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return jsonify(private_key=priv, public_key=pub)
    except Exception as e: return jsonify(error=str(e)), 400

@app.post('/api/rsa/encrypt')
def rsa_encrypt():
    data = request.get_json(silent=True) or {}
    try:
        pub = serialization.load_pem_public_key(data.get('key', '').encode())
        encrypted = pub.encrypt(data.get('text', '').encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return jsonify(result=b64e(encrypted), note='RSA-2048 OAEP with SHA-256')
    except Exception as e: return jsonify(error='RSA encryption failed. Check the public key and keep the message short. ' + str(e)), 400

@app.post('/api/rsa/decrypt')
def rsa_decrypt():
    data = request.get_json(silent=True) or {}
    try:
        priv = serialization.load_pem_private_key(data.get('key', '').encode(), password=None)
        plain = priv.decrypt(b64d(data.get('text', '')), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return jsonify(result=plain.decode(), note='RSA decryption successful')
    except Exception as e: return jsonify(error='RSA decryption failed. Check the private key and ciphertext. ' + str(e)), 400

@app.post('/api/hash')
def hash_text():
    data = request.get_json(silent=True) or {}
    raw = data.get('text', '').encode('utf-8')
    return jsonify(result=hashlib.sha256(raw).hexdigest(), bytes=len(raw), algorithm='SHA-256')

@app.post('/api/caesar')
def caesar():
    data = request.get_json(silent=True) or {}
    try: shift = int(data.get('shift', 3)) % 26
    except (TypeError, ValueError): return jsonify(error='Shift must be a whole number.'), 400
    text = data.get('text', '')
    mode = data.get('mode', 'encrypt')
    if mode == 'decrypt': shift = -shift
    out = ''.join(chr((ord(c)-base+shift)%26+base) if c.isalpha() and c.isascii() else c for c in text for base in ([65] if c.isupper() else [97]) )
    return jsonify(result=out, note='Classical demonstration cipher — not secure for real data')

@app.post('/api/file/encrypt')
def file_encrypt():
    upload = request.files.get('file'); password = request.form.get('password', '')
    if not upload or not upload.filename: return jsonify(error='Choose a file to encrypt.'), 400
    try:
        salt, nonce = os.urandom(16), os.urandom(12)
        key = derive_key(password, salt)
        encrypted = b'CGFILE1' + salt + nonce + AESGCM(key).encrypt(nonce, upload.read(), None)
        name = os.path.basename(upload.filename) + '.cg'
        return send_file(io.BytesIO(encrypted), as_attachment=True, download_name=name, mimetype='application/octet-stream')
    except Exception as e: return jsonify(error=str(e)), 400

@app.post('/api/file/decrypt')
def file_decrypt():
    upload = request.files.get('file'); password = request.form.get('password', '')
    if not upload or not upload.filename: return jsonify(error='Choose a .cg file to decrypt.'), 400
    try:
        packed = upload.read()
        if not packed.startswith(b'CGFILE1') or len(packed) < 51: raise ValueError('Not a valid CryptoGuard encrypted file.')
        salt, nonce, ciphertext = packed[7:23], packed[23:35], packed[35:]
        key = derive_key(password, salt)
        # Filename is stored as authenticated data during encryption; use a safe default after decrypt.
        plain = AESGCM(key).decrypt(nonce, ciphertext, None)
        original = upload.filename[:-3] if upload.filename.lower().endswith('.cg') else 'decrypted_file'
        return send_file(io.BytesIO(plain), as_attachment=True, download_name=os.path.basename(original), mimetype='application/octet-stream')
    except Exception as e: return jsonify(error='File decryption failed. Check password/file. ' + str(e)), 400

@app.errorhandler(413)
def too_large(_): return jsonify(error='File exceeds the 25 MB upload limit.'), 413

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
