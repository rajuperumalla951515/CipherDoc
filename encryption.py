import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')


def load_public_key(public_pem):
    return serialization.load_pem_public_key(
        public_pem.encode('utf-8'),
        backend=default_backend()
    )


def load_private_key(private_pem):
    return serialization.load_pem_private_key(
        private_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )


def generate_aes_key():
    return os.urandom(32)


def encrypt_with_aes_gcm(data, aes_key):
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_with_aes_gcm(encrypted_data, aes_key):
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_aes_key_with_rsa(aes_key, public_pem):
    public_key = load_public_key(public_pem)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8')


def decrypt_aes_key_with_rsa(encrypted_aes_key_b64, private_pem):
    private_key = load_private_key(private_pem)
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def encrypt_file(file_path, public_pem):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    aes_key = generate_aes_key()
    encrypted_data = encrypt_with_aes_gcm(file_data, aes_key)
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_pem)
    
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    
    return encrypted_file_path, encrypted_aes_key


def decrypt_file(encrypted_file_path, encrypted_aes_key, private_pem):
    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_pem)
    
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = decrypt_with_aes_gcm(encrypted_data, aes_key)
    
    decrypted_file_path = encrypted_file_path.replace('.encrypted', '.decrypted')
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    
    return decrypted_file_path, decrypted_data


def encrypt_text(text, public_pem):
    aes_key = generate_aes_key()
    encrypted_data = encrypt_with_aes_gcm(text.encode('utf-8'), aes_key)
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_pem)
    
    return base64.b64encode(encrypted_data).decode('utf-8'), encrypted_aes_key


def decrypt_text(encrypted_text_b64, encrypted_aes_key, private_pem):
    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_pem)
    encrypted_data = base64.b64decode(encrypted_text_b64)
    decrypted_data = decrypt_with_aes_gcm(encrypted_data, aes_key)
    
    return decrypted_data.decode('utf-8')
