# Common cryptographic utilities for the SSL Key Repository application

import os
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import hashlib
import hmac


def generate_key_pair(key_size=2048):
    """Generate a new RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Generate public key from private key
    public_key = private_key.public_key()
    
    return private_key, public_key


def save_keys(private_key, public_key, private_key_path, public_key_path):
    """Save keys to files"""
    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)
    
    # Set secure permissions for private key
    os.chmod(private_key_path, 0o600)
    
    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)

    # Public keys are never sensitive - make sure this is readable regardless
    # of umask, rather than leaving it whatever the containing directory's
    # default happens to produce (relevant since generate_db_keypair()'s
    # directory may only be group-, not world-, readable now).
    os.chmod(public_key_path, 0o644)


def load_private_key(private_key_path):
    """Load private key from file"""
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def load_private_key_from_string(private_key_string):
    """Load private key from PEM string"""
    private_key_bytes = private_key_string.encode('utf-8')
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    return private_key


def load_public_key_from_string(public_key_string):
    """Load public key from PEM string"""
    public_key_bytes = public_key_string.encode('utf-8')
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    return public_key


def load_public_key(public_key_path):
    """Load public key from file"""
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key


def sign_message(message, private_key):
    """Sign a message with the private key"""
    try:
        # Handle both string and bytes input
        if isinstance(message, str):
            message_to_sign = message.encode('utf-8')
        else:
            message_to_sign = message
        
        # Sign the message using PSS padding with SHA-256
        signature = private_key.sign(
            message_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        print(f"Error signing message: {e}")
        return None


def verify_signature(message, signature, public_key):
    """Verify a signature using the public key"""
    try:
        # Handle both string and bytes input
        if isinstance(message, str):
            message_to_verify = message.encode('utf-8')
        else:
            message_to_verify = message
            
        # Verify the signature using PSS padding with SHA-256
        public_key.verify(
            signature,
            message_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Error verifying signature: {e}")
        return False


def get_public_key_fingerprint(public_key):
    """Calculate the SHA-256 fingerprint of a public key"""
    try:
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(public_key_der).hexdigest()
        return fingerprint
    except Exception as e:
        print(f"Error calculating public key fingerprint: {e}")
        return None


def compute_registration_proof(registration_secret, client_id, public_key_pem, nonce, timestamp):
    """Compute an HMAC-SHA256 proof that the caller knows the shared registration
    secret, binding the proof to this specific client_id/public_key/nonce/timestamp
    so it cannot be replayed or reused for a different identity."""
    message = "|".join([client_id, public_key_pem, str(nonce), str(timestamp)]).encode('utf-8')
    return hmac.new(registration_secret.encode('utf-8'), message, hashlib.sha256).hexdigest()


def verify_registration_proof(registration_secret, client_id, public_key_pem, nonce, timestamp, proof):
    """Verify a registration proof using a constant-time comparison"""
    if not proof:
        return False
    expected = compute_registration_proof(registration_secret, client_id, public_key_pem, nonce, timestamp)
    return hmac.compare_digest(expected, proof)


def encrypt_data(data, public_key):
    """Encrypt data with the public key"""
    try:
        # Handle both string and bytes input
        if isinstance(data, str):
            data_to_encrypt = data.encode('utf-8')
        else:
            data_to_encrypt = data

        symmetric_key = Fernet.generate_key()
        ciper_aes = Fernet(symmetric_key)
        encrypted_data_aes = ciper_aes.encrypt(data_to_encrypt)

        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_data = encrypted_key + encrypted_data_aes
        return encrypted_data
    except Exception as e:
        print(f"Error encrypting data: {e}")
        return None


def decrypt_data(encrypted_data, private_key):
    """Decrypt data with the private key"""
    try:
        encrypted_key = encrypted_data[:256]  # RSA encrypted symmetric key (256 bytes for 2048-bit key)
        encrypted_data_aes = encrypted_data[256:]  # AES encrypted data

        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cipher_aes = Fernet(decrypted_key)
        decrypted_data = cipher_aes.decrypt(encrypted_data_aes)
        # Return binary data, not decoded string
        return decrypted_data
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None