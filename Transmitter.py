import socket
import json
import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Security Stacks 
""" 
    Integrity           : sha256 HASH
    authentication      : RSA-PSS digital signature, transmitter public key
    Confidentiality     : AES-GCM symmetrical encryption for messages, RSA-OAEP for AES key
    Non-Repudiation     : RSA digital signature
"""
# Flow
"""
    Transmitter and receiver generate public and private key using RSA keys -> 
    -> Receiver's Public keys is sent to transmitter -> 
    -> Message is inputted in tranceiver -> 
    -> Message is symmetrically encrypted using AES creating nonce, ciphertext, and key ->
    -> key is asymmetrically encrypted using RSA OAEP, using RECEIVER's public key -> 
    -> digital signature is made using transmitters private keys
"""
# CONFIG
SERVER_IP = "100.99.107.98" # Ganti ke SERVER_IP dari VM
PORT = 5000

# Asymetric Encription  : RSA key Function
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def load_public_key_from_pem(pem_data: str):
    return serialization.load_pem_public_key(pem_data.encode())


# HASH
def sha256_hash(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


# AES Encrypt
def aes_encrypt(plaintext: bytes):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return aes_key, nonce, ciphertext

# RSA ENCRYPT AES KEY
def rsa_encrypt_key(public_key, aes_key: bytes):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# Digital Signature
def sign_data(private_key, data: bytes):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


# Socket Helpers
def send_json(conn, obj):
    data = json.dumps(obj).encode()
    conn.sendall(len(data).to_bytes(4, "big"))
    conn.sendall(data)


def recv_json(conn):
    length_data = conn.recv(4)
    if not length_data:
        return None
    length = int.from_bytes(length_data, "big")

    data = b""
    while len(data) < length:
        packet = conn.recv(4096)
        if not packet:
            break
        data += packet

    return json.loads(data.decode())


print("TRANSMITTER")

# Sender key pair
sender_private, sender_public = generate_rsa_keys()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER_IP, PORT))
print(f"Connected to server {SERVER_IP}:{PORT}")

# Terima receiver public key
packet = recv_json(client)
receiver_public_pem = packet["public_key"]
receiver_public = load_public_key_from_pem(receiver_public_pem)
print("Receiver public key diterima")

# Siapkan pesan -> ubah menjadi bytes
message = input("Masukkan pesan yang ingin dikirim: ").encode()
print("\nPesan asli:", message.decode())

# Hash
msg_hash = sha256_hash(message)
print("Hash pesan:", msg_hash)

# AES encrypt
aes_key, nonce, ciphertext = aes_encrypt(message)

# Encrypt AES_Key dengan RSA dengan receiver public key
encrypted_aes_key = rsa_encrypt_key(receiver_public, aes_key)

# Sign ciphertext
signature = sign_data(sender_private, ciphertext)

# Sender public key
sender_public_pem = public_key_to_pem(sender_public)

# Kirim semuanya ke receiver dengan json payload
payload = {
    "sender_public_key": sender_public_pem,
    "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
    "nonce": base64.b64encode(nonce).decode(),
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "signature": base64.b64encode(signature).decode(),
    "hash": msg_hash
}

send_json(client, payload)

print("\nData Terkirim !!")
print(payload)

client.close()
print("Transmitter selesai")