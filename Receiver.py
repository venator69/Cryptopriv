import socket
import json
import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# RSA KEY FUNCTIONS
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


# AES DECRYPT
def aes_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes):
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


# RSA DECRYPT AES KEY
def rsa_decrypt_key(private_key, encrypted_key: bytes):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# Verify Signature
def verify_signature(public_key, data: bytes, signature: bytes):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


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


# Server
HOST = "0.0.0.0"
PORT = 5000


print("RECEIVER")

# Receiver key pair
receiver_private, receiver_public = generate_rsa_keys()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print(f"Receiver listening on {HOST}:{PORT}")
print("Menunggu transmitter connect...")

conn, addr = server.accept()
print(f"Connected by {addr}")

#Kirim public key receiver ke transmitter
receiver_public_pem = public_key_to_pem(receiver_public)
send_json(conn, {
    "type": "receiver_public_key",
    "public_key": receiver_public_pem
})
print("Receiver public key sent")

# Terima sender public key + encrypted payload
packet = recv_json(conn)

sender_public_pem = packet["sender_public_key"]
encrypted_aes_key = base64.b64decode(packet["encrypted_aes_key"])
nonce = base64.b64decode(packet["nonce"])
ciphertext = base64.b64decode(packet["ciphertext"])
signature = base64.b64decode(packet["signature"])
original_hash = packet["hash"]

sender_public = load_public_key_from_pem(sender_public_pem)

print("\nData Diterima")
print("Encrypted AES Key:", packet["encrypted_aes_key"][:60] + "...")
print("Nonce:", packet["nonce"])
print("Ciphertext:", packet["ciphertext"][:60] + "...")
print("Signature:", packet["signature"][:60] + "...")
print("Hash Asli:", original_hash)

# Verifikasi signature
print("\nVerif signature")
valid = verify_signature(sender_public, ciphertext, signature)
print("Status Signature:", "VALID" if valid else "TIDAK VALID")

if not valid:
    print("[!] Pesan ditolak karena signature tidak valid.")
    conn.close()
    server.close()

# Decrypt AES key
print("\nDECRYPT AES KEY")
aes_key = rsa_decrypt_key(receiver_private, encrypted_aes_key)
print("[+] AES key berhasil didekripsi")

# Decrypt pesan
print("\nDECRYPT PESAN")
plaintext = aes_decrypt(aes_key, nonce, ciphertext)
print("Pesan hasil dekripsi:", plaintext.decode())

# STEP 6: Integrity check
print("\nINTEGRITY CHECK")
decrypted_hash = sha256_hash(plaintext)
print("Hash setelah dekripsi:", decrypted_hash)
print("Integrity:", "SAMA" if decrypted_hash == original_hash else "BERUBAH")

conn.close()
server.close()
print("\nReceiver selesai.")

