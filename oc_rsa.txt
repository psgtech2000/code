# client.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_message(plaintext, public_key):
    """
    Encrypts plaintext using the RSA public key with OAEP padding.
    """
    plaintext_bytes = plaintext.encode('utf-8')
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext_bytes)

# === Main Client Logic ===
def start_client():
    host, port = '127.0.0.1', 9998  

    print("--- RSA Client-Server Demonstration (Client Side) ---")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # 1. Connect to server
        print(f"Connecting to server at {host}:{port}...")
        client_socket.connect((host, port))
        print("Connection successful.")

        # 2. Receive server's public key
        public_key_pem = client_socket.recv(4096)
        public_key = RSA.import_key(public_key_pem)
        print("Received server's public key.")

        # 3. Define plaintext
        plaintext = input("Enter message: ")
        print(f"Original Plaintext: {plaintext}")

        # 4. Encrypt
        encrypted_message = encrypt_message(plaintext, public_key)
        print(f"\nEncrypted (hex): {encrypted_message.hex()}")

        # 5. Send encrypted message
        client_socket.send(encrypted_message)
        print("Encrypted message sent.")

    finally:
        print("\nClosing the client socket.")
        client_socket.close()

if __name__ == "__main__":
    start_client()
