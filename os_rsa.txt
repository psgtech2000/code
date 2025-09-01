# server.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_message(ciphertext, private_key):
    try:
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_bytes = cipher.decrypt(ciphertext)
        return decrypted_bytes.decode('utf-8')
    except (ValueError, TypeError) as e:
        print(f"Decryption failed: {e}")
        return None

# === Main Server Logic ===
def start_server():
    host, port = '127.0.0.1', 9998

    print("--- RSA Client-Server Demonstration (Server Side) ---")

    # 1. Generate RSA key pair
    key_pair = RSA.generate(2048)
    public_key = key_pair.publickey()
    private_key = key_pair
    print(" Generated a new 2048-bit RSA key pair for the session.")
    print(f"Public Key (PEM):\n{public_key.export_key().decode()[:100]}...\n")
    print(f"Private Key (PEM):\n{private_key.export_key().decode()[:100]}...\n")

    # 2. Start server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f" Server listening on {host}:{port}")

    client_socket, addr = server_socket.accept()
    print(f" Accepted connection from {addr}")

    try:
        # Step A: Send public key to client
        client_socket.send(public_key.export_key())
        print("Public key sent to client.")

        # Step B: Receive encrypted message
        encrypted_message = client_socket.recv(4096)
        print(f"Received encrypted message (hex): {encrypted_message.hex()}")

        # Step C: Decrypt
        decrypted_text = decrypt_message(encrypted_message, private_key)

        print("\n--- Decryption Result ---")
        if decrypted_text:
            print(f"Decrypted Plaintext: {decrypted_text}")
            # (Optional) Verification check – if server also knows expected plaintext
        else:
            print("[!] Could not decrypt the message.")

    finally:
        print("\n Closing client and server sockets.")
        client_socket.close()
        server_socket.close()

if __name__ == "__main__":
    start_server()
