import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def encrypt(msg, key, mode):
    data = msg.encode('utf-8')
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        padded_bytes = pad(data, AES.block_size)
        return cipher.encrypt(padded_bytes)

    elif mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC)
        padded_bytes = pad(data, AES.block_size)
        return cipher.iv + cipher.encrypt(padded_bytes)

    elif mode == "CFB":
        cipher = AES.new(key, AES.MODE_CFB)
        return cipher.iv + cipher.encrypt(data)

def start_client():
    host, port = "127.0.0.1", 9999
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print(f"\n--- AES Client Started ---")
    print(f"Connected to server at {host}:{port}\n")

    try:
        # Get key from server
        key = client.recv(1024)
        print(f"Received AES Key (hex): {key.hex()}")

        # User input
        msg = input("Enter message: ")
        mode = input("Mode (ECB, CBC, CFB): ").upper()

        # Encrypt
        ct = encrypt(msg, key, mode)

        # Send mode (16 bytes padded)
        client.send(mode.ljust(16).encode())

        # Send ciphertext
        client.send(ct)

        # Print neatly
        print(f"\n--- Encryption Details ---")
        print(f"Mode Selected:        {mode}")
        print(f"Original Plaintext:   {msg}")
        if mode != "ECB":
            iv = ct[:AES.block_size]
            print(f"IV (hex):             {iv.hex()}")
        print(f"Ciphertext (hex):     {ct.hex()}\n")

        print("Message sent successfully")

    finally:
        client.close()

if __name__ == "__main__":
    start_client()
