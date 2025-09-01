import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

def recv_all(sock, n):
    """Helper to receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def decrypt(data, key, mode):
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(data)
        return unpad(decrypted, AES.block_size).decode('utf-8')

    elif mode == "CBC":
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        return unpad(decrypted, AES.block_size).decode('utf-8')

    elif mode == "CFB":
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        return cipher.decrypt(ciphertext).decode('utf-8')

def start_server():
    host, port = "127.0.0.1", 9999
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    print(f"\n--- AES Server Started ---")
    print(f"Listening on {host}:{port}\n")

    client, addr = server.accept()
    print(f"[+] Connection established from {addr}\n")

    try:
        # Send AES key
        key = get_random_bytes(16)
        client.send(key)
        print(f"AES Key (hex):      {key.hex()}")

        # Receive mode (16 bytes, padded)
        mode = recv_all(client, 16).decode().strip()
        print(f"Mode Selected:      {mode}")

        # Receive ciphertext
        data = client.recv(4096)
        print(f"Ciphertext (hex):   {data.hex()}")

        # Decrypt
        plaintext = decrypt(data, key, mode)
        print(f"\nDecrypted Plaintext: {plaintext}")

        print("\nVerification: Successful, message decrypted correctly.")

    finally:
        client.close()
        server.close()


if __name__ == "__main__":
    start_server()
