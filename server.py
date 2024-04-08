import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

HOST = 'localhost'
PORT = 8080

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()

    print(f'Socket server started @ {HOST}:{PORT}')

    conn, peer_addr = server.accept()

    with conn:
        print(f'Connected by {peer_addr}')

        aes_key = get_random_bytes(16)

        rsa_key = RSA.importKey(open('public.pem').read())
        rsa = PKCS1_OAEP.new(rsa_key)

        cipher = rsa.encrypt(aes_key)
        conn.sendall(cipher)

        print(len(cipher))

        nonce = get_random_bytes(8)
        conn.sendall(nonce)

        ctr = Counter.new(64, prefix=nonce, initial_value=1)
        aes = AES.new(aes_key, AES.MODE_CTR, counter=ctr)

        while True:
            cipher = conn.recv(1024)

            if not cipher: break

            msg = aes.decrypt(cipher).decode()

            print(f'{peer_addr}: {msg}')
