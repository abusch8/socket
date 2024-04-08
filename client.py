import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util import Counter

HOST = 'localhost'
PORT = 8080

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))

    cipher = client.recv(1024)

    print(len(cipher))

    rsa_key = RSA.importKey(open('private.pem').read())
    rsa = PKCS1_OAEP.new(rsa_key)

    aes_key = rsa.decrypt(cipher)

    nonce = client.recv(1024)

    ctr = Counter.new(64, prefix=nonce, initial_value=1)
    aes = AES.new(aes_key, AES.MODE_CTR, counter=ctr)

    while True:
        msg = input('>> ')

        cipher = aes.encrypt(msg.encode())

        client.sendall(cipher)
