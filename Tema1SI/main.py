import os
import socket
from base64 import b64encode, b64decode
from binascii import unhexlify
from crypto.Cipher import AES
from crypto.Util.Padding import pad, unpad

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(("127.0.0.1", 4000))

serverSocket.listen()
a_connection = None
a_address = None
b_connection = None
b_address = None

initialization_vector = "7bde5a0f3f39fd658efc45de143cbc94"
k_prim = "3e83b13d99bf0de6c6bde5ac5ca4ae68"
random_key = os.urandom(16)
print(random_key)
initialization_vector = unhexlify(initialization_vector)
k_prim = unhexlify(k_prim)

while True:
    (clientConnected, clientAddress) = serverSocket.accept()

    if a_address is None:
        a_connection = clientConnected
        a_address = clientAddress
    else:
        b_connection = clientConnected
        b_address = clientAddress

    print("Accepted a connection request from %s:%s" % (clientAddress[0], clientAddress[1]))

    if b_address is None:
        dataFromClient = a_connection.recv(1024)
        mode_type = dataFromClient.decode()
        random_key = pad(random_key, AES.block_size)
        if mode_type == "OFB":
            cipher = AES.new(k_prim, AES.MODE_OFB, initialization_vector)
        else:
            cipher = AES.new(k_prim, AES.MODE_ECB)
        cipher_text = cipher.encrypt(random_key)
        out = b64encode(cipher_text)
        print(f"OUT: {out}")
        if mode_type == "OFB":
            decipher = AES.new(k_prim, AES.MODE_OFB, initialization_vector)
        else:
            decipher = AES.new(k_prim, AES.MODE_ECB)
        plaintext = unpad(decipher.decrypt(b64decode(out)), AES.block_size)
        print(f'PT: {plaintext}')

        a_connection.send(out)
    else:
        b_connection.send(mode_type.encode())
        print("Ce trimitem la B:")
        print(out)
        b_connection.send(out)
        a_key = a_connection.recv(1024)
        print("Am primit de la A:")
        print(a_key)
        b_connection.send(a_key)
        final_msg = b_connection.recv(1024)
        print(final_msg.decode())
        a_connection.send(final_msg)
        encrypted_msg = a_connection.recv(1024)
        encrypted_final = bytearray()
        while encrypted_msg:
            encrypted_final += bytearray(encrypted_msg)
            encrypted_msg = a_connection.recv(1024)
        print(encrypted_final[0:100])
        print("Am trimis lui B fisierul criptat final")
        b_connection.sendall(encrypted_final)
        break

print("----------------------------------------")

serverSocket.close()
