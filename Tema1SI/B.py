import socket
from base64 import b64decode
from binascii import unhexlify
from crypto.Cipher import AES
from crypto.Util.Padding import unpad

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect(("127.0.0.1", 4000))
data = clientSocket.recv(1024)
print(data.decode())

key = clientSocket.recv(1024)

print("--------------")
print(key)
print("------------")

iv = "7bde5a0f3f39fd658efc45de143cbc94"
password = "3e83b13d99bf0de6c6bde5ac5ca4ae68"
iv = unhexlify(iv)
password = unhexlify(password)

if data.decode() == "OFB":
    decipher_ofb = AES.new(password, AES.MODE_OFB, iv)
    plaintext = unpad(decipher_ofb.decrypt(b64decode(key)), AES.block_size)
else:
    decipher = AES.new(password, AES.MODE_ECB)
    plaintext = unpad(decipher.decrypt(b64decode(key)), AES.block_size)

print(f'PT: {plaintext}')

a_decrypted_key = clientSocket.recv(1024)
print("Am primit de la A:")
print(a_decrypted_key)

if a_decrypted_key == plaintext:
    final_msg = "Se poate incepe comunicarea"
else:
    final_msg = "Nu se poate incepe comunicarea"

print(final_msg)
clientSocket.send(final_msg.encode())

encrypted_msg = clientSocket.recv(1024)
encrypted_final = bytearray()
while len(encrypted_msg) == 1024:
    encrypted_final += bytearray(encrypted_msg)
    encrypted_msg = clientSocket.recv(1024)
encrypted_final += bytearray(encrypted_msg)
header = encrypted_final[0:64]
encrypted_final = encrypted_final[64:]
if data.decode() == "OFB":
    decipher_final_ofb = AES.new(password,AES.MODE_OFB, iv)
    final_plaintext = decipher_final_ofb.decrypt(encrypted_final)
else:
    decipher_final_ecb = AES.new(password,AES.MODE_ECB)
    final_plaintext = decipher_final_ecb.decrypt(encrypted_final)
final_plaintext = header + final_plaintext

if data.decode() == "ECB":
    with open("image_decrypted_ecb.bmp", "wb") as f:
        f.write(final_plaintext)
else:
    with open("image_decrypted_ofb.bmp", "wb") as f:
        f.write(final_plaintext)
clientSocket.close()
