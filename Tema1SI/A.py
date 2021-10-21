import socket
from base64 import b64decode
from binascii import unhexlify
from crypto.Cipher import AES
from crypto.Util.Padding import pad, unpad

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect(("127.0.0.1", 4000))
data = "ECB"
clientSocket.send(data.encode())
dataFromServer = clientSocket.recv(1024)

print(dataFromServer.decode())

iv = "7bde5a0f3f39fd658efc45de143cbc94"
password = "3e83b13d99bf0de6c6bde5ac5ca4ae68"
iv = unhexlify(iv)
password = unhexlify(password)

if data == "OFB":
    decipher = AES.new(password, AES.MODE_OFB, iv)
else:
    decipher = AES.new(password, AES.MODE_ECB)
plaintext = unpad(decipher.decrypt(b64decode(dataFromServer.decode())), AES.block_size)
print(f'PT: {plaintext}')

clientSocket.send(plaintext)
final_msg = clientSocket.recv(1024)

print(final_msg.decode())

if final_msg.decode() == "Se poate incepe comunicarea":
    with open("image.bmp", "rb") as f:
        clear = f.read()
    if data == "ECB":
        cipher = AES.new(password, AES.MODE_ECB)
    else:
        cipher = AES.new(password, AES.MODE_OFB, iv)

    clear = pad(clear, AES.block_size)
    ciphertext = cipher.encrypt(clear)
    ciphertext = clear[0:64] + ciphertext
    final_plaintext = decipher.decrypt(ciphertext)
    if data == "ECB":
        with open("image_encrypted_ecb.bmp", "wb") as f:
            f.write(ciphertext)
    else:
        with open("image_encrypted_ofb.bmp", "wb") as f:
            f.write(ciphertext)
    clientSocket.sendall(ciphertext)
clientSocket.close()
