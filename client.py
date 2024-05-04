#Najpierw uruchom serwer
import socket
import socks
from cryptography.fernet import Fernet
import base64


socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
socket.socket = socks.socksocket

key = base64.urlsafe_b64decode('#Wpisz tutaj klucz szyfrowania ktory otzymasz po uruchomieniu serwera')
cipher_suite = Fernet(key)


def encrypt_message(message):
    return cipher_suite.encrypt(message.encode())


s = socket.socket()
try:
    s.connect(('#Wpisz tutaj adres, który otrzymasz po uruchomieniu serwera', 80))
    while True:
        message_to_send = input("Wpisz wiadomość do wysłania: ")
        encrypted_msg = encrypt_message(message_to_send)
        s.send(encrypted_msg)

        response = s.recv(1024)
        if not response:
            break
        print("Odebrano:", cipher_suite.decrypt(response).decode())
finally:
    s.close()
