from stem.control import Controller
from cryptography.fernet import Fernet
import socket
import base64

with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    response = controller.create_ephemeral_hidden_service({80: 5000}, await_publication=True)
    print("Adres:", response.service_id + ".onion")

    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    print("Klucz szyfrowania (base64):", base64.urlsafe_b64encode(key).decode())

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 5000))
    s.listen(1)
    conn, addr = s.accept()

    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            print("Odebrano:", cipher_suite.decrypt(data).decode())

            response_message = input("Wpisz odpowiedź: ")
            encrypted_response = cipher_suite.encrypt(response_message.encode())
            conn.send(encrypted_response)
        except Exception as e:
            print("Wystąpił błąd:", e)
            break

    conn.close()
    s.close()
