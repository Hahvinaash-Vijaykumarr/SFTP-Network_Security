import pathlib
import socket
import sys
import time
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def convert_int_to_bytes(x):
    return x.to_bytes(8, "big")

def convert_bytes_to_int(xbytes):
    return int.from_bytes(xbytes, "big")

def read_bytes(socket, length):
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)
    return b"".join(buffer)

def load_server_private_key():
    with open("source/auth/server_private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )

def load_server_certificate():
    with open("source/auth/server_signed.crt", "rb") as cert_file:
        return cert_file.read()

def decrypt_session_key(private_key, encrypted_session_key):
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key

def decrypt_data_with_key(key, encrypted_data):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data

def save_received_encrypted_file(filename, data):
    directory = "recv_files_enc"
    pathlib.Path(directory).mkdir(parents=True, exist_ok=True)

    enc_filename = f"{directory}/enc_recv_{pathlib.Path(filename).name}"
    with open(enc_filename, "wb") as file:
        file.write(data)

def save_received_file(filename, data):
    directory = "recv_files"
    pathlib.Path(directory).mkdir(parents=True, exist_ok=True)

    dec_filename = f"{directory}/recv_{pathlib.Path(filename).name}"
    with open(dec_filename, "wb") as file:
        file.write(data)

def main(args):
    port = int(args[0]) if len(args) > 0 else 4324
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            print(f"Listening on {address}:{port}...")
            client_socket, client_address = s.accept()
            print(f"Connection from {client_address}")

            with client_socket:
                session_key = None

                while True:
                    mode = convert_bytes_to_int(read_bytes(client_socket, 8))
                    print(f"Received mode: {mode}")

                    if mode == 0:
                        print("Receiving file...")
                        filename_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                        filename = read_bytes(client_socket, filename_len).decode("utf-8")
                        print(f"Receiving file: {filename}")
                    elif mode == 1:
                        start_time = time.time()

                        file_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                        print(f"Expecting file length: {file_len}")
                        file_data = read_bytes(client_socket, file_len)
                        print(f"Received file length: {len(file_data)}")

                        # Save the encrypted file
                        save_received_encrypted_file(filename, file_data)

                        # Save the decrypted file if session_key exists
                        if session_key:
                            decrypted_data = decrypt_data_with_key(session_key, file_data)
                            save_received_file(filename, decrypted_data)
                        
                        print(f"Finished receiving file {filename} in {time.time() - start_time:.2f}s")

                    elif mode == 2:
                        print("Client disconnected")
                        break

                    elif mode == 3:
                        auth_message_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                        auth_message = read_bytes(client_socket, auth_message_len)
                        server_cert = load_server_certificate()
                        private_key = load_server_private_key()

                        signed_auth_message = private_key.sign(
                            auth_message,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256(),
                        )

                        client_socket.sendall(convert_int_to_bytes(len(signed_auth_message)))
                        client_socket.sendall(signed_auth_message)
                        client_socket.sendall(convert_int_to_bytes(len(server_cert)))
                        client_socket.sendall(server_cert)

                    elif mode == 4:
                        encrypted_session_key_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                        encrypted_session_key = read_bytes(client_socket, encrypted_session_key_len)

                        private_key = load_server_private_key()
                        session_key = decrypt_session_key(private_key, encrypted_session_key)

                        print("Session key received and decrypted")

    except Exception as e:
        print(f"Server encountered an error: {e}")

if __name__ == "__main__":
    main(sys.argv[1:])