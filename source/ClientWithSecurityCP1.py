import pathlib
import socket
import sys
import time
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os

def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
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


def load_server_public_key():
    with open("source/auth/server_private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        ).public_key()


def encrypt_data(public_key, data):
    encrypted_data = b""
    for i in range(0, len(data), 117):
        chunk = data[i : i + 117]
        encrypted_chunk = public_key.encrypt(chunk, padding.PKCS1v15())
        encrypted_data += encrypted_chunk
    return encrypted_data


def save_encrypted_file(filename, data):
    enc_filename = f"send_files_enc/enc_{pathlib.Path(filename).name}"
    with open(enc_filename, "wb") as file:
        file.write(data)


def authentication(s):
    s.sendall(convert_int_to_bytes(3))
    auth_message = b"Client Request SecureStore ID"
    s.sendall(convert_int_to_bytes(len(auth_message)))
    s.sendall(auth_message)

    signed_auth_message_len = convert_bytes_to_int(read_bytes(s, 8))
    signed_auth_message = read_bytes(s, signed_auth_message_len)
    cert_len = convert_bytes_to_int(read_bytes(s, 8))
    cert_data = read_bytes(s, cert_len)

    server_cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    server_public_key = server_cert.public_key()

    try:
        server_public_key.verify(
            signed_auth_message,
            auth_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        print("Server authentication successful")
    except InvalidSignature:
        print("Server authentication failed")
        return False

    return True


def main(args):
    port = int(args[0]) if len(args) > 0 else 4324
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    print("Establishing connection to server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        if authentication(s):
            while True:
                filename = input("Enter a filename to send (enter -1 to exit):").strip()

                if filename == "-1":
                    s.sendall(convert_int_to_bytes(2))
                    break

                while not pathlib.Path(filename).is_file():
                    filename = input("Invalid filename. Please try again:").strip()

                filename_bytes = bytes(filename, encoding="utf8")

                # Send the filename
                s.sendall(convert_int_to_bytes(0))
                s.sendall(convert_int_to_bytes(len(filename_bytes)))
                s.sendall(filename_bytes)

                # Read, encrypt, and send the file
                try:
                    with open(filename, mode="rb") as fp:
                        data = fp.read()
                        print(f"Read {len(data)} bytes from {filename}")
                        public_key = load_server_public_key()
                        encrypted_data = encrypt_data(public_key, data)
                        save_encrypted_file(filename, encrypted_data)
                        print(f"Encrypted file saved as enc_{pathlib.Path(filename).name}")

                        s.sendall(convert_int_to_bytes(1))
                        s.sendall(convert_int_to_bytes(len(encrypted_data)))
                        s.sendall(encrypted_data)
                except Exception as e:
                    print(f"Error processing file {filename}: {e}")

            # Close the connection
            s.sendall(convert_int_to_bytes(2))
            print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])