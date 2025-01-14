import pathlib
import socket
import sys
import time
from datetime import datetime
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from signal import signal, SIGINT
from colorama import init, Fore
import zlib

text_color = Fore.WHITE


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
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception(f"{text_color}Socket connection broken")
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


def decrypt_data(private_key, data):
    decrypted_data = b""
    for i in range(0, len(data), 128):
        chunk = data[i : i + 128]
        decrypted_chunk = private_key.decrypt(chunk, padding.PKCS1v15())
        decrypted_data += decrypted_chunk
    return decrypted_data


def save_received_encrypted_file(filename, data):
    enc_filename = f"recv_files_enc/enc_recv_{pathlib.Path(filename).name}"
    with open(enc_filename, "wb") as file:
        file.write(data)

def get_text_color():
    print("Please enter your preferred text color (e.g., RED, GREEN, BLUE):")
    color = input().strip().upper()

    color_map = {
        "BLACK": Fore.BLACK,
        "RED": Fore.RED,
        "GREEN": Fore.GREEN,
        "YELLOW": Fore.YELLOW,
        "BLUE": Fore.BLUE,
        "MAGENTA": Fore.MAGENTA,
        "CYAN": Fore.CYAN,
        "WHITE": Fore.WHITE
    }

    return color_map.get(color, Fore.WHITE)  # Default to WHITE if invalid color


def main(args):
    
    # Initialize colorama
    init(autoreset=True)
    
    # Get text color
    text_color = get_text_color()
    
    port = int(args[0]) if len(args) > 0 else 4322
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            print(f"{text_color}Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(client_socket, filename_len).decode(
                                "utf-8"
                            )
                        case 1:
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            file_data = read_bytes(client_socket, file_len)
                            save_received_encrypted_file(filename, file_data)

                            private_key = load_server_private_key()
                            decrypted_data = decrypt_data(private_key, file_data)

                            print(f"{text_color}Decrypted data size: {len(decrypted_data)} bytes")

                            decompressed_data = zlib.decompress(decrypted_data)
                            print(f"{text_color}Decompressed file size: {len(decompressed_data)} bytes")

                            filename = "recv_" + filename.split("/")[-1]

                            with open(f"recv_files/{filename}", mode="wb") as fp:
                                fp.write(decrypted_data)
                            print(
                                f"{text_color}Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            print(f"{text_color}Closing connection...")
                            s.close()
                            break
                        case 3:
                            auth_message_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            auth_message = read_bytes(client_socket, auth_message_len)

                            server_private_key = load_server_private_key()
                            signed_auth_message = server_private_key.sign(
                                auth_message,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256(),
                            )

                            client_socket.sendall(
                                convert_int_to_bytes(len(signed_auth_message))
                            )
                            client_socket.sendall(signed_auth_message)

                            server_certificate = load_server_certificate()
                            client_socket.sendall(
                                convert_int_to_bytes(len(server_certificate))
                            )
                            client_socket.sendall(server_certificate)

    except Exception as e:
        print(e)
        s.close()


def handler(signal_received, frame):
    # Handle any cleanup here
    print(f"{text_color}SIGINT or CTRL-C detected. Exiting gracefully")
    exit(0)


if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is received
    signal(SIGINT, handler)
    main(sys.argv[1:])
