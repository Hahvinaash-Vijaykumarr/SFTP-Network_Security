import pathlib
import socket
import sys
import time
import zlib
from datetime import datetime
import secrets
import traceback
from signal import signal, SIGINT
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

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


def load_ca_certificate():
    with open("source/auth/cacsertificate.crt", "rb") as cert_file:
        return x509.load_pem_x509_certificate(cert_file.read(), default_backend())


def load_server_certificate():
    with open("source/auth/server_signed.crt", "rb") as cert_file:
        return cert_file.read()
    
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
    global text_color  # Declare text_color as global
    text_color = get_text_color()  # Set text color based on user input

    port = int(args[0]) if len(args) > 0 else 4322
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    print(f"{text_color}Client connected")

                    handshake_message = b"Client is pinging the server..."
                    received_handshake = read_bytes(client_socket, len(handshake_message))
                    print(f"{text_color}Received handshake message: {received_handshake}")

                    if received_handshake == handshake_message:
                        print(f"{text_color}Sending handshake acknowledgment...")
                        client_socket.sendall(handshake_message)
                    else:
                        print(f"{Fore.RED}Unexpected handshake message received")
                        client_socket.close()
                        return
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print(f"{text_color}Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(client_socket, filename_len).decode(
                                "utf-8"
                            )
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            compressed_data = read_bytes(client_socket, file_len)
                            # print(file_data)

                            print(f"{text_color}Decrypted data size: {len(compressed_data)} bytes")

                            
                            file_data = zlib.decompress(compressed_data) # decompressing the data to send it over
                            print(f"{text_color}Decompressed file size: {len(file_data)} bytes")

                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(f"recv_files/{filename}", mode="wb") as fp:
                                fp.write(file_data)
                            print(
                                f"{text_color}Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
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
        print(f"{Fore.RED}{e}")
        s.close()


def handler(signal_received, frame):
    # Handle any cleanup here
    print(f"{text_color}SIGINT or CTRL-C detected. Exiting gracefully")
    exit(0)


if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)
    main(sys.argv[1:])