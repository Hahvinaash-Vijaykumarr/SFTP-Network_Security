import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore

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

def authentication(s, text_color):
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
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print(f"{text_color}Server authentication successful")
    except InvalidSignature:
        print(f"{Fore.RED}Server authentication failed")
        return False
    
    return True

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
    text_color = get_text_color()  # Get text color from user

    port = int(args[0]) if len(args) > 0 else 4322
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    print(f"{text_color}Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print(f"{text_color}Connected")

        if authentication(s, text_color):  # Pass text_color to authentication
            while True:
                filename = input(
                    f"{text_color}Enter a filename to send (enter -1 to exit):"
                ).strip()

                while filename != "-1" and (not pathlib.Path(filename).is_file()):
                    filename = input(f"{text_color}Invalid filename. Please try again:").strip()

                if filename == "-1":
                    s.sendall(convert_int_to_bytes(2))
                    break

                filename_bytes = bytes(filename, encoding="utf8")

                # Send the filename
                s.sendall(convert_int_to_bytes(0))
                s.sendall(convert_int_to_bytes(len(filename_bytes)))
                s.sendall(filename_bytes)

                # Send the file
                with open(filename, mode="rb") as fp:
                    data = fp.read()
                    s.sendall(convert_int_to_bytes(1))
                    s.sendall(convert_int_to_bytes(len(data)))
                    s.sendall(data)

            # Close the connection
            s.sendall(convert_int_to_bytes(2))
            print(f"{text_color}Closing connection...")

    end_time = time.time()
    print(f"{text_color}Program took {end_time - start_time}s to run.")

if __name__ == "__main__":
    main(sys.argv[1:])