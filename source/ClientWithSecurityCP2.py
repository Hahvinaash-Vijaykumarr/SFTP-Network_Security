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
from colorama import init, Fore

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

def load_server_public_key():
    with open("source/auth/server_private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        ).public_key()

def encrypt_data_with_key(key, data):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    return encrypted_data

def encrypt_session_key(public_key, session_key):
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_session_key

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
        print(f"{text_color}Server authentication successful{Fore.RESET}")
    except InvalidSignature:
        print(f"{text_color}Server authentication failed{Fore.RESET}")
        return False

    return True

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
    global text_color
    text_color = get_text_color()
    
    port = int(args[0]) if len(args) > 0 else 4322
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    print(f"{text_color}Establishing connection to server...{Fore.RESET}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print(f"{text_color}Connected{Fore.RESET}")

        if authentication(s):
            session_key = Fernet.generate_key()
            public_key = load_server_public_key()
            encrypted_session_key = encrypt_session_key(public_key, session_key)

            s.sendall(convert_int_to_bytes(4))  # Notify server of key exchange
            s.sendall(convert_int_to_bytes(len(encrypted_session_key)))  # Send size of encrypted session key
            s.sendall(encrypted_session_key)  # Send encrypted session key

            while True:
                filename = input(f"{text_color}Enter a filename to send (enter -1 to exit):{Fore.RESET}").strip()

                if filename == f"{text_color}-1{Fore.RESET}":
                    s.sendall(convert_int_to_bytes(2))
                    break

                while not pathlib.Path(filename).is_file():
                    filename = input(f"{text_color}Invalid filename. Please try again:{Fore.RESET}").strip()

                filename_bytes = bytes(filename, encoding="utf8")

                s.sendall(convert_int_to_bytes(0))  # Indicate file sending mode
                s.sendall(convert_int_to_bytes(len(filename_bytes)))  # Send size of filename
                s.sendall(filename_bytes)  # Send filename

                with open(filename, mode="rb") as fp:
                    data = fp.read()
                    print(f"{text_color}Read {len(data)} bytes from {filename}{Fore.RESET}")
                    encrypted_data = encrypt_data_with_key(session_key, data)
                    save_encrypted_file(filename, encrypted_data)  # Save encrypted file
                    print(f"{text_color}Encrypted file saved as enc_{pathlib.Path(filename).name}{Fore.RESET}")

                    s.sendall(convert_int_to_bytes(1))  # Indicate data sending mode
                    s.sendall(convert_int_to_bytes(len(encrypted_data)))  # Send size of encrypted file data
                    s.sendall(encrypted_data)  # Send encrypted file data

            print(f"{text_color}Connection closed after {(time.time() - start_time)}s{Fore.RESET}")

if __name__ == "__main__":
    main(sys.argv[1:])