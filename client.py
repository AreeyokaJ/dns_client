import socket 

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999 

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        msg = b"ping"
        sock.sendto(msg, (SERVER_HOST, SERVER_PORT))
        sock.settimeout(2.0)
       
        try:
            data, addr = sock.recvfrom(1024)
            print(f"reply from {addr}: {data!r}")
        except socket.timeout:
            print("no reply (timeout)")


if __name__ == "__main__":
    main()