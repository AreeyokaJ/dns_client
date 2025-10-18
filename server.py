import socket 

HOST = "127.0.0.1"
PORT = 9999
BUF = 1024

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT)) 
        print(f"UDP server listening on {HOST}: {PORT}")

        while True:
            data, addr = sock.recvfrom(BUF)
            print(f"from {addr}: {data!r}")
            sock.sendto(b"pong: " + data, addr)

if __name__ == "__main__":
    main()