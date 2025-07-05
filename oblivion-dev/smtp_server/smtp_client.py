import socket
import sys

def send_cmd(sock, cmd):
    sock.send((cmd + "\r\n").encode())
    response = sock.recv(1024).decode()
    print("S:", response.strip())
    return response

def send_data(sock, data_lines):
    for line in data_lines:
        sock.send((line + "\r\n").encode())
    sock.send(b".\r\n")
    response = sock.recv(1024).decode()
    print("S:", response.strip())

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2525

    print(f"Connecting to SMTP server at {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    print("S:", sock.recv(1024).decode().strip())

    send_cmd(sock, "EHLO localhost")
    send_cmd(sock, "MAIL FROM:<sender@example.com>")
    send_cmd(sock, "RCPT TO:<receiver@example.com>")
    send_cmd(sock, "DATA")

    send_data(sock, [
        "Subject: Test Email",
        "From: sender@example.com",
        "To: receiver@example.com",
        "",
        "This is a test message.",
        "Regards,",
        "Test Client"
    ])

    send_cmd(sock, "QUIT")
    sock.close()

if __name__ == "__main__":
    main()
