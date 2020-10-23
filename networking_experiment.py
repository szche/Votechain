import socketserver, socket
import sys

host = "127.0.0.1"
port = 10000
address = (host, port)

class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        message = self.request.recv(10)
        print("Got a message {}".format(message))

        if message == b"p":
            self.request.sendall(b"o")


def serve():
    server = MyTCPServer(address, TCPHandler)
    server.serve_forever()

def ping():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(address)
    sock.sendall(b"p")
    data = sock.recv(10)
    print("Recieved: {}".format(data.decode()))

if __name__ == "__main__":
    command = sys.argv[1]
    if command == "serve":
        serve()
    elif command == "ping":
        ping()
    else:
        print("Invalid command!")

