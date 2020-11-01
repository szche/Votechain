import socketserver, socket
from . import logger, serialize, deserialize
#import logging
#from . import utils


host = "0.0.0.0"
port = 10000
address = (host, port)

def prepare_data(command, data):
    return {
        "command": command,
        "data": data,
    }


class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class TCPHandler(socketserver.BaseRequestHandler):
    def respond(self, command, data):
        print("Sending response: {} -> {}".format(command, data))
        print("="* 20)
        response = prepare_data(command, data)
        serialized_response = serialize(response)
        self.request.sendall(serialized_response)


    def handle(self):
        global committee
        raw_message = self.request.recv(100000).strip()
        message = deserialize(raw_message)
        command = message["command"]
        data = message["data"]
        logger.info(f"Recieved  {message}")
        logger.info(f'Type of com inside handle: {type(committee)}' )
        if command == "ping":
            print("Got a PING message")
            self.respond("pong", "This is a pong message")
        elif command == "block":
            committee.handle_block(data)
            

def send_message(address, command, data, response=False):
    message = prepare_data(command, data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(address)
        s.sendall( serialize(message) )
        if response == True:
            return deserialize( s.recv(5000) )



