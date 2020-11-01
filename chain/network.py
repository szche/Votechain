import socketserver, socket
import logging
from . import utils

committee = None

logging.basicConfig(
    level="INFO",
    format='%(asctime)-15s %(levelname)s %(message)s',
)
logger = logging.getLogger(__name__)

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
        serialized_response = utils.serialize(response)
        self.request.sendall(serialized_response)


    def handle(self):
        raw_message = self.request.recv(100000).strip()
        message = utils.deserialize(raw_message)
        command = message["command"]
        data = message["data"]
        logger.info(f"Recieved  {message}")
        if command == "ping":
            print("Got a PING message")
            self.respond("pong", "This is a pong message")
        elif command == "block":
            committee.handle_block(data)
            

def send_message(address, command, data, response=False):
    message = prepare_data(command, data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(address)
        s.sendall( utils.serialize(message) )
        if response == True:
            return utils.deserialize( s.recv(5000) )



