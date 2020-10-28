import chain.utils 
from chain.transfer import Transfer
from chain.committee import Committee
from chain.vote import Vote
from chain.keys import * 
import sys
import socketserver, socket

comm = None 

def prepare_data(command, data):
    return {
        "command": command,
        "data": data,
    }
host = "127.0.0.1"
port = 10000
address = (host, port)

class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class TCPHandler(socketserver.BaseRequestHandler):

    def respond(self, command, data):
            response = prepare_data(command, data)
            serialized_response = utils.serialize(response)
            self.request.sendall(serialized_response)


    def handle(self):
        raw_message = self.request.recv(100000)
        message = utils.deserialize(raw_message)
        print("Got a message {}".format(message))
        command = message["command"]

        if command == "ping":
            self.respond("pong", "This is a pong message")
            
        if command == "balance":
            public_key = message["data"]
            votes = comm.fetch_vote(public_key)
            self.respond("balance-response", votes)





def case_voter():
    print("=" * 20)
    # Generate private key
    #privkey_generator = input("Input your album number: ")
    privkey_generator = 1234
    secexp = randrange_from_seed__trytryagain(privkey_generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    print("Your private key:\t {}".format(short_key(private_key)))
    print("Your public key:\t {}".format(short_key(public_key)))

    #print("-" * 20)
    #print("Committee {}".format(committee["name"]))
    #print("Private key: {}".format( short_key(committee["privkey"]) ))
    #print("Public key: {}".format( short_key(committee["pubkey"]) ))
    #print("-" * 20)
    #
    #comm = Committee(committee["privkey"], committee["pubkey"])
    #
    #Issue a vote to my key and validate it
    #my_vote = comm.issue(public_key)
    #comm.validate_vote(my_vote)
    #
    #print("Owner: {}".format(short_key(comm.get_owner(my_vote))))
    #print("I have {} votes".format(len(comm.fetch_vote(public_key))))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(address)
    
    #Now ask committee what my balance is
    message = prepare_data("balance", public_key)
    serialized_message = utils.serialize(message)
    sock.sendall(serialized_message)
    message_data = sock.recv(100000)
    print("Recieved: {}".format( utils.deserialize(message_data)  ))


def case_committee():
    global comm
    print("=" * 20)
    print("You're running it as a committee")
    print("-" * 20)
    print("Committee {}".format(committee["name"]))
    print("Private key: {}".format( short_key(committee["privkey"]) ))
    print("Public key: {}".format( short_key(committee["pubkey"]) ))
    print("-" * 20)
    
    comm = Committee(committee["privkey"], committee["pubkey"])
    
    server = MyTCPServer(address, TCPHandler)
    server.serve_forever()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "voter":
        case_voter()
    elif mode == "committee":
        case_committee()
