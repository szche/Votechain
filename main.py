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
            print("Sending response: {} -> {}".format(command, data))
            print("="* 20)
            response = prepare_data(command, data)
            serialized_response = utils.serialize(response)
            self.request.sendall(serialized_response)


    def handle(self):
        raw_message = self.request.recv(100000)
        message = utils.deserialize(raw_message)
        command = message["command"]

        if command == "ping":
            print("Got a PING message")
            self.respond("pong", "This is a pong message")
        # Return an array of votes   
        elif command == "balance":
            public_key = message["data"]
            print("Got a BALANCE request for key {}".format(short_key(public_key)))
            votes = comm.fetch_vote(public_key)
            self.respond("balance-response", votes)
        # Track the vote
        elif command == "vote":
            vote_id = message["data"]
            owner = comm.get_owner(vote_id)
            print("Got a VOTE message of id {}".format(vote_id))
            self.respond("vote-reposne", owner)
        elif command == "send":
            vote = message["data"]
            print("Got a SEND message of vote {}".format(vote))
            #Validate the vote
            try:
                comm.validate_vote(vote)
                comm.cast_vote(vote)
                self.respond("tx-response", "validated")
            except:
                self.respond("tx-response", "Not validated") 
            

def send_message(command, data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(address)

    message = prepare_data(command, data)
    serialized_message = utils.serialize(message)
    sock.sendall(serialized_message)

    message_data = sock.recv(1000000)
    message = utils.deserialize(message_data)
    return message


# Generates (privkey, pubkey) pair
# Returns a tuple
def create_keypair(generator):
    secexp = randrange_from_seed__trytryagain(generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return (private_key, public_key)


def case_voter():
    print("=" * 20)
    # Generate my private key
    keypair = create_keypair(input("Input your email address: "))
    print("Your private key:\t {}".format(short_key(keypair[0])))
    print("Your public key:\t {}".format(short_key(keypair[1])))

    #Check your balance
    balance = send_message("balance", keypair[1])
    print("My balance: {}".format(len(balance["data"])))

    #Send your vote
    #Generate a second keypair - debugging only
    keypair2 = create_keypair("THIS IS A TEST KEY GENERATOR")
    print("Test pubkey: {}".format(short_key(keypair2[1])))
    my_vote = balance["data"][0]
    
    #Check who's the owner of this vote
    vote_owner = send_message("vote", my_vote.id)
    print("Owner of this vote: {}".format(short_key(vote_owner["data"])))

    #Now send the vote to the debuggin address
    my_vote.sign_transfer(keypair[0], keypair2[1])
    send_vote = send_message("send", my_vote)
    print("Sending status: {}".format(send_vote["data"]))

    #Check debugging balance
    debug_balance = send_message("balance", keypair2[1])
    print("Debugging balance: {}".format( len(balance["data"]) ))
    for vote in debug_balance["data"]:
        print(vote)
    #Check your balance
    balance = send_message("balance", keypair[0])
    print("My balance: {}".format(len(balance["data"])))


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
    # TODO make the chain creator issue votes in genesis block
    # Issue the votes to the voters
    issue_votes = utils.from_disk("airdrop.votechain")
    for voter in issue_votes:
        vote = comm.issue(voter)
        comm.validate_vote(vote)
    
    server = MyTCPServer(address, TCPHandler)
    server.serve_forever()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "voter":
        case_voter()
    elif mode == "committee":
        case_committee()
