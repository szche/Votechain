import sys, os, logging, pickle, time, threading, socketserver, socket, re
from copy import deepcopy
from uuid import uuid4
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError
from ecdsa.util import randrange_from_seed__trytryagain

committee = None

host = "127.0.0.1"
PORT = 10000
address = (host, PORT)

class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class TCPHandler(socketserver.BaseRequestHandler):
    def get_canonical_peer_address(self):
        ip = self.client_address[0]
        try:
            hostname = socket.gethostbyaddr(ip)
            hostname = re.search(r"_(.*?)_", hostname[0]).group(1)
        except:
            hostname = ip
        return (hostname, PORT)

    def respond(self, command, data):
        logger.info("Sending response: {}".format(command))
        response = prepare_data(command, data)
        self.request.sendall(response)

    def handle(self):
        global committee
        message = read_message(self.request)
        command = message["command"]
        data = message["data"]
        peer = self.get_canonical_peer_address()
        #peer = self.client_address

        # Handshake / Auth
        if command == "connect":
            if peer not in committee.pending_peers and peer not in committee.peers:
                committee.pending_peers.append(peer)
                logger.info(f'(handshake) Accepted "connect" request from "{peer[0]}"')
                send_message(peer, "connect-response", None)

        elif command == "connect-response":
            if peer in committee.pending_peers and peer not in committee.peers:
                committee.pending_peers.remove(peer)
                committee.peers.append(peer)
                logger.info(f'(handshake) Connected to "{peer[0]}"')
                send_message(peer, "connect-response", None)

                # Ask for peers
                send_message(peer, "peers", None)

        else:
            assert peer in committee.peers, f"Rejecting {command} from unconnected {peer[0]}"

        # Business logic

        #Share your peers
        if command == "peers":
            send_message(peer, "peers-response", committee.peers)
        elif command == "peers-response":
            for peer in data:
                committee.connect(peer)



        #When discovering new block 
        elif command == "block":
            committee.handle_block(data)
        #User asks for his balance
        elif command == "balance":
            balance = committee.fetch_balance(data)
            self.respond("balance-response", balance)
        #User sends his vote
        elif command == "send-vote":
            committee.handle_vote(data)
        #User asks for specific block
        elif command == "fetch-block":
            block = committee.fetch_block(data)
            self.respond("fetch-block-response", block) 
        #User asks for specific vote
        elif command == "fetch-vote":
            vote = committee.fetch_vote(data)
            self.respond("fetch-vote-response", block) 


def read_message(s):
    message = b''
    # Our protocol is: first 4 bytes signify message length
    raw_message_length = s.recv(4) or b"\x00"
    message_length = int.from_bytes(raw_message_length, 'big')
    
    while message_length > 0:
        chunk = s.recv(1024)
        message += chunk
        message_length -= len(chunk)
        if len(chunk) == 0: break
    return deserialize(message)

def prepare_data(command, data):
    message = {
        "command": command,
        "data": data,
    }
    serialized_message = serialize(message)
    length = len(serialized_message).to_bytes(4, 'big')
    return length + serialized_message


def send_message(address, command, data, response=False):
    message = prepare_data(command, data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(address)
        s.sendall(message)
        if response:
            return read_message(s)

logging.basicConfig(
    level="INFO",
    format='%(message)s',
)
logger = logging.getLogger(__name__)

# Generates (privkey, pubkey) pair
# Returns a tuple
def create_keypair(generator):
    secexp = randrange_from_seed__trytryagain(generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return (private_key, public_key)

# Return shorter version of the key
def short_key(public_key):
    public_key_hex = public_key.to_string().hex()
    return f"{public_key_hex[0:4]}...{public_key_hex[-5:]}"


##########################################
#   Serialization and writing to disk    #
##########################################
def serialize(data):
    return pickle.dumps(data)

def deserialize(serialized):
    return pickle.loads(serialized)

def to_disk(data, filename):
    serialized = serialize(data)
    with open(filename, "wb") as f:
        f.write(serialized)

def from_disk(filename):
    with open(filename, "rb") as f:
        serialized = f.read()
        return deserialize(serialized)

##########################################
#   Vote class                           #
##########################################
class Vote:
    def __init__(self, transfers):
        self.transfers = transfers
        self.id = uuid4() # <- random and unique Vote id, used to check for duplicates

    def __eq__(self, other):
        return self.id == other.id and \
                self.transfers == other.transfers

    # Sign the transfer, but dont show it to the Committee yet!
    def sign_transfer(self, owner_private_key, recipient_public_key):
        # Assert that you're the owner
        assert self.transfers[-1].public_key.to_string()== owner_private_key.get_verifying_key().to_string()
        message = transfer_message(self.transfers[-1].signature, recipient_public_key)
        signature = owner_private_key.sign(message)
        vote_transfer = Transfer(signature, recipient_public_key)
        self.transfers.append(vote_transfer)

    def __str__(self):
        output = ""
        output += '======== Vote ========\n'
        output += f"Vote id: {self.id}\n"
        current_owner = self.transfers[-1].public_key
        output += f"Owner: {short_key(current_owner)}\n"
        if len(self.transfers) == 1:
            output += "Previous owner: GENESIS-BLOCK\n"
            output += f'Signature: GENESIS-BLOCK\n'
        else:
            previous_owner = self.transfers[-2].public_key
            output += f"Previous owner: {short_key(previous_owner)}\n"
            short_prev_sig = self.transfers[-1].signature.hex()[0:4] +"..."+ self.transfers[-1].signature.hex()[-5:]
            output += f'Signature: {short_prev_sig}\n'

        output += '=======================\n'
        return output

# Prepare a sending commitment
# i.e. tick the box on your voting ticket but dont put it in the ballot box yet
def transfer_message(previous_signature, next_owner_public_key):
    message = {
            "previous_signature": previous_signature,
            "next_owner_public_key": next_owner_public_key
    }
    return serialize(message)

##########################################
#   Transfer class                       #
##########################################
class Transfer:
    def __init__(self, signature, public_key):
        self.signature = signature
        self.public_key = public_key

    def __eq__(self, other):
        return self.signature == other.signature and \
                self.public_key.to_string() == other.public_key.to_string()

#########################################
#   Committee class                      #
##########################################
class Committee:
    def __init__(self, private_key, public_key, address):
        self.private_key = private_key
        self.public_key = public_key
        self.votes = {}     # Cached most recent versions of the votes (unspent UTXOS)
        self.blocks = []    # The chain
        self.mempool = []   # Votes waiting to be included in the block
        self.genesis_block()    # On node start-up, get the contests of the genesis block
        #TODO sync with other nodes
        #TODO dont start from genesis block only
        #self.peers = {(p, 10000) for p in os.environ['PEERS'].split(',')}
        self.peers = []  
        self.pending_peers = []
        self.address = address

    def connect(self, peer):
        if peer not in self.peers and peer != self.address:
            logger.info(f'(handshake) Sent "connect" to {peer[0]}')
            try:
                send_message(peer, "connect", None)
                self.pending_peers.append(peer)
            except:
                logger.info(f'(handshake) Node {peer[0]} offline')




    # Return an array of votes
    # Owner of the public key is the owner of these votes
    def fetch_balance(self, public_key):
        votes = []
        for vote in self.votes.values():
            if vote.transfers[-1].public_key.to_string() == public_key.to_string():
                votes.append(vote)
        return votes
    
    def fetch_vote(self, voteID):
        return self.votes[voteID]

    def fetch_block(self, nr):
        return self.blocks[nr-1]

    def validate_vote(self, vote):
        # Check if all the previous transfers are valid
        issue_transfer = vote.transfers[0] # Must be in the genesis block to be valid
        # Assert that the issue transfer is in the genesis block
        # Find this vote ID in the genesis block and assert that 
        # the transfers are the same
        inGenesis = False
        for genesis_vote in self.blocks[0].votes:
            if genesis_vote.id == vote.id and genesis_vote.transfers[0] == issue_transfer:
                inGenesis = True
                break
        assert inGenesis == True

        previous_transfer = issue_transfer
        for next_transfer in vote.transfers[1::]:
            message = transfer_message(previous_transfer.signature, next_transfer.public_key)
            assert previous_transfer.public_key.verify(next_transfer.signature, message)
            previous_transfer = next_transfer
        
    # Update the cached vote 
    # Cached vote is the most recent version of this vote
    def update_cached_votes(self, vote):
        last_observation = self.votes[vote.id]
        last_observation_length = len(last_observation.transfers)
        assert last_observation.transfers == vote.transfers[:last_observation_length]
        self.votes[vote.id] = deepcopy(vote)

    # Return the public key of the next commitee in turn to produce a block
    @property
    def next_committee_turn(self):
        blocks = len(self.blocks)
        turns = self.blocks[0].turns
        return turns[blocks % len(turns)][1]

    # When seeing a new block
    def handle_block(self, block):
        #Verify committee signature (Skip the genesis block)
        if len(self.blocks) > 0:
            public_key = self.next_committee_turn
            public_key.verify(block.signature, block.message)

        #Verify previous signature
        assert self.blocks[-1].signature == block.prev_sig
        
        #Verify every vote
        for vote in block.votes:
            self.validate_vote(vote)

        #Update self.votes and mempool
        for vote in block.votes:
            self.update_cached_votes(vote)
            if vote in self.mempool:
                self.mempool.remove(vote)

        #Update self.blocks
        self.blocks.append(block)

        #Schedule next block
        self.schedule_next_block()

        #Save the accepted block
        self.save_block()
        logger.info(f"Block accepted, height: {len(self.blocks)}")

    def create_block(self):
        votes = deepcopy(self.mempool)
        self.mempool = []
        block = Block(
                votes = votes,
                prev_sig = self.blocks[-1].signature
                )
        block.sign(self.private_key)
        return block


    def submit_block(self):
        # Create the block
        block = self.create_block()
        # Validate it and save it locally
        self.handle_block(block)
        # Broadcast the block
        for address in self.peers:
            logger.info(f"Sending to {address}")
            send_message(address, "block", block)

    #For authorized "Block producers" only!
    def schedule_next_block(self):
        if self.public_key.to_string() == self.next_committee_turn.to_string():
            logger.info(f"MY TURN NOW!")
            threading.Timer(30, self.submit_block, []).start()
            

    # Upon reciving the vote, validate it, add it to your mempool and broadcast it further
    def handle_vote(self, vote):
        mempool_ids = [vote.id for vote in self.mempool]
        #If this ID is already in the mempool, dont do anything
        if vote.id in mempool_ids: return
        self.validate_vote(vote)
        #assert vote.id not in mempool_ids
        #Otherwise, add it to your mempool and broadcast it
        self.mempool.append( deepcopy(vote) )
        for address in self.peers:
            logger.info(f"Broadcasting the tx further -> {address}")
            send_message(address, "send-vote", vote)

    # Get the information from the genesis block
    # Genesis block comes pre-loaded with the software
    # TODO: check that the checksum of the genesis block is correct
    def genesis_block(self):
        assert len(self.blocks) == 0
        block = from_disk("data/0.votechain")
        for vote in block.votes:
            self.votes[vote.id] = deepcopy(vote)
        self.blocks.append(block)
        """
        logger.info("Cached votes: ")
        for vote in self.votes.values():
            logger.info(f"{short_key(vote.transfers[-1].public_key)}")
        """
        
    #Save the last block
    def save_block(self):
        last_block = self.blocks[-1]
        block_height = self.blocks.index(last_block)
        filename = f"data/{block_height}.votechain"
        to_disk(last_block, filename)
    

##########################################
#   Block class                          #
##########################################
class Block:
    def __init__(self, votes, timestamp=None, signature=None, prev_sig=None):
        if timestamp == None:
            timestamp = time.time()
        self.timestamp = timestamp
        self.signature = signature
        self.votes = votes
        self.prev_sig = prev_sig

    def __str__(self):
        output = ""
        output += '======== Block ========\n'
        output += f'Txs: {len(self.votes)}\n'
        output += f'Timestamp: {self.timestamp}\n'
        if self.signature == None:
            output += f'Signature: {self.signature}\n'
        else:
            short_sig = self.signature.hex()[0:4] +"..."+ self.signature.hex()[-5:]
            output += f'Signature: {short_sig}\n'
        if self.prev_sig == None:
            output += f'Prev_signature: {self.prev_sig}\n'
        else:
            short_prev_sig = self.prev_sig.hex()[0:4] +"..."+ self.prev_sig.hex()[-5:]
            output += f'Prev_signature: {short_prev_sig}\n'
        output += '=======================\n'
        return output
    
    @property
    def message(self):
        data = [self.votes, self.timestamp, self.prev_sig]
        return serialize(data)

    def sign(self, private_key):
        self.signature = private_key.sign(self.message)




def case_voter():
    print("=" * 20)
    # Generate my private key
    keypair = create_keypair(input("Input your email address: "))
    print("Your private key:\t {}".format(short_key(keypair[0])))
    print("Your public key:\t {}".format(short_key(keypair[1])))

    while True:
        print("=" * 20)
        print("Menu:")
        print("1) Check your balance")
        print("2) Check balance of someone else")
        print("3) Send to")
        print("4) Fetch block")
        print("5) Fetch vote")
        print("=" * 20)

        option = int( input("What's your choice: ") )
        #Check your balance
        if option == 1:
            balance = send_message(address, "balance", keypair[1], True)
            print("Your balance is: {}".format(len(balance["data"])))
            for vote in balance["data"]:
                print(vote)
        #Check the balance of someone else
        elif option == 2:
            new_id = create_keypair( input("Input the generator of another address: ") )
            balance = send_message(address, "balance", new_id[1], True)
            print("His balance is: {}".format(len(balance["data"])))
            for vote in balance["data"]:
                print(vote)
        #Send to
        elif option == 3:
            new_owner = create_keypair( input("Input the generator of another address: ") )
            my_balance = send_message(address, "balance", keypair[1], True)
            if len(my_balance["data"]) == 0:
                print("You do not have enough votes!")
                continue
            my_vote = my_balance["data"][0]
            my_vote.sign_transfer(keypair[0], new_owner[1])
            send_message(address, "send-vote", my_vote)
        #Fetch block
        elif option == 4:
            blockNR = int(input("What's the block nr: "))
            block = send_message(address, "fetch-block", blockNR, True)
            print(block["data"])
        #Fetch vote
        elif option == 5:
            voteID = input("What's the vote id: ")
            vote = send_message(address, "fetch-vote", voteID, True)
            print(vote["data"])
        else:
            print("Invalid option")
            continue


def serve():
    server = socketserver.TCPServer(("0.0.0.0", PORT), TCPHandler)
    server.serve_forever()


def case_committee():
    global committee
    node_name = os.environ["NAME"]
    generator = ""
    name = ""
    if node_name == "node0":
        generator = "lajkonik"
        name = "Krakow"
    elif node_name == "node1":
        generator = "syrenka"
        name = "Warszawa"
    elif node_name == "node2":
        generator = "koziolki"
        name = "Poznan"
    keypair = create_keypair(generator)
    committee = Committee(keypair[0], keypair[1], (node_name, PORT))
    logger.info(f"Started as {name: <9} -> {short_key(keypair[1])}")

    """
    print("Your public key: {}".format( short_key(keypair[1]) ))
    print("Your private key: {}".format( short_key(keypair[0]) ))
    print("-" * 20)

    parties = committee.blocks[0].parties
    print("\n=== Avaliable parties ===")
    for party in parties:
        print( f'{party: <40} with key {short_key(parties[party])}' )

    auth_committees = committee.blocks[0].turns
    print("\n=== Authorized committees ===")
    for com in auth_committees:
        print( f'{com[0]: <40} with key {short_key(com[1])}' )
    """

    committee.schedule_next_block()

    # Start server thread
    server_thread = threading.Thread(target=serve, name="server")
    server_thread.start()

    #Connect to other peers
    peers = [(p, PORT) for p in os.environ['PEERS'].split(',')]
    for peer in peers:
        committee.connect(peer)

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "voter":
        case_voter()
    elif mode == "committee":
        case_committee()
