import sys, os, logging, pickle, time, threading, socketserver, socket
from copy import deepcopy
from uuid import uuid4
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError
from ecdsa.util import randrange_from_seed__trytryagain

committee = None

host = "127.0.0.1"
port = 10000
address = (host, port)

class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class TCPHandler(socketserver.BaseRequestHandler):
    def respond(self, command, data):
        logger.info("Sending response: {} -> {}".format(command, data))
        response = prepare_data(command, data)
        serialized_response = serialize(response)
        self.request.sendall(serialized_response)


    def handle(self):
        global committee
        logger.info("Recieved something...")
        message = read_message(self.request)
        command = message["command"]
        data = message["data"]
        logger.info(f"Recieved  {message}")
        if command == "ping":
            print("Got a PING message")
            self.respond("pong", "This is a pong message")
        elif command == "block":
            committee.handle_block(data)
        elif command == "balance":
            balance = committee.fetch_vote(data)
            self.respond("balance-response", balance)
        #Recieve the vote, validate it and pass it to other peers
        elif command == "send-vote":
            logger.info("SOMEONE IS SENDING HIS VOTE")
            committee.handle_vote(data)
            

def read_message(s):
    message = b''
    # Our protocol is: first 4 bytes signify message length
    raw_message_length = s.recv(4) or b"\x00"
    message_length = int.from_bytes(raw_message_length, 'big')
    print(f"MSG length: {message_length}")
    
    while message_length > 0:
        chunk = s.recv(1024)
        message += chunk
        print("Recieved chunk {}".format(len(chunk)))
        message_length -= len(chunk)
        logger.info(f"Left: {message_length}")
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
    format='%(asctime)-15s %(levelname)s %(message)s',
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
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.votes = {}     # Cached most recent versions of the votes (unspent UTXOS)
        self.blocks = []    # The chain
        self.mempool = []   # Votes waiting to be included in the block
        self.genesis_block()    # On node start-up, get the contests of the genesis block
        #TODO sync with other nodes
        #TODO dont start from genesis block only
        self.peer_addresses = {(p, 10000) for p in os.environ['PEERS'].split(',')}

    # Return an array of votes
    # Owner of the public key is the owner of these votes
    def fetch_vote(self, public_key):
        votes = []
        for vote in self.votes.values():
            if vote.transfers[-1].public_key.to_string() == public_key.to_string():
                votes.append(vote)
        return votes

    # Returns which public key owns this vote
    def get_owner(self, voteID):
        return self.votes[voteID].transfers[-1].public_key

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
        logger.info(f"Block {len(self.blocks)} added to the chain")

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
        for address in self.peer_addresses:
            logger.info(f"Sending to {address}")
            send_message(address, "block", block)

    def schedule_next_block(self):
        if self.public_key.to_string() == self.next_committee_turn.to_string():
            logger.info(f"MY TURN NOW!")
            threading.Timer(15, self.submit_block, []).start()
            

    # Upon reciving the vote, validate it, add it to your mempool and broadcast it further
    def handle_vote(self, vote):
        self.validate_vote(vote)
        mempool_ids = [vote.id for vote in self.mempool]
        #If this ID is already in the mempool, dont do anything
        if vote.id in mempool_ids: return
        #assert vote.id not in mempool_ids
        #Otherwise, add it to your mempool and broadcast it
        self.mempool.append( deepcopy(vote) )
        for address in self.peer_addresses:
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
            output += f'Signature: {self.signature.hex()}\n'
        if self.prev_sig == None:
            output += f'Prev_signature: {self.prev_sig}\n'
        else:
            output += f'Prev_signature: {self.prev_sig.hex()}\n'
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

    #Check your balance
    balance = send_message(address, "balance", keypair[1], True)
    print("My balance: {}".format(len(balance["data"])))

    # Send this vote to someone else
    new_owner = create_keypair(input("Input the generator of another address: "))
    my_vote = balance["data"][0]
    my_vote.sign_transfer(keypair[0], new_owner[1])
    send_message(address, "send-vote", my_vote)

    #Check my and someone's balance
    balance = send_message(address, "balance", keypair[1], True)
    print("My balance: {}".format(len(balance["data"])))

    balance = send_message(address, "balance", new_owner[1], True)
    print("My balance: {}".format(len(balance["data"])))

    """
    #Send your vote
    #Generate a second keypair - debugging only
    keypair2 = create_keypair("test_case")
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
    print("Debugging balance: {}".format( len(debug_balance["data"]) ))
    for vote in debug_balance["data"]:
        print(vote)
    #Check your balance
    balance = send_message("balance", keypair[0])
    print("My balance: {}".format(len(balance["data"])))
    """



def case_committee():
    global committee
    print("Creating committee")
    node_id = int(os.environ["NODE_ID"])
    generator = ""
    if node_id == 0:
        generator = "lajkonik"
        logger.info("Started as Krakow committee")
    elif node_id == 1:
        generator = "syrenka"
        logger.info("Started as Warszawa committee")
    elif node_id == 2:
        generator = "koziolki"
        logger.info("Started as Poznan committee")
    #generator = input("Input committee password: ")
    keypair = create_keypair(generator)
    committee = Committee(keypair[0], keypair[1])
    logger.info(f"My public key: {short_key(keypair[1])}")

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

    committee.schedule_next_block()

    """
    print("-" * 20)
    my_keys = create_keypair("MY TEST KEY")
    friend_keys = create_keypair("FRIEND TEST KEY")
    balance = committee.fetch_vote(my_keys[1])
    print("My balance: {}".format(len(balance)))
    my_vote = balance[0]
    my_vote.sign_transfer(my_keys[0], friend_keys[1])
    """
    server = socketserver.TCPServer(("0.0.0.0", 10000), TCPHandler)
    server.serve_forever()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "voter":
        case_voter()
    elif mode == "committee":
        case_committee()
