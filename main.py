import sys, logging, pickle, time, threading, socketserver, socket, re, requests, os, random
from copy import deepcopy
from uuid import uuid4
from datetime import datetime
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError
from ecdsa.util import randrange_from_seed__trytryagain


committee = None

PORT = 10000

# Get request returns your public IP address
MY_IP_LINK = "https://chadam.pl/tracker/ip.php"

# Get request returns the list of public nodes
PEERS_LIST = "https://chadam.pl/tracker/"

# Visit this link to be added to the tracker list as a public node
ADD_YOUR_PEER = "https://chadam.pl/tracker/public.php"


logging.basicConfig(
    level="INFO",
    format='%(message)s',
)
logger = logging.getLogger(__name__)


# Return byte-like objects from hex values
# Used for signing and verifying etc.
def pubkey_from_hex(pubkey):
    return VerifyingKey.from_string( bytes().fromhex(pubkey), curve=SECP256k1 )

def sig_from_hex(signature):
    return bytes().fromhex(signature)

def privkey_from_hex(privkey):
    return SigningKey.from_string( bytes().fromhex(privkey), curve=SECP256k1 )

# Change public key, private key and signature to hex values
def to_hex(data):
    # Private key
    if isinstance(data, SigningKey):        #Private key
        return data.to_string().hex()
    # Public key
    elif isinstance(data, VerifyingKey):    # Public key
        return data.to_string().hex()
    # Else (Signature)
    return data.hex()


class MyTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class TCPHandler(socketserver.BaseRequestHandler):

    def respond(self, command, data):
        response = prepare_data(command, data)
        self.request.sendall(response)

    def handle(self):
        global committee
        message = read_message(self.request)
        command = message["command"]
        data = message["data"]
        peer = self.client_address
        logger.info(f"Got a {command} from {peer}")

        if command == "peers":
            try:
                self.respond("peers-response", committee.peers)
                possible_peers = data + [peer]
                committee.new_peers(possible_peers)
            except:
                pass

        # Syncing new nodes
        # Receiving data    ->  Signature of the last user's known block
        # Response data     ->  Every block following that signature
        if command == "sync":
            try:
                blocks = committee.sync_request(data)
                logger.info(f'Served "sync" request with { len(blocks) } blocks')
                self.respond("sync-response", blocks)
            except:
                self.respond("sync-response", "error")

        # Receive a newly minted block and handle it
        # Receiving data    ->  New block
        elif command == "block":
            try:
                committee.handle_block(data)
            except:
                logger.info("Something went wrong during handling new block")
        
        # Receive a newly signed vote and add it to the blockchain 
        # Receiving data    ->  Vote
        elif command == "send-vote":
            committee.handle_vote(data)


def read_message(s):
    message = b''
    # first 4 bytes signify message length
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
    #logger.info(f"Sending {command} to {address}")
    message = prepare_data(command, data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(address)
        s.sendall(message)
        if response:
            return read_message(s)


# Generates (privkey, pubkey) pair
# Returns a tuple
def create_keypair(generator):
    print("Creating keypair...")
    secexp = randrange_from_seed__trytryagain(generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return ( to_hex(private_key), to_hex(public_key) )


# Return shorter version of the key
def short_key(key):
    return f"{key[0:4]}...{key[-5:]}"


##########################################
#   Serialization and writing to disk    #
##########################################
def serialize(data):
    return pickle.dumps(data, protocol=0)


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
    def __init__(self, transfers, voteid):
        self.transfers = transfers
        self.id = voteid  # <- random and unique Vote id, used to check for duplicates

    def __eq__(self, other):
        return self.id == other.id and \
                self.transfers == other.transfers

    # Sign the transfer, but dont show it to the Committee yet!
    def sign_transfer(self, owner_private_key, recipient_public_key):
        recipient_public_key = pubkey_from_hex(recipient_public_key)
        owner_private_key = privkey_from_hex(owner_private_key)
        # Assert that you're the owner
        assert self.transfers[-1].public_key == to_hex(owner_private_key.get_verifying_key())
        message = transfer_message(self.transfers[-1].signature, to_hex(recipient_public_key))
        signature = to_hex(owner_private_key.sign(message))
        vote_transfer = Transfer(signature, to_hex(recipient_public_key))
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
            short_prev_sig = self.transfers[-1].signature[0:4] +"..."+ self.transfers[-1].signature[-5:]
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
    logger.info(message)
    return serialize(message)
    """
    if previous_signature is None:
        previous_signature = ""
    return bytes(previous_signature+next_owner_public_key, encoding="utf-8")
    """


##########################################
#   Transfer class                       #
##########################################
class Transfer:
    def __init__(self, signature, public_key):
        self.signature = signature
        self.public_key = public_key

    def __eq__(self, other):
        return self.signature == other.signature and \
                self.public_key == other.public_key


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
        self.peers = []  
        self.address = address

    def new_peers(data):
        for peer in data:
            if peer not in self.peers and peer != self.address:
                self.peers.append(peer)



    # Return an array of votes
    # Owner of the public key is the owner of these votes
    def fetch_balance(self, public_key):
        #print(f"Fetching balance for {public_key}")
        votes = []
        for vote in self.votes.values():
            if vote.transfers[-1].public_key == public_key:
                votes.append(vote)
        return votes
    
    def fetch_vote(self, voteID):
        return self.votes[voteID]

    def fetch_block(self, nr):
        return self.blocks[nr-1]

    def validate_vote(self, vote):
        logger.info(f"Validating vote {vote}")
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
            #logger.info(f"Previous transfer signature: {previous_transfer.signature}")
            #logger.info(f"Reciepent public key: {next_transfer.public_key}")
            #logger.info(f"Issuer public key: {previous_transfer.public_key}")
            #logger.info(f"{pubkey_from_hex(previous_transfer.public_key)}, {sig_from_hex(next_transfer.signature)}, {message}")
            assert pubkey_from_hex(previous_transfer.public_key).verify(sig_from_hex(next_transfer.signature), message)
            previous_transfer = next_transfer
        logger.info("Vote passed the for")

        
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
        turns = list( self.blocks[0].committees.values() )
        return turns[blocks % len(turns)]

    # When seeing a new block
    def handle_block(self, block, schedule=True):
        logger.info("Handling new block: {}".format(block.signature))
        #Verify committee signature (Skip the genesis block)
        if len(self.blocks) > 1:
            public_key = self.next_committee_turn
            #logger.info(f"Block should be produced by {short_key(public_key)}")
            pubkey_from_hex(public_key).verify(sig_from_hex(block.signature), block.message)

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
        if schedule == True:
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
        print(f"Creating the block: {block.signature}")
        # Validate it and save it locally
        self.handle_block(block)
        # Broadcast the block
        for address in self.peers:
            logger.info(f"Sending to {address}")
            try:
                send_message((address, PORT), "block", block)
            except:
                pass

    # For authorized "Block producers" only!
    # Wont work for any other node
    def schedule_next_block(self):
        if self.public_key == self.next_committee_turn:
            logger.info(f"My turn to create block now!")
            threading.Timer(10, self.submit_block, []).start()
            

    # Upon reciving the vote, validate it, add it to your mempool and broadcast it further
    def handle_vote(self, vote):
        mempool_ids = [vote.id for vote in self.mempool]
        #If this ID is already in the mempool, dont do anything
        if vote.id in mempool_ids: return
        self.validate_vote(vote)

        if vote == self.votes[vote.id]: return

        #assert vote.id not in mempool_ids
        #Otherwise, add it to your mempool and broadcast it
        self.mempool.append( deepcopy(vote) )
        logger.info("Vote added to th mempool")
        for address in self.peers:
            logger.info(f"Broadcasting the tx further -> {address}")
            send_message((address, PORT), "send-vote", vote)
            logger.info(f"Vote sent to {address}")

    # Create the genesis block
    # Genesis block comes pre-loaded with the software
    def genesis_block(self):
        assert len(self.blocks) == 0
        # Initial vote airdrop,
        # (Issuing the voting ballots to the voters)
        votes = [
                    Vote( 
                            transfers=[Transfer(None,"76d0926fb152cf78ceccd9343b1b6d476d0cc09235b8d9dc6a6414e1dbbb023c8ed968dae7d4a592b78e1fb0b9e7abe33530cfd0908ef1de5e8462af4ddc0682" )],
                            voteid="ee65f195-fdef-4f28-972f-cf63b8ee13ee"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"374626ecfc59d73a960a1ee2e8929cc155e175186ee2b44ea664de45990af0efbc8a88e0c979e6a1f2d3018e8c6aad6f0c86b5f6cdd67b067bcdca2db112b188" )],
                            voteid="1b61cee1-d88a-4f24-b8f6-4aa12057d7a0"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"a5d9f0fcc191271069a10573f57ef3b7f46bf819b402784a92429b30e044cb0fb4701db54a978570567d73380f9dd3bde1b4ef1dacdd5051ae8f578c52b84475" )],
                            voteid="155c048c-a8d4-4d42-8437-634ecf3008c1"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"2200a1ce355b6a209eef567a3081875d621839ac3ff7a609dd7619cae0a8679d1d61b67e98e1609cc13a2e461152f7f7a96c85af4a656799fc5b7af5679d13b2" )],
                            voteid="a22d33bd-32ef-4b4c-a83e-491ee3f91ed5"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"06f7294b565ebe61c8f40c151886b03c64f79b6b499c5a1e2a9871219d17c57e3c9ee3b91647533ddf18d3c2dbd12e24c9fc62b05787da9efd00581d5095c507" )],
                            voteid="9d8c8caf-8665-46e7-8771-389fe26bff11"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"e0d24b76eede67639e0fca6a5cb6743ea01e772d5d40bf3cda35165483763dd8e0b59711517a4ef53110face022cc109e51192aeb4ed4f57a63d6ac7cde1a3cb" )],
                            voteid="05b79791-ff5e-4b69-8c45-0dbb59785504"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"3dd3ba4ed8b797597051892600fb00318e308056d775cc5bb8dd2a68fa349f78191d653471de81a2037dbcff1eb6472a1c82e6b3c678b6c035cf8b8e30957f33" )],
                            voteid="ca15e701-d6af-4560-aab1-11fb9161228d"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"d5c05952a5c3fb151149425ab8ff7e321143aa373ca79f84642356c6e217e7937b1809f992cf9034518cc2cba00eba014034dcd6f38b96c271d07fb06d33d54c" )],
                            voteid="826da20a-f5d8-49c0-bfee-baa74ebb3952"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"4e66ca9d1749da14d6df8d2cd4e1632facd832ce02d307a8bb3b57fc1dde35c68d2985986947e1b28dd1eb44c031d7c8a500fb54626552615f696d6f6f35880d" )],
                            voteid="58d2111b-fabe-4bc0-957c-e8ba6c3e0f5f"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"d000f93e6fbdbe015c983c5b5516011cf2ebf7c6721ad0989d7d6229daa3aff3953bd5c0439595a2073327ec20c3da38d1900ef8ad1246ce75d153dbb04b9bf2" )],
                            voteid="0be3c0b9-a4c8-4463-a9dd-d375ee8a335e"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"b0a7e6f903086b5683b0f6d6a93fd6b259a8c50cf6667d7535cb409b2298f7b91126cd65449b7efc6999ffa63dd17123f5871b821879983b7a711b8571cf7e38" )],
                            voteid="45f58121-03a3-42aa-a723-9e895a467fae"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"524e528aaa6a55f06d7ba0a9325d2055316689b9238850ce47aa205d26517fc7a15461b176b5c462f18beb6c4e5ce61c43c44cba4c1a522fca77bb469a745b26" )],
                            voteid="14deffd1-329f-44d5-93e5-aba896e866ef"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"de5acaa1fa2b8167930b91360e2e08c544c81846e5eb44e3342e46f7434aac2af8525b3abdd23270675b4bb41ada15d6b8776d20a0a3f9a02a39d7be8dcdeee4" )],
                            voteid="a3b5f3fe-e748-4adf-99bb-61daa1a776c2"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"26d373aec47b9d494f73743170ada8e78c0a6ff21eb1d73fb48fae0e5240be3139c55b11d4545aa92c49611f4512adaec79be6bfb5161fa7324caf8a406d3390" )],
                            voteid="451f32a6-1d5f-4fcb-b9ad-1818057bf8ad"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"e24b2f773ca8bddd0f7e73e4f7e420048b27fd2363a3ea00326b7bd492372058ddb1e14625ba4be421923bb94e511ff93edc286be852d5e3b39ca57f24df6319" )],
                            voteid="1a39221c-0e2e-496e-90e8-ab9fa486d728"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"26df5d33f0835bf3bfbefac746665cffba1550f4c57bfef58cee1677509690237b94b2f5ef8257c2bddfea02e4b52e687667ffad37a8837bb95d250fcf04d6bc" )],
                            voteid="b231a8e3-7c79-41d9-8b17-22fd5abb038d"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"582cb37d4c8e9ead633e00046a65468f818cc0d352dd30ffd800a00d4b17b0187ca328a9ac41d88c6ec4d1e36e9442d8cacf3f9a77fe10ce3f61aef5d336e621" )],
                            voteid="06a94e0f-508f-4b01-ba33-9621bb7cf1ba"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"b7467dc019f366929c7bda17cf8f846277ff1f7e4d3aae98f1203c9883627b6f6cd11a4edca15f5ecb601d324c577e6421740a1f63cadf369b13da7d7f6b3407" )],
                            voteid="215f66cd-9aa1-4569-bb2f-41d5ed81d47f"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"27bbcb5c490887ee615ac3abb91dfad11f870b7b512647ef5e0b3a48563c32e02eda8190070f891f7fd5cb12bd7f6576d351d51e30e306af3764056fcdfa0040" )],
                            voteid="e2b7e2c5-3975-479b-bc2a-65305b3bedb5"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"d13f9ba52eaffa72aae8a7a887a62005097b026d1d62934092bf660161d6bbd239ae3f04ea81662eb87abc81cd97e316ea96ad62613ed154bd4d0d625be676d0" )],
                            voteid="02432b9b-8677-4da4-9cb4-6eb0cf06aaf1"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"c2cf4ba10e2fa875e6c98b823749adc8a05ad9fb00199247a150322fdbf9df17afe5b8d87a72bf1409fd28a97d2b58536f4b97f99a78e87d932cad9f7ec0a97e" )],
                            voteid="3cc57372-6f4d-4a20-9e63-2f87550cbb1c"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"6fc5530426ee54ba0cb93abe7025922c81cb69727928a6f3b6afc6b2e7d54354f8aa7f986eb9e6d1509d649a2c05dcdf730c523f9fd51f4550187bbcf7d3e7db" )],
                            voteid="bc90bcdc-a33d-4866-b5e2-3527fb56934c"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"6f10885160dff73fd399bacec26d0f35e21b89c0aabf6b4d45d0ffc387b306bc742d17654e37065706c25fde164369063b54d84767d24f8ed14ed2bfb17cb5fc" )],
                            voteid="c38ab763-9bba-41da-a3ea-bd5160e30b88"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"d4fff0ed0f3585438d0bf625c072e30bf122c7a23146ae2e70e8dedd20b7a9ed6f6474310a55eccd1296ae280fe27dec5f3ee275e01a98da11ae0830463ab9a5" )],
                            voteid="bcc1d0d5-9f44-432a-9560-5f67721b2a09"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"6bdb0d5c8881242562ecfb441c00e97fb894b7fd1dedc1de0294e5b17c3d6f58ab4f0151ba00edf4aa1538e3b04d1336ee7b54a881aff42eba77696f9b1d3da0" )],
                            voteid="fb777be6-c2e7-43a7-a94e-ca84f4cf0e88"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"9ab62569382c2685bbc7a3af29067a2636e4dd9edd405435d2181a2b51b2165f175a1f91779224f9a9875cfe5424ad9ead757081156cefd7ddad8c0e0e44e275" )],
                            voteid="cfe44761-95e1-4fad-9f77-dd6ec529fefa"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"67beee4cb7325e5a9efe1aac8975065e2379113f49a488d0a9f02d2a7bb838179ecd8c8a081f036247296b0397579ba218f4748bac55cdf0b2697986640fe9c6" )],
                            voteid="c5638f6c-a54a-497a-b71a-3757fd65d8e1"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"adf7fcf07a3f5c49efce0d356007cbad19a0009d5a13a467f6fac9b1219ed44454b5fb200e22944510620b3c3c43c57b2ae4ed9b6a802d459e427239d40db680" )],
                            voteid="9c134e45-c03c-4811-b7b8-45adaaf6022d"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"13753079c6ca00750d0cd10bc3fc60f64f537919b836121491ae07b4641cac9ee60096fdecca833b3effe88f73d420d3a50280b509eeb22223962031f527a355" )],
                            voteid="e1f8dc05-4438-4b54-b368-eea27e6e156c"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"419009bb591c402b365efb03274292c42a3bbee49d899c060ad845a1f6a6ce3148e25ddede0a9732367b47dead20142bb245a1bc8cb84a4d54721f1a87bd337d" )],
                            voteid="0e8a38d1-804e-4374-8177-64c24c38dc57"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"7151bb7dffb119923aacd9bfbc4eb0b475cd4c4a98bbbf7ff1d149fe3a9a4443ce20f48d75f3a019268d24652e55828fbb2ffddc26b08069bccfcf3003c2c847" )],
                            voteid="0f6c543d-9b38-4991-ba4d-5d806c2b33d7"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"98486d144ebbad6ff304f26797004fe72c4248e4b8d6dbc1cae512cb3e95f6c769a8c232ada3dd10af9756692aaf57d65a94f2c27d6c27e2398fbe2db3fb51f6" )],
                            voteid="214b6679-4311-4395-b150-5d9c299f0a3b"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"8b2ae6335d8a9eaeef9affc61011e1b6d07752b5c6bc9f97b97180453964fe711a78210cc3b90992158a6d3773324e93877bd968f9bba960a31cec14391576fe" )],
                            voteid="74aee1ad-8098-47ce-8d68-ee74ca35026c"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"122915faad0c21ccd9a8520976a6b21f2a78fb93242c19917d2719de912a79a211af4d317e348933e2337e981a8d12b7e49ebbd5118bb691db0001963fe67db2" )],
                            voteid="7daecc3e-a0ad-4272-a274-ea3190f5ff0c"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"b34faab6dcf9f34925385d914faa7f70bceb786a6e8813ea2fb393919736999756fc0ab20a1912c77deda356143b95bfa330554fd314f88dc75ef888a6d3e1fe" )],
                            voteid="81cc50ec-e7e8-4a56-a60d-5e4b3f624117"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"6edcd14b8d2b2217292c329ae6f872307a8d90636dae572c703d826bfa653ad69bc88848ce133690f8d6a97f7c2dd8eb59a050cf28e9e286fe79c9221b4857c4" )],
                            voteid="e06ae2da-bc74-43a9-84dd-f4398deb0f69"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"6f59b2ac74e9a24c5b4fd1f1b2c8f10c70c2f52d20bf8321ebfcf0fcf72b700d3aea0e706bb32e3ff4458e70bc9dac5122212157b1d616694a2da751b7e6ea04" )],
                            voteid="fdad4e21-070c-4cbb-aa7c-80125bc117df"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"bb428ba146891c3f7bcb9353dca40765979822cc44f1262ef8b3b01ef00a4454b43d912f7715fd42c0c6fc91df1801b7f812be5856622a19869e4b24b84c4e1f" )],
                            voteid="82566d5d-38cf-41be-a17b-a448cdc1b42a"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"32fd2bccd218f3e50fc91926f39d68a51b9178db402bedf0203db0c73395557bdbf5dd88ec1cb9223de92973235b4595e4409deeb0fc4f4c3dc645c6aaec1556" )],
                            voteid="5a6147cb-ee33-4009-8d92-8f1dbaa522c7"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"4c3dc886f68d5d2ea144621880251a448405e55379b62b65d8d98d7e7e7ac56aba00162729068319998d7285f59bc05b6b1991e28874d555c31f198b5bdabe00" )],
                            voteid="8aa33e55-16e4-41c7-83e5-43ccb2a62b7e"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"c2f425ba34b20e7718be74abb0b7f78986a0d858d84918b72391fc7241d6160a75fa15aa01859c346c510238ac964343772b0f55e35dddb053f363e5c090637e" )],
                            voteid="d0c499a3-8b02-419b-92d3-041ef5c31bd1"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"247bc787a9b50fceb0f53fbdc9027a11240ecfd9563f0f8927ef29577710a5a42efa4e76ac18a1ac248e0ed6ccb7c11d256c8c02eb29f3750ab60bc3f45059a9" )],
                            voteid="e018a71f-d76a-4056-b646-d13810d59fbb"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"b0788343a74eb4bdc7c87eec53ff2311e499cfb443f2e2e3ebef7437a22c22f20a9d40f62faf54d17f821c47a64048558e08e4d9992e9e62c43b8bde251320bf" )],
                            voteid="2a437f02-2519-4b4c-a091-b19f1df0c773"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"a45d51b0a15444fe70852a9c179093ed81ca935b6ffb951d71c55099d115b2f0f48d24f4525e3080f49c4240e197a4a9078364de8b1a511934a1f1084742c4fc" )],
                            voteid="9c5bb059-448d-40cd-b74b-0252f144a061"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"e2bdf777b9c7563b228f7d0ff502ec19fc6f13d940fa4b47829dcc142408cb195835522b2667dca1f43d3895d8525654bfaf9748e099f39daf85e7602cb5d4ba" )],
                            voteid="fa1f2e57-ce86-4214-94c7-b0cfc2b4b151"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"e9a8d8098d5eb0fe2451ba5067fe7488f9dfdae073c662e915d1d122224e37582c9dab4f233a98d1336bbb77c39e45b85dd65e1edb6384d3f315c1e188885fb0" )],
                            voteid="b11a75c4-0031-4a63-ad1c-8fb3ac5ce63f"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"3611f794cdc4ad45ed3c45a889d3d6f16f892e51153859421c106f5f8b1de3081b50cd64db9d5e40f0f352cda454b010b21ed6f7189c7a2a340fb327aa1fdd93" )],
                            voteid="f16c2300-7d15-4418-9987-e6878a4cb772"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"5d24e2bb55fe951cc097ac34930a7c9a255d010e0b1f5bad383161b202cdab26b3785ffde4efa81dd9af63387d3c0cf53c997cc81e7d4356aa8506d92c3c60ac" )],
                            voteid="de829be6-5786-4ed6-8c47-ac7fe41394e9"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"7dc75bb2bba0e36d8380d2eac64a863c7d577379219146fd57ad0f75de05495d654f306897730f6aa3d43f6f7b21fb9dd05f1f93e061a85a59a9838eb49a66f8" )],
                            voteid="d839905e-d88a-4034-98cf-653716944335"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"5530834a170e305febfb9c85e38e351f7980f2e932dd59eced02608e0964109cb552ac388c705ef820720cb9f9f25f61cea03b0b73dd6acc9e6db228f8fbfd30" )],
                            voteid="cca6cb6b-0629-4748-9cb5-cd9016c54b2b"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"7903a3a17611fa2cce90cd3dbda152769c5c9ef7b1c76558b918007d29bc40b21dfc20b1cce5816397ee440974ea4f04e4c3e77804f4cdd33debb6eadb3ca514" )],
                            voteid="9dd3de0d-299c-4b28-832b-3218544a74c1"
                    ),
                    Vote( 
                            transfers=[Transfer(None,"610aada1a97ef484f0e7192c5a621d26684a9ed0a7c49f3ec6b2102a65cb9b0de87c93096c0698ed5608f6bae77676e8d376df8affe01a696178938804ada5e7" )],
                            voteid="e55de250-ae64-4526-b8a7-4d2269229264"
                    )
        ]

        block = Block(
                    timestamp = 1604497751.2164383,
                    votes = votes,
                    signature = "24258ac099402b03677b6f402f9526c892f14a55476cdd98b79aeb1be6922b516bed040d0dc6e1f4fa151bc65519e3a41c6fd893d7a37e58078d83f585f9a87b",
                    prev_sig = None,
                )
        block.parties = {
                "X": "50536b106fb153aaefeb7e87c932ed809c6e991dcda08c6cd149bc8379496c5fac82038ee9c3af49a0350e2e1fe0e1dc437a432d1dbd0f5b5cd52f877e7483e7",
                "Y": "5a8a5652ac4e2d48f464dcc0b32b7daa27c5a4e843cea80db282e5d0a2d882bd2c8e0c62ea7e4aed7db7621ee90ce5be9ce57342f4cfd9fabdcb7f72f1108eb8",
                }
        block.committees = {
                "Krakow": "49e642a989a2c7352373e23d624ca1a1794f865c0a331790e67261427f0f226ab9495c09d76d3c7cb6486c291ceef0109b0eeea89ecdaf14f10dba1098a587d9",
                "Warszawa": "9f229d18ba0386d1bbf9c5b8298c3ae05dfc85ca24b42e72c48a341c9792e52faa3797e468bcbb873f5123e88d4e7ac824732473f99fa9eb0d576df54574c420",
                }
        for vote in block.votes:
            self.votes[vote.id] = deepcopy(vote)
        self.blocks.append(block)
        self.save_block()
        
    #Save the last block
    def save_block(self):
        last_block = self.blocks[-1]
        block_height = self.blocks.index(last_block)
        filename = f"data/{block_height}.votechain"
        to_disk(last_block, filename)

    # Get the signature of other peer's latest block
    # Return every block that is after that block
    def sync_request(self, top_block_sig):
        to_sync = []
        for block in self.blocks[::-1]:
            if block.signature == top_block_sig:
                break
            to_sync.append(block)
        return to_sync[::-1]
    
    def handle_sync(self, blocks):
        for block in blocks:
            self.handle_block(block)
    

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
        output += f'Timestamp: {datetime.fromtimestamp(self.timestamp)}\n'
        if self.signature == None:
            output += f'Signature: {self.signature}\n'
        else:
            short_sig = self.signature[0:4] +"..."+ self.signature[-5:]
            output += f'Signature: {short_sig}\n'
        if self.prev_sig == None:
            output += f'Prev_signature: {self.prev_sig}\n'
        else:
            short_prev_sig = self.prev_sig[0:4] +"..."+ self.prev_sig[-5:]
            output += f'Prev_signature: {short_prev_sig}\n'
        output += '=======================\n'
        return output
    
    @property
    def message(self):
        data = [self.votes, self.timestamp, self.prev_sig]
        return serialize(data)

    def sign(self, private_key):
        signature = to_hex( privkey_from_hex(private_key).sign(self.message) )
        self.signature = signature


# Send the sync message to the public nodes every 5 seconds
# A hacky way if you dont want to mess with firewalls and NATs
def send_sync():
    global committee
    while True:
        random_node = random.choice(committee.peers)
        blocks_sync = send_message((random_node, PORT), "sync", committee.blocks[-1].signature, True)
        for missing_block in blocks_sync["data"]:
            signature = missing_block.signature[:4] + "..." + missing_block.signature[-5:]
            committee.handle_block(missing_block)
        time.sleep(10)


def get_my_ip():
    my_ip = requests.get(MY_IP_LINK).text
    logger.info(f"My IP is {my_ip}")
    return my_ip

# Get the public peers list and filter it
def get_public_peers():
    my_ip = get_my_ip() 
    peers_request = requests.get(PEERS_LIST).text
    peers = []
    for ip in peers_request.split(";"):
        if ip != "" and ip != my_ip:
            peers.append(ip)
    return peers

# Run the software with GUI as a private node
def case_voter():
    print("=" * 20)
    # Generate my private key
    keypair = create_keypair(input("Input your email address: "))
    print("Your private key:\t {}".format(short_key(keypair[0])))
    print("Your public key:\t {}".format(short_key(keypair[1])))

    address = (get_my_ip(), PORT)

    peers = get_public_peers()
    logger.info(f"Found {len(peers)} peers: {peers}")

    global committee

    committee = Committee(keypair[0], keypair[1], address)
    committee.peers = peers
    
    syncing_thread = threading.Thread(target=send_sync)
    syncing_thread.daemon = True
    syncing_thread.start()

    while True:
        print("=" * 20)
        print("Menu:")
        print("1) Check your balance")
        print("2) Check balance of someone else")
        print("3) Send to")
        print("4) Fetch block")
        print("5) Fetch vote")
        print("=" * 20)

        option = input("What's your choice: ")
        try:
            option = int(option)
        except:
            print("Invalid option!")
            continue
        #Check your balance
        if option == 1:
            balance = committee.fetch_balance( keypair[1]  )
            print("Your balance is: {}".format(len(balance)))
            for vote in balance:
                print(vote)
        #Check the balance of someone else
        elif option == 2:
            pubkey = input("Input the public key: ")
            balance = committee.fetch_balance(pubkey)
            print("His balance is: {}".format(len(balance)))
            for vote in balance:
                print(vote)
        #Send to
        elif option == 3:
            pubkey = create_keypair(input("Input the public key: "))[1]
            my_balance = committee.fetch_balance( keypair[1]  )
            if len(my_balance) == 0:
                print("You do not have enough votes!")
                continue
            my_vote = my_balance[0]
            my_vote.sign_transfer(keypair[0], pubkey)
            print(my_vote)
            committee.validate_vote(my_vote)
            random_node = random.choice(committee.peers)
            send_message((random_node, PORT), "send-vote", my_vote)
        #Fetch block
        elif option == 4:
            print("Current height: {}".format( len(committee.blocks) ))
            blockNR = int(input("What's the block nr: "))
            block = committee.fetch_block(blockNR)
            print(block)
        #Fetch vote
        elif option == 5:
            voteID = input("What's the vote id: ")
            vote = committee.fetch_vote(voteID)
            print(vote)
        else:
            print("Invalid option")
            continue


def serve():
    logger.info("Started server")
    server = socketserver.TCPServer(("0.0.0.0", PORT), TCPHandler)
    server.serve_forever()


# Run the software as a public node in terminal
def case_committee():
    global committee

    my_ip = get_my_ip() 

    generator = input("Input your generator: ")
    keypair = create_keypair(generator)
    committee = Committee(keypair[0], keypair[1], (my_ip, PORT))
    logger.info(f"Started as -> {short_key(keypair[1])}")

    # Add your ip to the peers-list
    requests.get(ADD_YOUR_PEER)

    peers = get_public_peers()
    logger.info(f"Found {len(peers)} peers: {peers}")

    #Connect to other peers
    logger.info("Found peers: ({})".format( peers ))
    committee.peers = peers
    
    # Perform an initial sync upon node startup
    for peer in committee.peers: 
        # Ask for new blocks
        try:
            blocks_sync = send_message((peer, PORT), "sync", committee.blocks[-1].signature, True)
            for missing_block in blocks_sync["data"]:
                committee.handle_block(missing_block, schedule=False)
        except:
            pass

        # Ask for other peers
        try:
            other_peers = send_message((peer, PORT), "peers", committee.peers, True)
            committee.new_peers(other_peers["data"])
        except:
            pass
            
    # Finally, after the node is synced and ready, start producing blocks yourself and serving requests
    committee.schedule_next_block()

    # Start server thread
    server_thread = threading.Thread(target=serve, name="server")
    server_thread.start()


if __name__ == "__main__":
    # Create the 'data' folder if it doesn't exist
    if os.path.isdir('data') == False:
        try:
            os.mkdir('data')
        except:
            print("Error while creating \'data\' directory")
            sys.exit(1)

    if len(sys.argv) == 1:
        case_voter()
    else:
        case_committee()
