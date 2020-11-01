from . import utils
from .transfer import Transfer
from .vote import Vote
from copy import deepcopy
from .keys import *
from .block import Block
import os, threading
import logging
#from .network import *
import time



import socketserver, socket
#import logging
#from . import utils

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





class Committee:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.votes = {}     # Cached most recent versions of the votes (unspent UTXOS)
        self.blocks = []    # The chain
        # Votes waiting to be validated
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
        issue_transfer = vote.transfers[0]
        issue_message = utils.serialize(issue_transfer.public_key)
        assert self.public_key.verify(issue_transfer.signature, issue_message)
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
        logger.info("Handling the block...")
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
            self.mempool.remove(vote)

        #Update self.blocks
        self.blocks.append(block)

        #Schedule next block
        self.schedule_next_block()

        #Save the accepted block
        self.save_block()
        logger.info("Block successfully added to the chain")

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
            logger.info(f"It's my turn")
            time.sleep(5)
            logger.info("Woke up")
            threading.Timer(15, self.submit_block()).start()

    # Get the information from the genesis block
    def genesis_block(self):
        assert len(self.blocks) == 0
        """
        # Issue the votes to the voters
        issue_votes = utils.from_disk("airdrop.votechain")
        votes = []
        for voter_pubkey in issue_votes:
            transfer = Transfer("", voter_pubkey)
            vote = Vote([transfer]) 
            votes.append(vote)

        for vote in votes:
            self.votes[vote.id] = deepcopy(vote)

        #Update self.blocks
        #block = Block([votes])
        block = Block(
                votes=votes,
                timestamp=1604069368.4400604,
                signature=b"\x08L]\xd5\x04>\xb0F\x07?)[\xbbq\t\x9b\xad}H(\xd8\xb3mh\xabe'\xc2O\x1a\xf0A\xbe\x18\xacG\xea\xa7[\xd4\xd8P\xdbM\r\xbb\xdc\xaf\xde144f\xafI\xc45\x83.\x8d8\xaf\xc0\x01")
        #Add the authorized committee's pubkeys
        auth_committees = utils.from_disk("voting_kit/committees.votechain")
        turns = [ (name, auth_committees[name]) for name in auth_committees] 
        block.turns = turns

        #Add the parties pubkeys
        block.parties = {}
        parties_pubkeys = utils.from_disk("voting_kit/parties.votechain")
        for party in parties_pubkeys:
            block.parties[party] = parties_pubkeys[party]

        self.blocks.append(block)
        self.save_block()
        """
        block = utils.from_disk("data/0.votechain")
        for vote in block.votes:
            self.votes[vote.id] = deepcopy(vote)
        self.blocks.append(block)
        
    #Save the last block
    def save_block(self):
        last_block = self.blocks[-1]
        block_height = self.blocks.index(last_block)
        filename = f"data/{block_height}.votechain"
        utils.to_disk(last_block, filename)
