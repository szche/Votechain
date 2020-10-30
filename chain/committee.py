from . import utils
from .transfer import Transfer
from .vote import Vote
from copy import deepcopy
from .keys import *
from .block import Block

class Committee:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        # Cached votes
        self.votes = {}
        # Blocks in the history
        self.blocks = []
        # Votes waiting to be validated
        self.mempool = []
        #Create genesis block
        self.genesis_block()


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
        
    # Check if this vote is valid and built on top of the existing vote
    # If that is the case, update the state of the vote
    # i.e. put the voting ticket in the ballot box
    def update_cached_votes(self, vote):
        last_observation = self.votes[vote.id]
        last_observation_length = len(last_observation.transfers)
        assert last_observation.transfers == vote.transfers[:last_observation_length]
        self.votes[vote.id] = deepcopy(vote)

    @property
    def next_committee_turn(self):
        blocks = len(self.blocks)
        turns = self.blocks[0].turns
        return turns[blocks % len(turns)]
        

    def handle_block(self, block):
        #Verify committee signature (Skip the genesis block)
        if len(self.blocks) > 0:
            public_key = self.next_committee_turn
            public_key.verify(block.signature, block.message)
        
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
        print("all good")


    def schedule_next_block(self):
        #TODO
        pass

    #Issue the first block
    def genesis_block(self):
        assert len(self.blocks) == 0
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
        block = Block([votes])
        #Add the authorized committee's pubkeys
        committee_public_keys = utils.from_disk("voting_kit/committee_pubkeys.votechain")
        turns = [pubkey for pubkey in committee_public_keys.values()]
        block.turns = turns
        self.blocks.append(block)
