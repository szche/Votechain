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
        self.votes = {}

    # Issue a 'voting ticket' by a Committee to a voter
    def issue(self, public_key):
        message = utils.serialize(public_key) 
        signature = self.private_key.sign(message)
        transfer = Transfer(signature, public_key)
        vote = Vote([transfer])
        # After creating a valid vote, add it to the votes index
        self.votes[vote.id] = deepcopy(vote)
        return vote

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
    def cast_vote(self, vote):
        last_observation = self.votes[vote.id]
        last_observation_length = len(last_observation.transfers)
        assert last_observation.transfers == vote.transfers[:last_observation_length]
        self.validate_vote(vote)
        self.votes[vote.id] = deepcopy(vote)

    # TODO
    def broadcast_block(self, block):
        pass

    # TODO 
    def validate_block(self, block):
        for vote in block:
            self.validate_vote(vote)

    def update_from_block(self, block):
        self.validate_block(block)
        #TODO update the "votes database" to reflect changes made in block

    def sign_block_hash(self, block):
        pass



