from .vote import Vote
from .keys import *

class Block:
    def __init__(self, committee_pubkey, prev_hash):
        self.committee_pubkey = committee_pubkey
        self.votes = []
        self.prev_hash = prev_hash
        self.merkle_root = None

    def add_vote(self, vote):
        # Dont add the same vote more than once
        assert vote not in self.votes
        # Assert the vote is valid
        # TODO
        self.votes.append(vote)

    # TODO
    def get_merkle_root(self):
        pass

    # TODO
    def get_hash(self):
        hash_data = [self.prev_hash, self.merkle_root, self.committee_pubkey]
        pass


    
