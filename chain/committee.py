import utils
from transfer import Transfer
from vote import Vote
from copy import deepcopy

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

    # Loop through the votes and check if the public_key of the coin matches the argument
    def fetch_vote(self, public_key):
        votes = []
        for vote in self.votes.values():
            if vote.transfers[-1].public_key.to_string() == public_key.to_string():
                votes.append(vote)
        return votes

    def observe_vote(self, vote):
        last_observation = self.votes[vote.id]
        last_observation_length = len(last_observation.transfers)
        assert last_observation.transfers == vote.transfers[:last_observation_length]
        vote.validate()
        self.votes[vote.id] = deepcopy(vote)

