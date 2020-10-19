from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError
import utils
from copy import deepcopy
from uuid import uuid4

#Create PKW keys
pkw_private_key = SigningKey.generate(curve=SECP256k1)
pkw_public_key = pkw_private_key.get_verifying_key()

#Some voters
alice_private_key = SigningKey.generate(curve=SECP256k1)
alice_public_key = alice_private_key.get_verifying_key()

bob_private_key = SigningKey.generate(curve=SECP256k1)
bob_public_key = bob_private_key.get_verifying_key()

# Return public key of the current vote owner
def get_owner(public_key):
    database = {
        utils.serialize(pkw_public_key): "PKW",
        utils.serialize(alice_public_key): "Alice",
        utils.serialize(bob_public_key): "Bob",
    }
    return database[utils.serialize(public_key)]

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

    

class Transfer:
    def __init__(self, signature, public_key):
        self.signature = signature
        self.public_key = public_key

    def __eq__(self, other):
        return self.signature == other.signature and \
                self.public_key.to_string() == other.public_key.to_string()

class Vote:
    def __init__(self, transfers):
        self.transfers = transfers
        self.id = uuid4()
        self.validate()

    def __eq__(self, other):
        return self.id == other.id and \
                self.transfers == other.transfers

    #Validate that the vote is valid
    def validate(self):
        # Get the first transfer and validate it - should be issued by the PKW
        first_transfer = self.transfers[0]
        message = utils.serialize(first_transfer.public_key)
        assert pkw_public_key.verify(first_transfer.signature, message)
        # Get the rest of transfers (if the voters gives away his vote to someone else)
        previous_transfer = first_transfer
        for next_transfer in self.transfers[1::]:
            message = transfer_message(previous_transfer.signature, next_transfer.public_key) 
            assert previous_transfer.public_key.verify(next_transfer.signature, message)
            previous_transfer = next_transfer
   
    # Return who is currently owning this vote
    def owner(self):
        public_key = self.transfers[-1].public_key
        return get_owner(public_key)

    # Send this vote to someone else
    def send(self, owner_private_key, recipient_public_key):
        assert self.transfers[-1].public_key == owner_private_key.get_verifying_key()
        message = transfer_message(self.transfers[-1].signature, recipient_public_key)
        signature = owner_private_key.sign(message)
        vote_transfer = Transfer(signature, recipient_public_key)
        self.transfers.append(vote_transfer)

    # Show the history of this vote
    def list_transfers(self):
        print("PKW ", end="")
        for transfer in self.transfers:
            print("-> {} ".format( get_owner(transfer.public_key) ), end="")
        print("")

    def __str__(self):
        return "Vote id: {}\nOwner: {}".format(self.id, self.owner())



def transfer_message(previous_signature, next_owner_public_key):
    message = {
            "previous_signature": previous_signature,
            "next_owner_public_key": next_owner_public_key
    }
    return utils.serialize(message)



# Test scenario 1:
# PKW gives alice the 'voting ticket', she forwards it to Bob and he sends it back to PKW
# In the meantime, Bob tries to create his own 'voting ticket' out of thin air but fails to do so
def test_scenario1():
    committee = Committee(pkw_private_key, pkw_public_key)
    # Give a vote to alice and verify it
    vote = committee.issue(alice_public_key)
    print("This vote is owned by: {}".format(vote.owner()))
    # Now let's pass the alice's vote to bob
    vote.send(alice_private_key, bob_public_key)
    print("This vote is owned by: {}".format(vote.owner()))
    # Now the PKW gets it
    vote.send(bob_private_key, pkw_public_key)
    print("This vote is owned by: {}".format(vote.owner()))
    # Check the history of the vote
    vote.list_transfers()

    # ==================================================================
    # Bob fakes his vote, should return error 
    bob_message = utils.serialize(bob_public_key)
    bob_signature = bob_private_key.sign(bob_message)
    bob_transfer = Transfer(bob_signature, bob_public_key)
    try:
        bob_vote = Vote([bob_transfer])
    except:
        print("=== Bob's vote is invalid! ===")
    # ==================================================================

# Test scenario 2:
#
#
def test_scenario2():
    # Create a voting comittee
    committee = Committee(pkw_private_key, pkw_public_key)
    # Give Alice 2 votes and Bob 1 vote
    vote = committee.issue(alice_public_key)
    vote2 = committee.issue(bob_public_key)
    vote3 = committee.issue(alice_public_key)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))
    print("-" * 20)

    # Create a sending commitment
    vote3.send(alice_private_key, bob_public_key)
    # Update the Committee's voting database
    committee.observe_vote(vote3)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))

    # Now try to send that same vote again, should fail
    try:
        vote3.send(alice_private_key, bob_public_key)
        committee.observe_vote(vote3)
    except:
        print("Cannot send this vote! It's not yours")
        print("-" * 20)

    # Finally, Bob send the vote back to alice
    vote3.send(bob_private_key, alice_public_key)
    committee.observe_vote(vote3)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))


if __name__ == "__main__":
    # Run Test scenario 1
    #test_scenario1()

    # Run Test scenatio 2
    test_scenario2()

