from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError
import utils

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
    if public_key == pkw_public_key:
        return "PKW"
    elif public_key == alice_public_key:
        return "Alice"
    elif public_key == bob_public_key:
        return "Bob"
    

class Transfer:
    def __init__(self, signature, public_key):
        self.signature = signature
        self.public_key = public_key


class Vote:
    def __init__(self, transfers):
        self.transfers = transfers

    #Validate that the vote is valid
    def validate(self):
        # Get the first transfer and validate it - should be issued by the PKW
        first_transfer = self.transfers[0]
        message = utils.serialize(first_transfer.public_key)
        try:
            pkw_public_key.verify(first_transfer.signature, message)
        except BadSignatureError:
            return False
        # Get the rest of transfers (if the voters gives away his vote to someone else)
        previous_transfer = first_transfer
        for next_transfer in self.transfers[1::]:
            message = transfer_message(previous_transfer.signature, next_transfer.public_key) 
            try:
                previous_transfer.public_key.verify(next_transfer.signature, message)
            except BadSignatureError:
                return False
            previous_transfer = next_transfer
        return True
   
    # Return who is currently owning this vote
    def owner(self):
        public_key = self.transfers[-1].public_key
        return get_owner(public_key)

    # Send this vote to someone else
    def send(self, owner_private_key, recipient_public_key):
        message = transfer_message(self.transfers[-1].signature, recipient_public_key)
        signature = owner_private_key.sign(message)
        vote_transfer = Transfer(signature, recipient_public_key)
        self.transfers.append(vote_transfer)

    # Show the history of this vote
    def list_transfers(self):
        print("PKW ", end="")
        for transfer in self.transfers:
            print("-> {} ".format( get_owner(transfer.public_key) ), end="")



def transfer_message(previous_signature, next_owner_public_key):
    message = {
            "previous_signature": previous_signature,
            "next_owner_public_key": next_owner_public_key
    }
    return utils.serialize(message)

# Issue a 'voting ticket' by a PKW to a voter
def issue(public_key):
    message = utils.serialize(public_key) 
    signature = pkw_private_key.sign(message)
    transfer = Transfer(signature, public_key)
    vote = Vote([transfer])
    return vote

# Give a vote to alice and verify it
vote = issue(alice_public_key)
print("This vote is owned by: {}".format(vote.owner()))
print("\t\t\tis vote valid? {}".format(vote.validate()))

# ==================================================================
# Bob fakes his vote, should return error 
bob_message = utils.serialize(bob_public_key)
bob_signature = bob_private_key.sign(bob_message)
bob_transfer = Transfer(bob_signature, bob_public_key)
bob_vote = Vote([bob_transfer])
#print("Is bob's fake vote valid? -> {}".format(bob_vote.validate()))
# ==================================================================


# Now let's pass the alice's vote to bob
vote.send(alice_private_key, bob_public_key)
print("This vote is owned by: {}".format(vote.owner()))
print("\t\t\tis vote valid? {}".format(vote.validate()))

# Now the PKW gets it
vote.send(bob_private_key, pkw_public_key)
print("This vote is owned by: {}".format(vote.owner()))
print("\t\t\tis vote valid? {}".format(vote.validate()))

# Check the history of the vote
vote.list_transfers()
