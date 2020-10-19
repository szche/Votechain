from uuid import uuid4
import utils
from keys import pkw_private_key, pkw_public_key
from transfer import Transfer

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
