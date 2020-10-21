from uuid import uuid4
import utils
from keys import *
from transfer import Transfer

class Vote:
    def __init__(self, transfers):
        self.transfers = transfers
        self.id = uuid4() # <- random and unique Vote id, used to check for duplicates

    def __eq__(self, other):
        return self.id == other.id and \
                self.transfers == other.transfers

    # Sign the transfer, but dont show it to the Committee yet!
    def sign_transfer(self, owner_private_key, recipient_public_key):
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



