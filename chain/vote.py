from uuid import uuid4
from .transfer import Transfer
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError

class Vote:
    def __init__(self, transfers):
        self.transfers = transfers
        self.id = uuid4() # <- random and unique Vote id, used to check for duplicates

    def __eq__(self, other):
        return self.id == other.id and \
                self.transfers == other.transfers

    # Sign the transfer, but dont show it to the Committee yet!
    def sign_transfer(self, owner_private_key, recipient_public_key):
        # Assert that you're the owner
        assert self.transfers[-1].public_key.to_string()== owner_private_key.get_verifying_key().to_string()
        message = transfer_message(self.transfers[-1].signature, recipient_public_key)
        signature = owner_private_key.sign(message)
        vote_transfer = Transfer(signature, recipient_public_key)
        self.transfers.append(vote_transfer)




