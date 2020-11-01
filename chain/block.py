#from . import Vote, utils
from .vote import Vote
from . import serialize 
import time
#from . import utils

class Block:
    def __init__(self, votes, timestamp=None, signature=None, prev_sig=None):
        if timestamp == None:
            timestamp = time.time()
        self.timestamp = timestamp
        self.signature = signature
        self.votes = votes
        self.prev_sig = prev_sig

    def __str__(self):
        output = ""
        output += '======== Block ========\n'
        output += f'Txs: {len(self.votes)}\n'
        output += f'Timestamp: {self.timestamp}\n'
        if self.signature == None:
            output += f'Signature: {self.signature}\n'
        else:
            output += f'Signature: {self.signature.hex()}\n'
        if self.prev_sig == None:
            output += f'Prev_signature: {self.prev_sig}\n'
        else:
            output += f'Prev_signature: {self.prev_sig.hex()}\n'
        output += '=======================\n'
        return output
    
    @property
    def message(self):
        data = [self.votes, self.timestamp, self.prev_sig, ]
        return serialize(data)

    def sign(self, private_key):
        self.signature = private_key.sign(self.message)



        

        

    
