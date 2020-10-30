from .vote import Vote
from .keys import *
import time
from . import utils

class Block:
    def __init__(self, votes, timestamp=None, signature=None):
        if timestamp == None:
            timestamp = time.time()
        self.timestamp = timestamp
        self.signature = signature
        self.votes = votes

    def __str__(self):
        output = ""
        output += '======== Block ========\n'
        output += f'Txs: {len(self.votes)}\n'
        output += f'Timestamp: {self.timestamp}\n'
        if self.signature == None:
            output += f'Signature: {self.signature}\n'
        else:
            output += f'Signature: {self.signature.hex()}\n'
        output += '=======================\n'
        return output
    
    @property
    def message(self):
        data = [self.votes, self.timestamp]
        return utils.serialize(data)

    def sign(self, private_key):
        self.signature = private_key.sign(self.message)



        

        

    
