from chain import Chain
from datetime import datetime

class Tx:
    def __init__(self, to, sender, amount):
        self.to = to
        self.sender = sender 
        self.amount = amount
        self.timestamp = datetime.timestamp( datetime.now() )
        self.signature = None
        
    def __str__(self):
        return "==========\nTx\n\tfrom: {}\n\tto: {}\n\tamount: {}\n\ttimestamp: {}\n\tSignature: {}\n==========".format(self.sender, self.to, self.amount, self.timestamp, self.signature)

    def create_coinbase(self, to, timestamp):
        #TODO create coinbase transaction
        pass

    def sign(self, private_key):
        #TODO sign the transaction
        if self.sender != private_key.get_verifying_key():
            print("Wrong private key!")
            return
        self.signature = "Signed"

    def verify(self):
        #TODO validate the tx
        pass

    def broadcast(self):
        #TODO broadcast the tx
        pass
