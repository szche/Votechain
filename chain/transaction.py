
class Tx:
    def __init__(self, to, sender, amount, timestamp):
        self.to = to
        self.sender = sender
        self.amount = amount
        self.timestamp = timestamp

    def create_coinbase(self, to, timestamp):
        #TODO create coinbase transaction
        pass

    def sign(self, private_key):
        #TODO sign the transaction
        pass

    def validate(self):
        #TODO validate the tx
        pass

    def broadcast(self):
        #TODO broadcast the tx
        pass
