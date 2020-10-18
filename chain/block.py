
class Block:
    def __init__(self, block_hash, height, nonce, txs):
        self.hash = block_hash
        self.height = height
        self.nonce = nonce
        self.txs = txs

    def __str__(self):
        return "Block\tnr: {}\n\thash: {}\n\tTransactions: {}".format(self.height, self.hash, len(self.txs))

    def validate(self):
        #TODO validate the block and txs
        pass

    def mine(self):
       #TODO main the block
       pass
