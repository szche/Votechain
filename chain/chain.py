from block import Block

class Chain:
    blocks = []
    def __init__(self, issuer_pubkey):
        genesis_block = Block("genesis_block", 0, 0, [])
        self.blocks.append(genesis_block)
        self._issuer = issuer_pubkey

    def __str__(self):
        return "The chain:\n\tIssuer: {}\n\tBlocks: {}".format(self._issuer ,len(self.blocks))

    def push_block(self, block):
        #TODO validate the block
        self.blocks.append(block)

    def get_block_info(self, height):
        return print(self.blocks[height])



