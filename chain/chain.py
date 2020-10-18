from block import Block

class Chain:
    blocks = []

    def __init__(self):
        genesis_block = Block("genesis_block", 0, 0, [])
        self.blocks.append(genesis_block)

    def __str__(self):
        return "The chain has {} blocks".format(len(self.blocks))

    def push_block(self, block):
        #TODO validate the block
        self.blocks.append(block)

    def get_block_info(self, height):
        return print(self.blocks[height])



