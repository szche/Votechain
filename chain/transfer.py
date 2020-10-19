class Transfer:
    def __init__(self, signature, public_key):
        self.signature = signature
        self.public_key = public_key

    def __eq__(self, other):
        return self.signature == other.signature and \
                self.public_key.to_string() == other.public_key.to_string()
