from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError
from chain import Chain
from block import Block
from transaction import Tx

#Create keys
bob_private_key = SigningKey.generate(curve=SECP256k1)
bob_public_key = bob_private_key.get_verifying_key()

alice_private_key = SigningKey.generate(curve=SECP256k1)
alice_public_key = alice_private_key.get_verifying_key()


chain = Chain(bob_public_key)
print(chain)

bob_to_alice = Tx(alice_public_key, bob_public_key, 100)
print(bob_to_alice)

bob_to_alice.sign(bob_private_key)
print(bob_to_alice)

chain.get_block_info(0)
