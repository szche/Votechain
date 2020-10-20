from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError
import utils

#Create PKW keys
pkw_private_key = SigningKey.generate(curve=SECP256k1)
pkw_public_key = pkw_private_key.get_verifying_key()


#Some voters
alice_private_key = SigningKey.generate(curve=SECP256k1)
alice_public_key = alice_private_key.get_verifying_key()

bob_private_key = SigningKey.generate(curve=SECP256k1)
bob_public_key = bob_private_key.get_verifying_key()

# Return public key of the current vote owner
# For debugging purposes only - HUGE privacy issue
def get_owner(public_key):
    database = {
        utils.serialize(pkw_public_key): "PKW",
        utils.serialize(alice_public_key): "Alice",
        utils.serialize(bob_public_key): "Bob",
    }
    return database[utils.serialize(public_key)]

