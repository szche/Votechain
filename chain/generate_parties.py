import utils
import sys 
from ecdsa import SigningKey, VerifyingKey, SECP256k1


parties_pubkeys = {}
parties_privkeys = {}

for i in range(int(sys.argv[1])):
    name = input("Whats the name of the party no. {}: ".format(i+1))
    party_privkey = SigningKey.generate(curve=SECP256k1)
    party_pubkey = party_privkey.get_verifying_key()
    parties_pubkeys[name] = party_pubkey
    parties_privkeys[name] = party_privkey

utils.to_disk(parties_pubkeys, "parties_pubkeys.votechain")
utils.to_disk(parties_privkeys, "parties_privkeys.votechain")
print("Successfully generated {} parties".format(sys.argv[1]))

    
