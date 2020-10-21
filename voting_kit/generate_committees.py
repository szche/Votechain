import sys 
import utils
from ecdsa import SigningKey, VerifyingKey, SECP256k1

pubkeys = {}
privkeys = {}
for i in range(int(sys.argv[1])): 
    name = input("Whats the name of the committee no. {}: ".format(i+1))
    com_privkey = SigningKey.generate(curve=SECP256k1)
    com_pubkey = com_privkey.get_verifying_key()
    pubkeys[name] = com_pubkey
    privkeys[name] = com_privkey

utils.to_disk(pubkeys, "committee_pubkeys.votechain")
utils.to_disk(privkeys, "committee_privkeys.votechain")

print("Successfully generated {} committees".format(sys.argv[1]))


