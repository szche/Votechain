from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError
from ecdsa.util import randrange_from_seed__trytryagain
from . import utils
import os

# Return shorter version of the key
def short_key(public_key):
    public_key_hex = public_key.to_string().hex()
    return f"{public_key_hex[0:4]}...{public_key_hex[-5:]}"

# Prepare a sending commitment
# i.e. tick the box on your voting ticket but dont put it in the ballot box yet
def transfer_message(previous_signature, next_owner_public_key):
    message = {
            "previous_signature": previous_signature,
            "next_owner_public_key": next_owner_public_key
    }
    return utils.serialize(message)


print("-" * 10)
# Get the authorized committee public key list
committee_public_keys = utils.from_disk("voting_kit/committee_pubkeys.votechain")
for committee in committee_public_keys:
    print("Committee {} with public key {}".format( committee, short_key(committee_public_keys[committee]) ))

#Get committee private keys - debugging purposes only
committee_private_keys = utils.from_disk("voting_kit/committee_privkeys.votechain")
committee = {
        "name": "Krakow",
        "privkey": committee_private_keys["Krakow"],
        "pubkey": committee_public_keys["Krakow"]
}

print("-" * 10)
# Get the political parties public key list
parties_public_keys = utils.from_disk("voting_kit/parties_pubkeys.votechain")
for party in parties_public_keys:
    print("Party {} with public key {}".format( party, short_key(parties_public_keys[party]) ))
print("-" * 10)


