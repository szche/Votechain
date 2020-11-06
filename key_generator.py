from chain.keys import *
from chain.utils import to_disk

privkeys = []
with open("data.txt", "r") as file1:
    privkeys = [line.strip() for line in file1]


pubkeys = []
for priv_generator in privkeys:
    secexp = randrange_from_seed__trytryagain(priv_generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    print("Public key for {} is:\t {}".format(priv_generator, short_key(public_key)))
    pubkeys.append(public_key)
    to_disk(pubkeys, "airdrop.votechain")






