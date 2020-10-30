import sys 
import utils
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import randrange_from_seed__trytryagain

# Generates (privkey, pubkey) pair
# Returns a tuple
def create_keypair(generator):
    secexp = randrange_from_seed__trytryagain(generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return (private_key, public_key)


pubkeys = {}
privkeys = {}
for i in range(int(sys.argv[1])): 
    name = input("Whats the name of the committee no. {}: ".format(i+1))
    password = input("What's the keypair generator? ")
    keypair = create_keypair(password)
    privkeys[name] = keypair[0]
    pubkeys[name] = keypair[1]


print("=" * 20)
print(" === Private keys ===")
for item in privkeys:
    keys = privkeys[item].to_string().hex()
    print(f'{item: <15} {keys}')

print("=" * 20)
print(" === Public keys ===")
for item in pubkeys:
    keys = pubkeys[item].to_string().hex()
    print(f'{item: <15} {keys}')

#Save only the public keys, use generators for private keys
utils.to_disk(pubkeys, "committees.votechain")

print("Successfully generated {} committees".format(sys.argv[1]))


