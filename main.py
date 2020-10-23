import chain.utils 
from chain.transfer import Transfer
from chain.committee import Committee
from chain.vote import Vote
from chain.keys import * 

def case_voter():
    # Generate private key
    #privkey_generator = input("Input your album number: ")
    privkey_generator = 1234
    secexp = randrange_from_seed__trytryagain(privkey_generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    print("Your private key:\t {}".format(short_key(private_key)))
    print("Your public key:\t {}".format(short_key(public_key)))

    print("-" * 20)
    print("Committee {}".format(committee["name"]))
    print("Private key: {}".format( short_key(committee["privkey"]) ))
    print("Public key: {}".format( short_key(committee["pubkey"]) ))
    print("-" * 20)

    comm = Committee(committee["privkey"], committee["pubkey"])

    #Issue a vote to my key and validate it
    my_vote = comm.issue(public_key)
    comm.validate_vote(my_vote)

    print("Owner: {}".format(short_key(comm.get_owner(my_vote))))
    print("I have {} votes".format(len(comm.fetch_vote(public_key))))

    # After generating your keys, establish connection with Committees
    # ask them, what is your coin balance

    # Cast your vote and check if its included


        

if __name__ == "__main__":
    # Run it when you're the voter
    case_voter()


