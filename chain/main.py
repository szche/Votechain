import utils
from transfer import Transfer
from committee import Committee
from vote import Vote
from keys import * 

# Test scenario 2:
# Alice gets 2 votes and Bob gets one. Alice sends Bob her vote and he gives it back
# During that exchange, Alice tries to double-spend the vote
# Fortunately, the Committee doesnt let her do it
def test_scenario2():
    print("PKW Private Key: {}".format( short_key(pkw_private_key)))
    print("Alice public key: {}".format( short_key(alice_public_key) ))
    print("Bob public key: {}".format( short_key(bob_public_key) ))
    # Create a voting comittee
    committee = Committee(pkw_private_key, pkw_public_key)
    # Give Alice 2 votes and Bob 1 vote
    vote = committee.issue(alice_public_key)
    vote2 = committee.issue(bob_public_key)
    vote3 = committee.issue(alice_public_key)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))
    print("-" * 20)

    print("Vote 3 is owned by: {}".format( short_key(committee.get_owner(vote3)) ))

    # Create a sending commitment
    vote3.sign_transfer(alice_private_key, bob_public_key)
    # Update the Committee's voting database
    committee.observe_vote(vote3)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))

    print("Vote 3 is owned by: {}".format( short_key(committee.get_owner(vote3)) ))
    # === WARNING ===
    # Now try to send that same vote again, should result in an error
    try:
        vote3.sign_transfer(alice_private_key, bob_public_key)
        committee.observe_vote(vote3)
    except:
        print("Cannot send this vote! It's not yours")
        print("-" * 20)
    # === ======== ===
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))
    print("Vote 3 is owned by: {}".format( short_key(committee.get_owner(vote3)) ))
    # Finally, Bob send the vote back to alice
    vote3.sign_transfer(bob_private_key, alice_public_key)
    committee.observe_vote(vote3)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))
    print("Vote 3 is owned by: {}".format( short_key(committee.get_owner(vote3)) ))
    

def case_voter():
    # Generate private key
    privkey_generator = input("Input your album number: ")
    secexp = randrange_from_seed__trytryagain(privkey_generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    print("Your private key:\t {}".format(short_key(private_key)))
    print("Your public key:\t {}".format(short_key(public_key)))

    # After generating your keys, establish connection with Committees
    # ask them, what is your coin balance
        

if __name__ == "__main__":
    # Run it when you're the voter
    case_voter()

