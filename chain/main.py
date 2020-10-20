import utils
from transfer import Transfer
from committee import Committee
from vote import Vote
from keys import * 

# Test scenario 1:
# PKW gives alice the 'voting ticket', she forwards it to Bob and he sends it back to PKW
# In the meantime, Bob tries to create his own 'voting ticket' out of thin air but fails to do so
def test_scenario1():
    committee = Committee(pkw_private_key, pkw_public_key)
    # Give a vote to alice and verify it
    vote = committee.issue(alice_public_key)
    print("This vote is owned by: {}".format(vote.owner()))
    # Now let's pass the alice's vote to bob
    vote.send(alice_private_key, bob_public_key)
    print("This vote is owned by: {}".format(vote.owner()))
    # Now the PKW gets it
    vote.send(bob_private_key, pkw_public_key)
    print("This vote is owned by: {}".format(vote.owner()))
    # Check the history of the vote
    vote.list_transfers()

    # ==================================================================
    # Bob fakes his vote, should return error 
    bob_message = utils.serialize(bob_public_key)
    bob_signature = bob_private_key.sign(bob_message)
    bob_transfer = Transfer(bob_signature, bob_public_key)
    try:
        bob_vote = Vote([bob_transfer])
    except:
        print("=== Bob's vote is invalid! ===")
    # ==================================================================


# Test scenario 2:
# Alice gets 2 votes and Bob gets one. Alice sends Bob her vote and he gives it back
# During that exchange, Alice tries to double-spend the vote
# Fortunately, the Committee doesnt let her do it
def test_scenario2():
    # Create a voting comittee
    committee = Committee(pkw_private_key, pkw_public_key)
    # Give Alice 2 votes and Bob 1 vote
    vote = committee.issue(alice_public_key)
    vote2 = committee.issue(bob_public_key)
    vote3 = committee.issue(alice_public_key)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))
    print("-" * 20)

    # Create a sending commitment
    vote3.send(alice_private_key, bob_public_key)
    # Update the Committee's voting database
    committee.observe_vote(vote3)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))

    # === WARNING ===
    # Now try to send that same vote again, should result in an error
    try:
        vote3.send(alice_private_key, bob_public_key)
        committee.observe_vote(vote3)
    except:
        print("Cannot send this vote! It's not yours")
        print("-" * 20)
    # === ======== ===

    # Finally, Bob send the vote back to alice
    vote3.send(bob_private_key, alice_public_key)
    committee.observe_vote(vote3)
    print("Alice has {} votes".format( len(committee.fetch_vote(alice_public_key))) )
    print("Bob has {} votes".format( len(committee.fetch_vote(bob_public_key))))


if __name__ == "__main__":
    # Run Test scenario 1
    #test_scenario1()

    # Run Test scenatio 2
    test_scenario2()

