import chain.utils 
from chain.transfer import Transfer
#from chain.committee import Committee
from chain.vote import Vote
from chain.keys import * 
from chain.block import Block
import sys
import socketserver, socket
import logging
import os
import threading

#from chain.network import *
from chain.committee import *


# Generates (privkey, pubkey) pair
# Returns a tuple
def create_keypair(generator):
    secexp = randrange_from_seed__trytryagain(generator, SECP256k1.order)
    private_key = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return (private_key, public_key)


def case_voter():
    print("=" * 20)
    # Generate my private key
    keypair = create_keypair(input("Input your email address: "))
    print("Your private key:\t {}".format(short_key(keypair[0])))
    print("Your public key:\t {}".format(short_key(keypair[1])))

    #Check your balance
    balance = send_message("balance", keypair[1])
    print("My balance: {}".format(len(balance["data"])))

    #Send your vote
    #Generate a second keypair - debugging only
    keypair2 = create_keypair("cetnar@student.agh.edu.pl")
    print("Test pubkey: {}".format(short_key(keypair2[1])))
    my_vote = balance["data"][0]
    
    #Check who's the owner of this vote
    vote_owner = send_message("vote", my_vote.id)
    print("Owner of this vote: {}".format(short_key(vote_owner["data"])))

    #Now send the vote to the debuggin address
    my_vote.sign_transfer(keypair[0], keypair2[1])
    send_vote = send_message("send", my_vote)
    print("Sending status: {}".format(send_vote["data"]))

    #Check debugging balance
    debug_balance = send_message("balance", keypair2[1])
    print("Debugging balance: {}".format( len(debug_balance["data"]) ))
    for vote in debug_balance["data"]:
        print(vote)
    #Check your balance
    balance = send_message("balance", keypair[0])
    print("My balance: {}".format(len(balance["data"])))



def case_committee():
    global committee 
    print("Creating committee")
    node_id = int(os.environ["NODE_ID"])
    generator = ""
    if node_id == 0:
        generator = "lajkonik"
    elif node_id == 1:
        generator = "syrenka"
    elif node_id == 2:
        generator = "koziolki"
    logger.info(f"Started as {generator}")
    #generator = input("Input committee password: ")
    keypair = create_keypair(generator)
    committee = Committee(keypair[0], keypair[1])
    logger.info(f"My public key: {short_key(keypair[1])}")

    print("Your public key: {}".format( short_key(keypair[1]) ))
    print("Your private key: {}".format( short_key(keypair[0]) ))
    print("-" * 20)

    parties = committee.blocks[0].parties
    print("\n=== Avaliable parties ===")
    for party in parties:
        print( f'{party: <40} with key {short_key(parties[party])}' )

    auth_committees = committee.blocks[0].turns
    print("\n=== Authorized committees ===")
    for com in auth_committees:
        print( f'{com[0]: <40} with key {short_key(com[1])}' )

    committee.schedule_next_block()

    """
    print("-" * 20)
    my_keys = create_keypair("MY TEST KEY")
    friend_keys = create_keypair("FRIEND TEST KEY")
    balance = committee.fetch_vote(my_keys[1])
    print("My balance: {}".format(len(balance)))
    my_vote = balance[0]
    my_vote.sign_transfer(my_keys[0], friend_keys[1])
    """
    server = socketserver.TCPServer(("0.0.0.0", 10000), TCPHandler)
    server.serve_forever()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "voter":
        case_voter()
    elif mode == "committee":
        case_committee()
