import logging, pickle, requests

##########################################
#                 Logging                #
##########################################
logging.basicConfig(
    level="INFO",
    format='%(message)s',
)
logger = logging.getLogger(__name__)


##########################################
#         Initial peer discovery         #
##########################################
# Get request returns your public IP address
MY_IP_LINK = "https://chadam.pl/tracker/ip.php"

# Get request returns the list of public nodes
PEERS_LIST = "https://chadam.pl/tracker/"

# Visit this link to be added to the tracker list as a public node
ADD_YOUR_PEER = "https://chadam.pl/tracker/public.php"

def get_my_ip():
    my_ip = requests.get(MY_IP_LINK).text
    logger.info(f"My IP is {my_ip}")
    return my_ip

# Get the public peers list and filter it
def get_public_peers():
    my_ip = get_my_ip() 
    peers_request = requests.get(PEERS_LIST).text
    peers = []
    for ip in peers_request.split(";"):
        if ip != "" and ip != my_ip:
            peers.append(ip)
    return peers

def add_as_public():
    requests.get(ADD_YOUR_PEER)


##########################################
#   Serialization and writing to disk    #
##########################################
def serialize(data):
    return pickle.dumps(data, protocol=4)


def deserialize(serialized):
    return pickle.loads(serialized)


def to_disk(data, filename):
    serialized = serialize(data)
    with open(filename, "wb") as f:
        f.write(serialized)


def from_disk(filename):
    with open(filename, "rb") as f:
        serialized = f.read()
        return deserialize(serialized)
