import pickle

def serialize(glos):
    return pickle.dumps(glos)

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

