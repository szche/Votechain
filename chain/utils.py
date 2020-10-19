import pickle

def serialize(glos):
    return pickle.dumps(glos)

def deserialize(serialized):
    return pickle.loads(serialized)
