from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.keys import BadSignatureError

#Create PKW keys
pkw_private_key = SigningKey.generate(curve=SECP256k1)
pkw_public_key = pkw_private_key.get_verifying_key()

