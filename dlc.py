from hashlib import sha256
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
import secrets

G = Point(
    secp256k1.gx,
    secp256k1.gy,
    curve=secp256k1
)

def generate_private_key():
    return secrets.randbits(256)

def generate_public_key(priv_key):
    return G * priv_key

def generate_key_pair():
    priv_key = generate_private_key()
    pub_key = generate_public_key(priv_key)

    return priv_key, pub_key

def message_bytes(msg):
    string_bytes = str.encode(msg)

    return sha256(string_bytes).digest()

def challenge_int(nonce_pub_key, pub_key, msg):
    nonce_pub_key_x = nonce_pub_key.x
    nonce_pub_key_bytes = int.to_bytes(nonce_pub_key.x, 32, 'big')

    pub_key_x = pub_key.x
    pub_key_bytes = int.to_bytes(pub_key.x, 32, 'big')

    msg_bytes = message_bytes(msg)

    challenge_bytes = nonce_pub_key_bytes + pub_key_bytes + msg_bytes

    challenge_hash = sha256(challenge_bytes).digest()

    return int.from_bytes(challenge_hash, 'big') % secp256k1.q

def sign_msg(priv_key, nonce, msg):
    nonce_pub_key = G * nonce
    pub_key = G * priv_key
    c = challenge_int(nonce_pub_key, pub_key, msg)

    return (nonce + (c * priv_key)) % secp256k1.q

def verify_sig(nonce_pub_key, pub_key, s, msg):
    c = challenge_int(nonce_pub_key, pub_key, msg)

    return G * s == nonce_pub_key + (pub_key * c)
