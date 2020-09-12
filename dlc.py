from hashlib import sha256
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
import secrets

G = Point(
    secp256k1.gx,
    secp256k1.gy,
    curve=secp256k1
)

def single_oracle_example():
    # initialization

    # generate Alice's key pairs
    priv_key_a, pub_key_a = generate_key_pair()
    # generate Bob's key pairs
    priv_key_b, pub_key_b = generate_key_pair()
    # generate Alice and Bob's aggregate key
    agg_pub_key = pub_key_a + pub_key_b
    # generate Olivia's key pairs
    priv_key_o, pub_key_o = generate_key_pair()
    # generate Olivia's nonce
    nonce_o, nonce_pub_key_o = generate_key_pair()
    # generate Olivia's challenge hash for 'yes' event
    c_o_yes = challenge_int(nonce_pub_key_o, pub_key_o, 'yes')
    # generate Olivia's signature point for 'yes' event
    s_o_pub_key_yes = (nonce_pub_key_o + (pub_key_o * c_o_yes))
    # generate Alice's nonce
    nonce_a, nonce_pub_key_a = generate_key_pair()
    # generate Bob's nonce
    nonce_b, nonce_pub_key_b = generate_key_pair()

    # nonce aggregation and tweak

    # generate Alice and Bob's aggregate nonce key
    agg_nonce_pub_key = nonce_pub_key_a + nonce_pub_key_b
    # generate adaptor signature nonce pub key for 'yes' event
    agg_nonce_pub_key_yes = agg_nonce_pub_key + s_o_pub_key_yes

    # adaptor signature

    # generate adaptor signature challenge hash for 'yes' event
    c_yes = challenge_int(agg_nonce_pub_key_yes, agg_pub_key, 'tx_yes')
    # generate Alice's adaptor signature for 'yes' event
    s_a_yes = (nonce_a + (c_yes * priv_key_a)) % secp256k1.q
    # generate Bob's adaptor signature for 'yes' event
    s_b_yes = (nonce_b + (c_yes * priv_key_b)) % secp256k1.q
    # generate aggregate adaptor signature for 'yes' event
    adapt_s_yes = (s_a_yes + s_b_yes) % secp256k1.q

    # oracle signing

    # generate Olivia's signature for 'yes' event
    s_o_yes = (nonce_o +(c_o_yes * priv_key_o)) % secp256k1.q

    # signature derivation

    # convert adaptor signature for 'yes' event to valid signature
    s_yes = (adapt_s_yes + s_o_yes) % secp256k1.q

    # verify sig
    return verify_sig(agg_nonce_pub_key_yes, agg_pub_key, s_yes, 'tx_yes')

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
