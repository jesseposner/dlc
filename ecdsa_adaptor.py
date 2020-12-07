"""Python ECDSA adaptor signatures implementation."""

import secrets
from hashlib import sha256


class ECDSAdaptor:
    """Class methods for ECDSA adaptor signature operations."""

    Q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    G_x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    G_y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

    @classmethod
    def encrypt(cls, x, Y, message_hash):
        Q = cls.Q

        # parse
        x = int(x, 16)
        Y = cls.Point.sec_deserialize(Y)
        m = int.from_bytes(message_hash, 'big')

        # nonce
        k = secrets.randbits(256) % Q
        R_a = k * cls.__G()
        R = k * Y
        r = R.x

        # DLEQ proof
        proof = cls.__DLEQ_prove(k, R_a, Y, R)

        # sign
        # s_a = (m + rx)/k
        s_a = ((m + r * x) * pow(k, Q - 2, Q)) % Q

        # serialize
        return R.sec_serialize() + R_a.sec_serialize() + format(s_a, 'x') + proof

    @classmethod
    def verify(cls, X, Y, message_hash, a):
        Q = cls.Q

        # parse and verify DLEQ proof
        R, R_a, s_a, proof = cls.__parse_a(a)
        Y = cls.Point.sec_deserialize(Y)
        cls.__DLEQ_verify(R_a, Y, R, proof)
        X = cls.Point.sec_deserialize(X)
        m = int(message_hash, 16)

        # u_1 = m/s_a
        u_1 = (m * pow(s_a, Q - 2, Q)) % Q
        r = R.x
        # u_2 = r/s_a
        u_2 = (r * pow(s_a, Q - 2, Q)) % Q

        # u_1 + (u_2 * x) == k
        # (u_1 + (u_2 * x))G == kG
        return (u_1 * cls.__G()) + (u_2 * X) == R_a

    @classmethod
    def decrypt(cls, a, y):
        Q = cls.Q

        # parse
        R, _, s_a, _ = cls.__parse_a(a)
        r = R.x
        y = int(y, 16)

        # decrypt
        # s = s_a/y
        s = (s_a * pow(y, Q - 2, Q)) % Q
        if s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0:
            s = Q - s

        # serialize
        return format(r, 'x') + format(s, 'x')

    @classmethod
    def recover(cls, Y, a, sig):
        Q = cls.Q

        # parse
        Y = cls.Point.sec_deserialize(Y)
        R, R_a, s_a = cls.__parse_a(a)
        sig_bytes = bytes.fromhex(sig)
        r = int.from_bytes(sig_bytes[:32], 'big')
        s = int.from_bytes(sig_bytes[32:], 'big')

        # validate
        r_implied = R.x % cls.Q
        assert r_implied == r

        # recover
        y = (s_a * pow(s, Q - 2, Q)) % Q
        Y_implied = y * cls.__G()
        if Y_implied == Y:
            return format(y, 'x')
        if Y_implied == -Y:
            return format(cls.Point.P - y, 'x')

        # fail
        return None

    @classmethod
    def __DLEQ_prove(cls, x, X, Y, Z):
        Q = cls.Q

        # nonce
        a = secrets.randbits(256) % Q
        A_G = a * cls.__G()
        A_Y = a * Y
        b_bytes = cls.__derive_b(X, Y, Z, A_G, A_Y)
        b = int.from_bytes(b_bytes, 'big')
        c = (a + b * x) % Q
        c_bytes = (c).to_bytes(32, 'big')

        return (b + c_bytes).hex()

    @classmethod
    def __DLEQ_verify(cls, X, Y, Z, proof):
        b_bytes = proof[:32]
        b = int.from_bytes(b_bytes, 'big')
        c = int.from_bytes(proof[32:], 'big')
        A_G = (c * cls.__G()) + -(b * X)
        A_Y = (c * Y) + -(b * Z)
        implied_b = cls.__derive_b(X, Y, Z, A_G, A_Y)

        assert implied_b == b_bytes

    @classmethod
    def __derive_b(cls, X, Y, Z, A_G, A_Y):
        b_bytes = b''
        for p in [X, Y, Z, A_G, A_Y]:
            b_bytes += bytes.fromhex(p.sec_serialize())
        tag_string = sha256(b'eq(DLG(secp256k1),DL(secp256k1))').digest()
        tag = tag_string + tag_string

        return sha256(tag + b_bytes).digest()

    @classmethod
    def __parse_a(cls, a):
        a_bytes = bytes.fromhex(a)
        R = cls.Point.sec_deserialize(a_bytes[:33].hex())
        R_a = cls.Point.sec_deserialize(a_bytes[33:66].hex())
        s_a = int.from_bytes(a_bytes[66:98], 'big')
        proof = a_bytes[98:162]

        return R, R_a, s_a, proof

    @classmethod
    def __G(cls):
        return cls.Point(cls.G_x, cls.G_y)

    class Point:
        """Class representing a secp256k1 elliptic curve point."""

        P = 2**256 - 2**32 - 977

        def __init__(self, x=float('inf'), y=float('inf')):
            self.x = x
            self.y = y

        @classmethod
        def sec_deserialize(cls, hex_public_key):
            P = cls.P
            hex_bytes = bytes.fromhex(hex_public_key)
            is_even = hex_bytes[0] == 2
            x_bytes = hex_bytes[1:]
            x = int.from_bytes(x_bytes, 'big')
            y_squared = (pow(x, 3, P) + 7) % P
            y = pow(y_squared, (P + 1) // 4, P)
            if y % 2 == 0:
                even_y = y
                odd_y = (P - y) % P
            else:
                even_y = (P - y) % P
                odd_y = y
            y = even_y if is_even else odd_y

            return cls(x, y)

        def sec_serialize(self):
            prefix = '02' if self.y % 2 == 0 else '03'

            return prefix + format(self.x, 'x')

        # point at infinity
        def is_zero(self):
            return self.x == float('inf') or self.y == float('inf')

        def __eq__(self, other):
            return self.x == other.x and self.y == other.y

        def __ne__(self, other):
            return not self == other

        def __neg__(self):
            if self.is_zero():
                return self

            return self.__class__(self.x, self.P - self.y)

        def dbl(self):
            x = self.x
            y = self.y
            P = self.P
            s = (3 * x * x * pow(2 * y, P - 2, P)) % P
            sum_x = (s * s - 2 * x) % P
            sum_y = (s * (x - sum_x) - y) % P

            return self.__class__(sum_x, sum_y)

        def __add__(self, other):
            P = self.P

            if self == other:
                return self.dbl()
            if self.is_zero():
                return other
            if other.is_zero():
                return self
            if self.x == other.x and self.y != other.y:
                return self.__class__()
            s = ((other.y - self.y) * pow(other.x - self.x, P - 2, P)) % P
            sum_x = (s * s - self.x - other.x) % P
            sum_y = (s * (self.x - sum_x) - self.y) % P

            return self.__class__(sum_x, sum_y)

        def __rmul__(self, scalar):
            p = self
            r = self.__class__()
            i = 1

            while i <= scalar:
                if i & scalar:
                    r = r + p
                p = p.dbl()
                i <<= 1

            return r

        def __str__(self):
            if self.is_zero():
                return '0'
            return 'X: 0x{:x}\nY: 0x{:x}'.format(self.x, self.y)

        def __repr__(self) -> str:
            return self.__str__()
