import hashlib
from binascii import hexlify, unhexlify
import base58
import ecdsa


class PublicKey:
    _curve = ecdsa.SECP256k1
    _address_prefix = 0
    formats = ['hex', 'hex_compressed', 'bin']

    def __init__(self, public_key: str, address_prefix: int):
        self.public_key = public_key
        self.address_prefix = address_prefix
        assert len(public_key) in [128, 130, 66]
        assert address_prefix in range(0, 256)

        if len(public_key) is 128:
            self.public_key = '04' + public_key

    def long_hex(self):
        public_key = self.public_key
        if len(public_key) is 130:
            return public_key

        elif len(public_key) is 66:
            x, y = decode_public_key(public_key)
            return '04' + hex(x)[2:] + hex(y)[2:]

    def compressed_hex(self):

        public_key = self.public_key

        if len(public_key) is 66:
            return public_key

        elif len(public_key) is 130:
            x, y = int(public_key[2:66], 16), int(public_key[66:130], 16)
            return '0' + str(2 + (y % 2)) + public_key[2:66]

    def to_address(self):
        public_key = self.public_key

        if len(public_key) is 130:
            x,y = int(public_key[2:66], 16), int(public_key[66:130], 16)
            public_key = '0' + str(2+(y % 2)) + public_key[2:66]

        r = hashlib.new('ripemd160', hashlib.sha256(unhexlify(public_key)).digest())
        inp = r.digest()

        if self.address_prefix == 0:
            inp = bytes([0]) + inp
        while self._address_prefix > 0:
            inp = bytes([self._address_prefix % 256]) + inp
            self._address_prefix //= 256

        return base58.b58encode_check(inp).decode('utf-8')


def decode_public_key(public_key):
    b = bytes.fromhex(public_key)
    x = b[1:33]
    result = 0
    while len(x) > 0:
        result *= 256
        result += x[0]
        x = x[1:]
    # calculation
    x = result
    P = 2 ** 256 - 2 ** 32 - 977
    A = 0
    B = 7
    beta = pow(int(x * x * x + A * x + B), int((P + 1) // 4), int(P))
    y = (P - beta) if ((beta + from_byte_to_int(b[0])) % 2) else beta

    return x,y


def from_byte_to_int(a):
    return a
