import re
import ecdsa
from binascii import hexlify, unhexlify
import base58
from publickey import PublicKey


class PrivateKey:
    _curve = ecdsa.SECP256k1
    _wif_prefix = 128
    _formats = [int, 'hex', 'wif_compressed']

    def __init__(self, private_key: (str, int) = None, wif_prefix: int = _wif_prefix, compressed=True):
        self.compressed = compressed
        self.wif_prefix = wif_prefix
        self.private_key = private_key
        assert wif_prefix in range(1, 256)

        if not private_key:
            # generate
            sk = ecdsa.SigningKey.generate(curve=self._curve)
            self.private_key = hexlify(sk.to_string()).decode('utf8')
        else:
            self.validate()

    def validate(self):
        private_key = self.private_key
        if isinstance(private_key, str):
            assert len(private_key) in [64, 52]
            if self.wif_prefix is 128 and len(private_key) is 52:
                if re.match(r"^[LK][a-km-zA-HJ-NP-Z0-9]{51}$", private_key) is None:
                    raise ValueError('Invalid wif key')

        private_key_format = self.get_format(private_key)
        if private_key_format not in self._formats:
            raise ValueError(f'Invalid format must be in {self._formats}, got {private_key_format} instead')

    def to_hex(self):
        if isinstance(self.private_key, int):
            hex_key = hex(self.private_key)[2:]
            z = '0'*(64 - len(hex_key))
            return z + hex_key
        elif isinstance(self.private_key, str):
            if len(self.private_key) is 52:
                return hexlify(base58.b58decode_check(self.private_key)[1:-1]).decode('utf8')
            else:
                return self.private_key

    def to_wif(self):
        if self.compressed:
            prefix = bytes([self.wif_prefix])
            compression_flag = bytes([1])
            extended_key = prefix + unhexlify(self.to_hex()) + compression_flag
            leading_zeroes = 0
            for x in extended_key:
                if x != 0:
                    break
                leading_zeroes += 1
            wif_key = '1'*leading_zeroes + base58.b58encode_check(extended_key).decode('utf8')
            return wif_key

    def public_key(self, address_prefix=0):
        sk = ecdsa.SigningKey.from_string(unhexlify(self.to_hex().encode()), curve=self._curve)
        vk = '04' + hexlify(sk.get_verifying_key().to_string()).decode('ascii')
        return PublicKey(vk, address_prefix)

    @staticmethod
    def get_format(private_key):
        if isinstance(private_key, str):
            # wif or hex ?
            if len(private_key) is 52:
                try:
                    base58.b58decode_check(private_key)
                except:
                    raise ValueError('Invalid base58 key')
                return 'wif_compressed'
            elif len(private_key) is 64:
                try:
                    int(private_key, 16)
                except:
                    raise ValueError('Invalid hex key')
                return 'hex'
        else:
            return type(private_key)