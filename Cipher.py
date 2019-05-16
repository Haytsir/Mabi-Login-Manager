import base64
import hashlib
from Cryptodome import Random
from Cryptodome.Cipher import AES

class AESCipher(object):
    def __init__(self, key):
        self.blockSize = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.blockSize - len(s) % self.blockSize) * chr(self.blockSize - len(s) % self.blockSize)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
