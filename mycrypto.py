import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from hashlib import sha256


class MyCipher(object):

    def __init__(self, secret):
        self._secret = secret
        self._derive_cipher_key()
        self._derive_mac_key()

    def _derive_cipher_key(self):
        kdf = HKDF(hashes.SHA256(), 32, None, None, default_backend())
        self._cipher_key = kdf.derive((self._secret + '1').encode())

    def _derive_mac_key(self):
        kdf = HKDF(hashes.SHA256(), 32, None, None, default_backend())
        self._mac_key = kdf.derive((self._secret + '2').encode())

    def encrypt(self, pt):
        """
        Encrypt and authenticate the given plaintext using AES and HMAC
        :param pt: plaintext
        :return: encrypted data: iv||ct||tag
                    iv = initialization vector (size: 128 bits)
                    ct = ciphertext (encrypted message) (size: unknown)
                    tag: MAC tag (size: 256 bits)
        """
        # pad the plaintext to make its size a multiple of 256 bits (for CBC)
        padder = PKCS7(256).padder()
        padded_pt = padder.update(pt) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._cipher_key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_pt) + encryptor.finalize()

        h = hmac.HMAC(self._mac_key, hashes.SHA256(), default_backend())
        h.update(iv + ct)
        tag = h.finalize()
        return iv + ct + tag

    def decrypt(self, msg):
        """
        Verify and decrypt the given message using AES and HMAC
        :param msg: encrypted data (structure above)
        :return: Decrypted message plaintext (if verified)
        """
        iv = msg[:16]           # first 128 bits
        ct = msg[16:-32]        # everything except the first 128 bits and the last 256 bits
        tag = msg[-32:]         # last 256 bits

        h = hmac.HMAC(self._mac_key, hashes.SHA256(), default_backend())
        h.update(msg[:-32])     # everything except the last 256 bits (iv||ct)
        try:
            h.verify(tag)
        except InvalidSignature as e:
            # TODO: Message invalid - do something
            raise e

        cipher = Cipher(algorithms.AES(self._cipher_key), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()

        # unpad the decrypted plaintext (it was padded for CBC before encryption)
        padded_pt = decryptor.update(ct) + decryptor.finalize()
        unpadder = PKCS7(256).unpadder()
        return unpadder.update(padded_pt) + unpadder.finalize()

    @staticmethod
    def derive_server_key(secret):
        return sha256((secret + '3').encode()).hexdigest()
