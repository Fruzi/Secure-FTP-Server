import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature


class MyCipher(object):

    def __init__(self, secret):
        self._secret = secret.encode()
        self._cipher_key = MyCipher.derive_key(self._secret + b'1')
        self._mac_key = MyCipher.derive_key(self._secret + b'2')

    def derive_server_key(self):
        return MyCipher.derive_key(self._secret + b'3').hex()

    def encrypt(self, pt, is_filename=False):
        """
        Encrypt and authenticate the given plaintext using AES and HMAC.
        if is_filename is True, the IV will be deterministically generated (derived from secret||pt),
        and the returned data will all be concatenated (not a tuple)
        :param pt: plaintext
        :param is_filename: encrypting for filename
        :return: encrypted data: tuple(iv||ct, tag) or iv||ct||tag in case of filename
                    iv = initialization vector (size: 128 bits)
                    ct = ciphertext (encrypted message) (size: unknown)
                    tag = MAC tag (size: 256 bits)
        """
        # pad the plaintext to make its size a multiple of 256 bits (for CBC)
        padder = PKCS7(256).padder()
        padded_pt = padder.update(pt) + padder.finalize()

        iv = MyCipher.derive_key(self._secret + pt)[:16] if is_filename else os.urandom(16)
        cipher = Cipher(algorithms.AES(self._cipher_key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_pt) + encryptor.finalize()

        h = hmac.HMAC(self._mac_key, hashes.SHA256(), default_backend())
        h.update(iv + ct)
        tag = h.finalize()
        return iv + ct + tag if is_filename else (iv + ct, tag)

    def decrypt(self, msg):
        """
        Verify and decrypt the given message using AES and HMAC
        :param msg: encrypted data (structure above)
        :return: Decrypted message plaintext (if verified)
        """
        if isinstance(msg, tuple):
            iv_and_ct, tag = msg
        else:
            iv_and_ct = msg[:-32]
            tag = msg[-32:]
        iv = iv_and_ct[:16]
        ct = iv_and_ct[16:]
        h = hmac.HMAC(self._mac_key, hashes.SHA256(), default_backend())
        h.update(iv_and_ct)
        try:
            h.verify(tag)
        except InvalidSignature:
            return None

        cipher = Cipher(algorithms.AES(self._cipher_key), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        padded_pt = decryptor.update(ct) + decryptor.finalize()

        # unpad the decrypted plaintext (it was padded for CBC before encryption)
        unpadder = PKCS7(256).unpadder()
        return unpadder.update(padded_pt) + unpadder.finalize()

    @staticmethod
    def derive_key(key_material):
        return HKDF(hashes.SHA256(), 32, None, None, default_backend()).derive(key_material)

    @staticmethod
    def derive_password_for_storage(password):
        salt = os.urandom(16)
        key = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
            backend=default_backend()
        ).derive(bytes.fromhex(password))
        return salt, key

    @staticmethod
    def verify_stored_password(password, salt, key):
        Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
            backend=default_backend()
        ).verify(bytes.fromhex(password), key)
