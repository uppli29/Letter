from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class AESCipher:

    def __init__(self, key):
        '''The AES class takes in key and initialize the cipher methods'''

        self.key = key

    def encrypt(self, raw):
        '''encrypts the data with 128bit key using ECB mode and returns cipher text'''

        cipher = Cipher(algorithms.AES(self.key), modes.ECB())
        encryptor = cipher.encryptor()
        padded_data = self.pad(raw)
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct

    def decrypt(self, enc):
        '''decrypts the data and return original data'''

        cipher = Cipher(algorithms.AES(self.key), modes.ECB())
        decryptor = cipher.decryptor()
        ct1 = decryptor.update(enc) + decryptor.finalize()
        pt = self.unpad(ct1)
        return pt

    def pad(self, text):
        '''pad the data to multiple of 128'''

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text)
        padded_data += padder.finalize()
        return padded_data

    def unpad(self, text):
        '''removed padded elements added to the origianl data'''

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(text)
        data += unpadder.finalize()
        return data
