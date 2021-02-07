from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class RSACipher():

    def encrypt(self, key, raw):
        '''Takes key and data encrypts and return cipher text'''
        public_key = RSA.importKey(key)
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(raw)

    def decrypt(self, key, enc):
        '''Takes cipher text and key decrypt it and return original data '''
        private_key = RSA.importKey(key)
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(enc)
