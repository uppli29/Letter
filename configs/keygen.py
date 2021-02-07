from Crypto.PublicKey import RSA


def key_generation():
    '''
    Returns private key and public of 2048 bits
    '''
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key
