import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def encrypt(key, pt, aad):
    '''AES in GCM Mode encrytion function
        parameters:
            key: 128 bit random key
            pt: plaintext for encryption 
                type: bytes 
            aad: authenticated associated data
                type: bytes '''
    iv = os.urandom(12) # 96 bit initialization vector

    encryptor = Cipher(
        algorithms.AES(key), # using AES block cipher
        modes.GCM(iv), # in GCM mode
        backend=default_backend()
    ).encryptor() # creating a AESGCM cipher object 

    encryptor.authenticate_additional_data(aad) # authenticated additional data will be authenticated but not encrypted
    ct = encryptor.update(pt) + encryptor.finalize() # getting cipher text after encryption

    return (iv, ct, encryptor.tag) 

def decrypt(key, aad, iv, ct, tag):
    '''AES in GCM Mode decrytion function
        parameters:
            key: 128 bit random key
            aad: authenticated associated data
                type: bytes 
            iv: 96 bit initialization vector 
            ct: ciphertext for decryption 
                type: bytes'''
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # Put aad back in or the tag will fail to verify 
    decryptor.authenticate_additional_data(aad)

    # decryptor provides the authenticated plaintext. 
    # if the tag does not match an InvalidTag exception will be raised 
    return decryptor.update(ct) + decryptor.finalize()

if __name__ == "__main__":
    plaintext = b'Hello World!'
    plaintext_str = plaintext.decode('utf-8')
    aad = b"Data that is authenticated but not encrypted" # authenticated associated data
    aad_str = aad.decode("utf-8")
    key = os.urandom(32) # 128 bit key generation for AES 
    iv, ciphertext, tag = encrypt(key, plaintext, aad) 
    # the initialization vector, cipher text and MAC tag 
    # is returned after encryption 
    decryted_msg = decrypt(key, aad, iv, ciphertext, tag)
    print("AES in GCM mode of plaintext: {}".format(plaintext_str))
    print("Additional Authenticated data: {}".format(aad_str))
    print("Initialization Vector: {}".format(iv.hex()))
    print("MAC tag: {}".format(tag.hex()))
    print("Ciphertext: {}".format(ciphertext.hex())) 
    print("Decrypted message: {}".format(decryted_msg.decode('utf-8')))