import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import time
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

    encryptor.authenticate_additional_data(aad) # authenticated associate data will be authenticated but not encrypted
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
    plaintext = bytes(64*1000*1000 - 33) # minus 33 to remove byte function overhead
    aad = b"Data that is authenticated but not encrypted" # authenticated associated data
    aad_str = aad.decode("utf-8")
    encrypt_start = time.time()
    for i in  range(0, 10): # doing 10 iterations of encryption
        key = os.urandom(32) # 128 bit key generation for AES 
        iv, ciphertext, tag = encrypt(key, plaintext, aad)
        # the initialization vector, cipher text and MAC tag 
        # is returned after encryption
    encrypt_end = time.time()
    encrypt_elapsed_time = encrypt_end - encrypt_start
    avg_encrypt_elapsed_time = encrypt_elapsed_time/10
    encrypt_perf = 64/avg_encrypt_elapsed_time
    decrypt_start = time.time()
    for i in range(0, 10): # doing 10 iterations of decryption
        decryted_msg = decrypt(key, aad, iv, ciphertext, tag)
    decrypt_end = time.time()
    decrypt_elapsed_time = decrypt_end - decrypt_start
    avg_decrypt_elapsed_time = decrypt_elapsed_time/10
    decrypt_perf = 64/avg_decrypt_elapsed_time
    print("AES in GCM mode of 64MB 0x0")
    print("Elapsed time for encryption of 64MB 0x0: {} sec".format(round(avg_encrypt_elapsed_time, 4)))
    print("Performance of Encryption is: {} MB/s".format(round(encrypt_perf, 4)))
    print("Elapsed time for decryption of 64MB 0x0: {} sec".format(round(avg_decrypt_elapsed_time, 4)))
    print("Performance of Decryption is: {} MB/s".format(round(decrypt_perf, 4)))
   
  