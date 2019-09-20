import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


if __name__ == "__main__":
    backend = default_backend()
    key = os.urandom(16) # 128 bit key
    iv = os.urandom(16) # 128 bit IV 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    # the buffer needs to be at leasr lenght of data + n - 1 where n is cipher/mode block size in bytes
    buf = bytearray(31)
    plaintext = b'a secret message'
    len_encrypted = encryptor.update_into(plaintext, buf)
    ciphertext = bytes(buf[:len_encrypted]) + encryptor.finalize()
    decryptor = cipher.decryptor()
    len_decrypted = decryptor.update_into(ciphertext, buf)
    decrypted_msg = bytes(buf[:len_decrypted]) + decryptor.finalize()
    print("AES in CBC mode with padding of [a secret messages]!")
    print("Plaintext: {}".format(plaintext.hex()))
    print("CipherText: {}".format(ciphertext.hex()))
    print("Decrypted Message: {}".format(decrypted_msg.decode('utf-8')))
