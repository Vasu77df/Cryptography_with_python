import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


if __name__ == "__main__":
    backend = default_backend()
    key = os.urandom(16) # 128 bit key
    iv = os.urandom(16) # 128 bit IV 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    # the buffer needs to be at leasr lenght of data + n - 1 where n is cipher/mode block size in bytes
    buf = bytearray(64000160)
    plaintext = bytes(64*1000*1000)
    en_start = time.time()
    len_encrypted = encryptor.update_into(plaintext, buf)
    ciphertext = bytes(buf[:len_encrypted]) + encryptor.finalize()
    en_end = time.time()
    total_time = en_end - en_start
    en_perf = 64/total_time
    de_start = time.time()
    decryptor = cipher.decryptor()
    len_decrypted = decryptor.update_into(ciphertext, buf)
    decrypted_msg = bytes(buf[:len_decrypted]) + decryptor.finalize()
    de_end = time.time()
    tt = de_end - de_start
    de_perf = 64/tt
    print("AES in CBC mode with padding of 64MB 0x0!")
    print("Time taken for encryption: {} secs".format(total_time))
    print("Performance of encryption: {} MB/s".format(en_perf))
    print("Time taken for decryption: {} secs".format(tt))
    print("Performance of decryption: {} MB/s".format(de_perf))
    
