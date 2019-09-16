from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import timeit

setup_code = '''
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
'''

evaluation_code = '''
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(bytes(256*1000*1000))
digest.finalize()
'''

def SHA_256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend()) # Initializing the hashing function to be used 
    digest.update(message) # Hashing of the message is done
    msg_digest = digest.finalize() # Finalizing the current context and returning the digest in bytes
    return msg_digest

if __name__ == "__main__":
    byte_plaintext = bytes(256*1000*100)
    digest = SHA_256(byte_plaintext) 
    digest_hex = digest.hex() # Converting the digest returned in bytes format to hexadecimal format 
    print ("Plaintext entered:{}".format(byte_plaintext))
    print("Message digest after Hashing in bytes: {}".format(digest))
    print("Message digest after SHA256 hashing in hexadecimal is: {} ".format(digest_hex))
    execution_time = timeit.timeit(setup=setup_code, stmt=evaluation_code, number=1)
    print("Time taken for Hashing the plaintext once: {}".format(execution_time))
    total_time = timeit.timeit(setup=setup_code, stmt=evaluation_code, number=10)
    print("Time taken after running the Hash function 10 times: {}".format(total_time))
    performance = 256/total_time
    print("The speed is {} MB/s".format(performance))
