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
    byte_plaintext = bytes(256*1000*1000 - 33)
    digest = SHA_256(byte_plaintext) 
    digest_hex = digest.hex() # Converting the digest returned in bytes format to hexadecimal format 
    print("SHA 256 of 256MB 0x00")
    print("Message digest after SHA256 hashing is: \n{} ".format(digest_hex))
    total_time = timeit.timeit(setup=setup_code, stmt=evaluation_code, number=10) # running the hash function 10 times and obtaining total time elapsed 
    execution_time = total_time/10
    print("Average Time taken for Hashing the plaintext: {} seconds".format(execution_time))
    performance = 256/execution_time
    print("The performance of the hashing function is {} MB/s".format(performance))
