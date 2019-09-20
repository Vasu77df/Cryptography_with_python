from cryptography.hazmat.backends import default_backend # importing backend for the hashing algorithms
from cryptography.hazmat.primitives import hashes # importing hashing functions


def SHA_512(message):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend()) # Initializing the hashing function to be used 
    digest.update(message) # Hashing of the message is done
    msg_digest = digest.finalize() # Finalizing the current context and returning the digest in bytes
    return msg_digest

if __name__ == "__main__":
    plaintext = input("Enter Plaintext here:") # Enter the plaintext to be hashed 
    byte_plaintext = plaintext.encode() # Converting the string datatype to bytes datatype for hashing 
    digest = SHA_512(byte_plaintext) 
    digest_hex = digest.hex() # Converting the digest returned in bytes format to hexadecimal format 
    print ("Plaintext entered:{}".format(plaintext))
    print("Expected Messsage Digest: \n 861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8")
    print("Computed Message digest after SHA512 hashing:\n {} ".format(digest_hex))