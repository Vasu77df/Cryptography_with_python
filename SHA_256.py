from cryptography.hazmat.backends import default_backend # importing backend for the hashing algorithms
from cryptography.hazmat.primitives import hashes # importing hashing functions


def SHA_256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend()) # Initializing the hashing function to be used 
    digest.update(message) # Hashing of the message is done
    msg_digest = digest.finalize() # Finalizing the current context and returning the digest in bytes
    return msg_digest

if __name__ == "__main__":
    plaintext = input("Enter Plaintext here:") # Enter the plaintext to be hashed 
    byte_plaintext = plaintext.encode() # Converting the string datatype to bytes datatype for hashing 
    digest = SHA_256(byte_plaintext) 
    digest_hex = digest.hex() # Converting the digest returned in bytes format to hexadecimal format 
    print ("Plaintext entered:{}".format(plaintext))
    print("Expected Messsage Digest: \n c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")
    print("Computed Message digest after SHA256 hashing:\n {} ".format(digest_hex))