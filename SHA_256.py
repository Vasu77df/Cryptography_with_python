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
    print("Expected Messsage Digest: \n 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069")
    print("Computed Message digest after SHA256 hashing:\n {} ".format(digest_hex))