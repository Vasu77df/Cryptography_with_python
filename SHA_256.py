from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def SHA_256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    msg_digest = digest.finalize()
    return msg_digest


if __name__ == "__main__":
    plaintext = input("enter plaintext here:")
    byte_plaintext = plaintext.encode()
    digest = SHA_256(byte_plaintext)
    digest = digest.hex()
    print("The message digest after SHA256 hashing in hexadecimal is: {} ".format(digest))
