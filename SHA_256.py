from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import sys
def SHA_256(message):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(message)
    ciphertext = digest.finalize()
    return ciphertext


if __name__ == "__main__":
    cipher = SHA_256(b"Hello World!")
    print(cipher.hex())
    x = type(cipher)
    print(x)