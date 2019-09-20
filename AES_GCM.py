import os 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def AES_GCM(data, aad):
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, aad)
    pt =aesgcm.decrypt(nonce, ct, aad)
    return ct, pt


if __name__ == "__main__":
    data = b"Hello World!"
    data_hex = data.hex()
    aad = b"authenticated but unencrypted data"
    encrypted_msg, decryted_msg = AES_GCM(data, aad)
    print(encrypted_msg.hex())
    print(decryted_msg)