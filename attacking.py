import os 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def AES_GCM(data, aad):
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, aad)
    attacking_add = input("enter authenticated associated data to attack:")
    pt =aesgcm.decrypt(nonce, ct, aad)
    return ct, pt


if __name__ == "__main__":
    data = b"Hello World!"
    data_str = data.decode('utf-8')
    aad = b"authenticated but unencrypted data" 
    aad_str = aad.decode('utf-8')
    encrypted_msg, decryted_msg = AES_GCM(data, aad)
    print("AES in GCM mode of plaintext: {}".format(data_str))
    print("Authenticated Associated data: {}".format(aad_str))
    print("Ciphertext: {}".format(encrypted_msg.hex()))
    print("Decrypted message: {}".format(decryted_msg.decode('utf-8')))