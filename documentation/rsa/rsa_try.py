import rsa
from cryptography.hazmat.primitives.asymmetric import rsa as crsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# Generate RSA key pair
def generate_key_pair(p,q,message):
    n = p * q
    e = 65537  # Commonly used public exponent
    d = rsa.common.inverse(e, (p-1)*(q-1))

    # Generate RSA key object
    private_key = rsa.PrivateKey(n, e, d, p, q)
    public_key = rsa.PublicKey(n, e)

    # Serialize the public and private keys
    public_key_pem = public_key.save_pkcs1().decode()
    private_key_pem = private_key.save_pkcs1().decode()
    
    print("Public key:")
    print(public_key_pem)
    print("Private key:")
    print(private_key_pem)

    # Encrypt message with public key
    cipher = rsa.encrypt(message, public_key)
    return cipher, private_key, public_key







