#vuln 0:
# def generate_random_prime():
#     from Crypto.Util import number
#     bits = 256
#     prime1 = number.getPrime(bits)
#     prime2 = number.getPrime(bits)
#     return prime1, prime2
# def get_keys():
#     p,q = generate_random_prime()
#     private_key, public_key = generate_key_pair(p,q)
#     return private_key.save_pkcs1().decode(), public_key.save_pkcs1().decode()



#vuln 1:
# def aes_encrypt(plaintext):
#     current_time = datetime.datetime.now().time()
#     time_str = str(current_time)
#     time = time_str.split(':')
#     seed = time[0] + time[1] + "1000000"
#     random.seed(seed)

#     key = random_number()
#     nonce = random_number()

#     cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
#     plaintext_bytes = plaintext.encode()
#     padded_plaintext = pad(plaintext_bytes, AES.block_size)
#     ciphertext = cipher.encrypt(padded_plaintext)
#     return base64.b64encode(ciphertext).decode(), key, nonce

#vuln 2:
# update lib in requirements.txt Authlib==1.3.1