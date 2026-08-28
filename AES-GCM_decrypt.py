from Crypto.Cipher import AES

def decrypt_and_verify(key, ciphertext, iv, tag):

    key = bytes.fromhex(key)
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    tag = bytes.fromhex(tag)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode()

key = input("[+] Enter your key ( SHA-256 ) : ")
ciphertext = input("[+] Enter your ciphertext: ")
iv = input("[+] Enter your iv: ")
tag = input("[+] Enter your tag: ")

print("[+] Your decrypted Value:", decrypt_and_verify(key, ciphertext, iv, tag))
