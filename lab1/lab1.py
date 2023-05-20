import sys
import binascii

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

def hashaj(zapis):
    if type(zapis) == bytes:
        zapis = zapis.decode('utf-8')
    h = SHA256.new()
    h.update(zapis.encode('utf-8'))
    return h.hexdigest()

def ispisi(imeDatoteke):
    with open(imeDatoteke, 'rb') as f:
        lines = f.readlines()

    print(f"\nSadržaj datoteke {imeDatoteke} je:")
    for linija in lines:
        print(linija)
    print("\n")

def deleteLine(imeDatoteke1, imeDatoteke2, brojLinije):

    with open(imeDatoteke1, 'rb') as f:
        lines1 = f.readlines()
    del lines1[brojLinije]
    with open(imeDatoteke1, 'wb') as f:
        f.writelines(lines1)

    with open(imeDatoteke2, 'rb') as f:
        lines2 = f.readlines()
    del lines2[brojLinije]
    with open(imeDatoteke2, 'wb') as f:
        f.writelines(lines2)

def encrypt(website, master_password, password):
    
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 32, 1000000, hmac_hash_module=SHA256)
    key = binascii.hexlify(key)
    iv = get_random_bytes(16)
    iv = binascii.hexlify(iv)
    zapis = website + b" " + key + b" " + iv + b'\n'

    with open('bazakljuceva.bin', 'ab') as f:
        f.write(zapis)

    key = binascii.unhexlify(key)
    iv = binascii.unhexlify(iv)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(password)

    return ciphertext, tag

def decrypt(website, ciphertext, tag, cuvaj_website):
    
    with open('bazakljuceva.bin', 'rb') as f:
        lines = f.readlines()

    for i in range(len(lines)):
        zapis = lines[i].split(b" ")
        expected_website = zapis[0]
        key = zapis[1]
        iv = zapis[2].replace(b'\n', b'')
        key = binascii.unhexlify(key)
        iv = binascii.unhexlify(iv)

        if expected_website == website:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            password = cipher.decrypt(ciphertext)
            try:
                cipher.verify(tag)
                print(f"Password for {cuvaj_website} is: {password.decode('utf-8')}.")
                exit()
            except ValueError:
                print(f"Authentification for password is invalid.\nPassword for {cuvaj_website} is: {password.decode('utf-8')}.")

    return 

def main():
    
    if sys.argv[1] == 'init': 

        master_password = hashaj(sys.argv[2])
        with open('masterpassword.bin', 'wb') as f:
            f.write(master_password.encode('utf-8'))

        with open('websitepassword.bin', 'wb') as f:
            f.write(b"")

        with open('bazakljuceva.bin', 'wb') as f:
            f.write(b"")

        print("Password manager initialized.")

    elif sys.argv[1] == 'put':

        master_password = sys.argv[2]
        
        with open('masterpassword.bin', 'rb') as f:
            expected_master_password = f.read().decode('utf-8')

        if hashaj(master_password) == expected_master_password:
            website = sys.argv[3]
            cuvaj_website = website
            website = hashaj(website).encode('utf-8')
            password = sys.argv[4]

            with open('websitepassword.bin', 'rb') as f:
                lines = f.readlines()

            for i in range(len(lines)):
                zapis = lines[i].split(b" ")
                dobivena_website = zapis[0]

                if website == dobivena_website:
                    deleteLine('websitepassword.bin', 'bazakljuceva.bin', i)
                    print(f"Password for {cuvaj_website} is already stored. Replacing it...")
                    continue 

            password, checker = encrypt(website, master_password, password.encode('utf-8'))

            password = binascii.hexlify(password)
            checker = binascii.hexlify(checker)
            zapis = website + b" " + password + b" " + checker + b'\n'

            with open('websitepassword.bin', 'ab') as f:
                f.write(zapis)

            print(f"Stored password for {cuvaj_website}.")
        else:
            print("Master password incorrect or integrity check failed.")

        
    elif sys.argv[1] == 'get':

        master_password = sys.argv[2]
        
        with open('masterpassword.bin', 'rb') as f:
            expected_master_password = f.read().decode('utf-8')

        if hashaj(master_password) == expected_master_password:
            website = sys.argv[3]
            cuvaj_website = website
            website = hashaj(website).encode('utf-8')
            check = False

            with open('websitepassword.bin', 'rb') as f:
                lines = f.readlines()

            for i in range(len(lines)):
                zapis = lines[i].split(b" ")
                expected_website = zapis[0]
                ciphertext = zapis[1]
                tag = zapis[2].replace(b'\n', b'')

                ciphertext = binascii.unhexlify(ciphertext)
                tag = binascii.unhexlify(tag)
                if expected_website == website:
                    decrypt(website, ciphertext, tag, cuvaj_website)
                    check = True

            if check == False:
                print(f"Password for {cuvaj_website} is not stored.")
                    
        else:
            print("Master password incorrect or integrity check failed.")  

main()