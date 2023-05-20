import sys
import getpass
import re
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import binascii
import base64

# funkcija za hashanje
def hashaj(zapis):
    h = SHA256.new()
    h.update(zapis)
    return h.hexdigest()

# funkcija za ispis binarne datoteke
def ispisi(imeDatoteke):
    with open(imeDatoteke, 'rb') as f:
        lines = f.readlines()

    print(f"\nSadržaj datoteke {imeDatoteke} je:")
    for linija in lines:
        print(linija)
    print("\n")

# funkcija za brisanje linije
def deleteLine(imeDatoteke, brojLinije):
    with open(imeDatoteke, 'rb') as f:
        lines = f.readlines()
    del lines[brojLinije]
    with open(imeDatoteke, 'wb') as f:
        f.writelines(lines)


def main():

    checker = 0
    nePostoji = 0

    while checker == 0:
        # dohvaćamo user i pripremamo podatak
        user = sys.argv[1]
        user_bin = user.encode('utf-8')
        user_hash = hashaj(user_bin)
        user_hash = binascii.unhexlify(user_hash)
        user_hash = base64.b64encode(user_hash)

        # traženje user-a u datoteci
        index_linije = -1
        with open('userpassword.bin','rb') as f:
            lines = f.readlines()

            # provjera postoji li već user
            for i in range(len(lines)):
                zapis = lines[i].split(b" ")
                procitani_user = zapis[0]

                # ukoliko pronađemo usera, prekidamo program
                if user_hash == procitani_user:
                    index_linije = i

        # ukoliko ne postoji user        
        if index_linije == -1:
            nePostoji = 1

        # unos lozinke
        password = getpass.getpass(prompt="Password: ")

        # dohvaćanje zapisa iz datoteke
        zapis = lines[index_linije].split(b" ")
        salt = zapis[1]
        procitani_password = zapis[2]
        password_bin = password.encode('utf-8')
        password_hash = PBKDF2(password_bin, salt, 32, 1000000, hmac_hash_module=SHA256)
        password_hash = base64.b64encode(password_hash)
        forcepass = zapis[3]
        forcepass = forcepass.rstrip()

        # provjera je li unesena ista lozinka 
        detected = 0 
        if password_hash == procitani_password and nePostoji == 0:

            provjeravamo_forcepass = 1
            provjeravamo_forcepass_bin = provjeravamo_forcepass.to_bytes((provjeravamo_forcepass.bit_length() + 7) // 8, "big")
            provjeravamo_forcepass_hash = hashaj(provjeravamo_forcepass_bin)
            provjeravamo_forcepass_hash = binascii.unhexlify(provjeravamo_forcepass_hash)
            provjeravamo_forcepass_hash = base64.b64encode(provjeravamo_forcepass_hash)

            # provjeravamo je li podignuta forcepass zastavica
            if forcepass == provjeravamo_forcepass_hash:   
                detected = 1

                # inicijaliziranje forcepass zastavice, hashanje forcepassa, pretvaranje iz hex u bin
                forcepass = 0
                forcepass_bin = forcepass.to_bytes((forcepass.bit_length() + 7) // 8, "big")
                forcepass_hash = hashaj(forcepass_bin)
                forcepass_hash = binascii.unhexlify(forcepass_hash)
                forcepass_hash = base64.b64encode(forcepass_hash)

                # učitavanje željenih podataka
                new_password = getpass.getpass(prompt="New password: ")
                repeated_new_password = getpass.getpass(prompt="Repeat new password: ")

                # regex za lozinku - barem jedno veliko slovo, malo slovo, broj i specijalni znak (samo za ASCII vrijednosti 33 do 126 uključivo)
                password_regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!-\/:-@\[-`\{-~])[A-Za-z0-9!-\/:-@\[-`\{-~]+$'
                
                # ispravno
                if new_password == repeated_new_password and re.fullmatch(password_regex, new_password) != None: 

                    # hashanje kombinacije salta i passworda
                    password_bin = new_password.encode('utf-8')
                    password_hash = PBKDF2(password_bin, salt, 32, 1000000, hmac_hash_module=SHA256)
                    password_hash = base64.b64encode(password_hash)
            
                    # ukoliko je podignuta zastavica, mijanjamo lozinku
                    if detected == 1:
                        # stvaranje zapisa za upis u datoteku
                        zapis = user_hash + b" " + salt + b" " + password_hash + b" " + forcepass_hash + b"\n"

                        # brišemo stari zapis
                        deleteLine('userpassword.bin', index_linije)

                        # zapisivanje nove lozinke i podataka u binarnu datoteku 
                        with open('userpassword.bin', 'ab') as f:
                            f.write(zapis)

                        checker = 1
                        print("Login successful.")
                else:
                    print("Username or password incorrect.")
            else:  
                checker = 1
                print("Login successful.")
        else:
            print("Username or password incorrect.")


# poziv main funkcije na početku programa
main()