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

# funkcija za brisanje linije
def deleteLine(imeDatoteke, brojLinije):
    with open(imeDatoteke, 'rb') as f:
        lines = f.readlines()
    del lines[brojLinije]
    with open(imeDatoteke, 'wb') as f:
        f.writelines(lines)

# funkcija za ispis binarne datoteke
def ispisi(imeDatoteke):
    with open(imeDatoteke, 'rb') as f:
        lines = f.readlines()

    print(f"\nSadržaj datoteke {imeDatoteke} je:")
    for linija in lines:
        print(linija)
    print("\n")


def main():

    # dodavanje novog korisničkog imena
    if sys.argv[1] == "add":
        # učitavanje user-a i hashanje
        user = sys.argv[2]
        user_bin = user.encode('utf-8')
        user_hash = hashaj(user_bin)
        user_hash = binascii.unhexlify(user_hash)
        user_hash = base64.b64encode(user_hash)

        # učitavanje podataka
        with open('userpassword.bin','rb') as f:
            lines = f.readlines()

        # provjera postoji li već user
        for i in range(len(lines)):
            zapis = lines[i].split(b" ")
            procitani_user = zapis[0]

            # ukoliko pronađemo usera, prekidamo program
            if user_hash == procitani_user:
                print("User already exists.")
                exit()

        # učitavanje željene lozinke
        password = getpass.getpass(prompt="Password: ")
        repeated_password = getpass.getpass(prompt="Repeat Password: ")
        
        # regex za lozinku - barem jedno veliko slovo, malo slovo, broj i specijalni znak (samo za ASCII vrijednosti 33 do 126 uključivo)
        password_regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!-\/:-@\[-`\{-~])[A-Za-z0-9!-\/:-@\[-`\{-~]+$'

        # ispravno
        if password == repeated_password and re.fullmatch(password_regex, password) != None: 
            
            # stvaranje salt-a
            salt = get_random_bytes(16)
            
            # hashanje kombinacije salta i passworda
            password_bin = password.encode('utf-8')
            password_hash = PBKDF2(password_bin, salt, 32, 1000000, hmac_hash_module=SHA256)
            
            # inicijaliziranje forcepass zastavice i hashanje forcepassa 
            forcepass = 0
            forcepass_bin = forcepass.to_bytes((forcepass.bit_length() + 7) // 8, "big")
            forcepass_hash = hashaj(forcepass_bin)

            # pretvaranje iz hex u bin
            password_hash = base64.b64encode(password_hash)
            forcepass_hash = binascii.unhexlify(forcepass_hash)
            forcepass_hash = base64.b64encode(forcepass_hash)

            # stvaranje zapisa za spremanje
            zapis = user_hash + b" " + salt + b" " + password_hash + b" " + forcepass_hash + b"\n"

            # zapisivanje u binarnu datoteku
            with open('userpassword.bin', 'ab') as f:
                f.write(zapis)

            print(f"User {user} successfuly added.")
        else:
            print("User add failed. Password mismatch or too weak. Minimum length of the password is 8 characters. It must contain at least one uppercase letter, one lowercase letter, one number and one special character.")


    
    
    # promjena lozinke postojećeg korisničkog imena
    if sys.argv[1] == "passwd":
        user = sys.argv[2] 

        # učitavanje željenih podataka
        password = getpass.getpass(prompt="Password: ")
        repeated_password = getpass.getpass(prompt="Repeat password: ")

        # regex za lozinku - barem jedno veliko slovo, malo slovo, broj i specijalni znak (samo za ASCII vrijednosti 33 do 126 uključivo)
        password_regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!-\/:-@\[-`\{-~])[A-Za-z0-9!-\/:-@\[-`\{-~]+$'
        
        # ispravno
        if password == repeated_password and re.fullmatch(password_regex, password) != None: 

            # čitanje iz datoteke
            with open('userpassword.bin', 'rb') as f:
                lines = f.readlines()

            # hashanje user, da možemo usporediti s onima iz baze
            user_bin = user.encode('utf-8')
            user_hash = hashaj(user_bin)
            user_hash = binascii.unhexlify(user_hash)
            user_hash = base64.b64encode(user_hash)

            # provjera imamo li usera u datoteci sa userima i lozinkama
            detected = 0
            for i in range(len(lines)):
                zapis = lines[i].split(b" ")
                procitani_user = zapis[0]

                # ukoliko pronađemo usera, obrišemo postojeće informacije
                if user_hash == procitani_user:
                    detected = 1
                    deleteLine('userpassword.bin', i)
                    break

            # provjera jesmo li pronašli user za kojeg trebamo promjeniti lozinku
            if detected == 0:
                print("Username doesn't exist.")
                exit()
            
            # stvaranje salt-a
            salt = get_random_bytes(16)
            
            # hashanje kombinacije salta i passworda
            password_bin = password.encode('utf-8')
            password_hash = PBKDF2(password_bin, salt, 32, 1000000, hmac_hash_module=SHA256)
            
            # inicijaliziranje forcepass zastavice i hashanje forcepassa 
            forcepass = 0
            forcepass_bin = forcepass.to_bytes((forcepass.bit_length() + 7) // 8, "big")
            forcepass_hash = hashaj(forcepass_bin)

            # pretvaranje iz hex u bin
            password_hash = base64.b64encode(password_hash)
            forcepass_hash = binascii.unhexlify(forcepass_hash)
            forcepass_hash = base64.b64encode(forcepass_hash)

            # stvaranje zapisa za upis u datoteku
            zapis = user_hash + b" " + salt + b" " + password_hash + b" " + forcepass_hash + b"\n"

            # zapisivanje nove lozinke i podataka u binarnu datoteku 
            with open('userpassword.bin', 'ab') as f:
                f.write(zapis)

            print("Password change successful.")
        else:
            print("User add failed. Password mismatch or too weak. Minimum length of the password is 8 characters. It must contain at least one uppercase letter, one lowercase letter, one number and one special character.")
    
    
    # forsiranje promjene lozinke korisničkog imena
    if sys.argv[1] == "forcepass":
        user = sys.argv[2]
        user_bin = user.encode('utf-8')
        user_hash = hashaj(user_bin)
        user_hash = binascii.unhexlify(user_hash)
        user_hash = base64.b64encode(user_hash)

        # učitavanje podataka
        with open('userpassword.bin','rb') as f:
            lines = f.readlines()

        detected = 0
        # provjera postoji li već user
        for i in range(len(lines)):
            zapis = lines[i].split(b" ")
            procitani_user = zapis[0]

            # ukoliko pronađemo usera, prekidamo program
            if user_hash == procitani_user:
                detected = 1
                user_pamti = zapis[0]
                salt_pamti = zapis[1]
                password_pamti = zapis[2]
                forcepass = 1
                forcepass_bin = forcepass.to_bytes((forcepass.bit_length() + 7) // 8, "big")
                forcepass_hash = hashaj(forcepass_bin)
                forcepass_hash = binascii.unhexlify(forcepass_hash)
                forcepass_hash = base64.b64encode(forcepass_hash)
                deleteLine('userpassword.bin', i)

                # spremanje promjenjenih podataka s podignutom forcepass zastavicom
                zapis = user_pamti + b" " + salt_pamti + b" " + password_pamti + b" " + forcepass_hash + b"\n"
                with open('userpassword.bin', 'ab') as f:
                    f.write(zapis)

        if detected == 0:
            print("Username doesn't exist.")
            exit()

        print("User will be requested to change password on next login.")

    
    # uklanjanje postojećeg korisničkog imena
    if sys.argv[1] == "del":
        user = sys.argv[2]
        user_bin = user.encode('utf-8')
        user_hash = hashaj(user_bin)
        user_hash = binascii.unhexlify(user_hash)
        user_hash = base64.b64encode(user_hash)

        # učitavanje podataka
        with open('userpassword.bin','rb') as f:
            lines = f.readlines()

        # provjera postoji li već user
        for i in range(len(lines)):
            zapis = lines[i].split(b" ")
            procitani_user = zapis[0]

            # ukoliko pronađemo usera, prekidamo program
            if user_hash == procitani_user:
                deleteLine('userpassword.bin', i)

        print("User successfuly removed.")


# poziv main funkcije na početku programa
main()