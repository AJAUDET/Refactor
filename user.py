#   Author : AJ Audet
#   Purpose : Implementing adding a user and their password as a hash to a file
#   ALT : Basis for how we add/verify users for Secure Drop
import json
import sys
import os
import pwinput
import string
import math
from password import create_salted_hash
from Crypto.PublicKey import RSA

PUB_DIR = "public_keys"
PRIV_DIR = "private_keys"

EMAIL_CONSTRAINT = '@'
EMAIL_CONSTRAINT_DOMAIN = ['.com', '.org', '.net', '.edu', '.gov']

if not os.path.exists(PUB_DIR):
    os.makedirs(PUB_DIR)
if not os.path.exists(PRIV_DIR):
    os.makedirs(PRIV_DIR)

def password_entropy(password):
    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)

    if charset_size == 0:
        return 0  # No valid characters

    # Entropy = length * log2(charset_size)
    entropy = len(password) * math.log2(charset_size)
    return entropy

def is_password_allowed(password, min_entropy=50):
    """
    Check if password meets minimum entropy requirement.
    """
    entropy = password_entropy(password)
    if entropy >= min_entropy:
        return True, entropy
    else:
        return False, entropy


def complex_check():
    pwd = pwinput.pwinput(prompt="Enter your Password: ", mask='*')
    if is_password_allowed(pwd)[0]:
        return pwd
    return None

def add_user():
    username = input("Enter your Username: ")
    email = input("Enter your Email: ")
    if any(word in email for word in EMAIL_CONSTRAINT_DOMAIN) and EMAIL_CONSTRAINT in email:
        pass
    else:
        print("Invalid email format. Please include a valid domain (e.g., .com, .org).")
        email = input("Enter your Email: ")
    while not email:
        print("Email cannot be empty. Please enter a valid email.")
        email = input("Enter your Email: ")
    pwd = complex_check()
    while not pwd:
        print("Password does not meet complexity requirements. Please enter 13 or more characters.")
        pwd = complex_check()
        
    pwd2 = pwinput.pwinput(prompt="Reenter your Password: ", mask='*')
    if(pwd != pwd2):
        print("Passwords do not match, try again\n")
    try:
        if os.path.exists('passwd.json'):
            with open('passwd.json', 'r') as outF:
                data = json.load(outF)
                if "User" in data:
                    old_usr = data["User"]
                    old_pwd = data["Password"]
                    data = {
                        "Users": {
                            old_usr : {
                                "Password":old_pwd,
                                "Email":"",
                                "Public Key":""
                            }
                        }
                    }
        else:
            data = {"Users": {}}

        if username in data["Users"]:
            print(f"User already registered")
            return

        private_key = RSA.generate(2048)
        public_key = private_key.public_key()
        
        private_key_str = private_key.export_key().decode("utf-8")
        public_key_str = public_key.export_key().decode("utf-8")
        
        pwd_hash = create_salted_hash(pwd)
        
        data["Users"][username] = {
            "Password": pwd_hash,
            "Email": email,
            "Public Key": public_key_str
            }
        with open('passwd.json', 'w') as outF:
            json.dump(data, outF, indent=2)

        keys_path = os.path.join(PUB_DIR, 'keys.json')
        if os.path.exists(keys_path):
            with open(keys_path, 'r') as inF:
                pub_keys_data = json.load(inF)
        else:
            pub_keys_data = {"Users": {}}
        pub_keys_data["Users"][username] = {
            "Public Key": public_key_str
        }
        with open(keys_path, 'w') as outF:
            json.dump(pub_keys_data, outF, indent=2)

        with open(os.path.join(PUB_DIR, f"{username}.pub"), 'w') as outF:
            data = public_key_str
            print(f"{data}", file=outF)

        with open(os.path.join(PRIV_DIR, f"{username}.priv"), 'w') as outF:
            data = private_key_str
            print(f"{data}", file=outF)
        print("User created successfully\n")
        return username   
    except json.JSONDecodeError:
        print("Error: Corrupted database file")
    except PermissionError:
        print("Error: No permission to write to file")
    except Exception as e:
        print(f"Error adding user: {type(e).__name__}")
          

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print(f"Usage:")
        print(f"\tpython3 add_user.py --add <outFile>")
        sys.exit(1)
    mode = sys.argv[1]
    
    if mode == '--add':
        add_user()
    else:
        print(f"Improper Usage")