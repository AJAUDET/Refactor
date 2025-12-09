# Author : AJ Audet  
# Purpose : generate a public/private key pair and store them in a json string in a .txt file
# ALT : We can use this to generate a pub/priv key pair for our users after registration

import sys
import os
from Crypto.PublicKey import RSA

def generateKeys(pub, priv):
    priv_key = RSA.generate(2048)
    pub_key = priv_key.public_key()
    
    try:
        if os.path.exists(pub) or os.path.exists(priv):
            print("Error: Key files already exist")
            return

        with open(pub, 'wb') as pubF:
            pubF.write(pub_key.export_key())

        with open(priv, 'wb') as privF:
            privF.write(priv_key.export_key())

        os.chmod(priv, 0o600)
        
        print("Keys generated successfully")
        
    except Exception as e:
        print(f"Error generating keys: {type(e).__name__}")

if __name__ == '__main__':
    if (len(sys.argv) != 4):
        print(f"Usage:")
        print(f"\tpython3 keygen.py --generate <outfile_pubKey> <outfile_privFile>")
        sys.exit(1)

    mode = sys.argv[1]
    pubFile = sys.argv[2]
    privFile = sys.argv[3]
    
    if mode == '--generate':
        generateKeys(pubFile, privFile)
    else:
        print(f"Improper Usage")
        sys.exit(1)