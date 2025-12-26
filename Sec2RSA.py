#---------Generate RSA Key Pair--------------------------------------------------
from Crypto.PublicKey import RSA  #Imports the RSA class from PyCryptodome. it allowsus to to generate, import, export RSA key objects (private + public)
from Crypto.Signature import pkcs1_15 #Imports the pkcs1_15 signing/verifying module that implements the PKCS#1 v1.5 signature scheme.
from Crypto.Hash import SHA256 #Imports the SHA-256 hashing algorithm implementation.

#pkcs1_15.new(key).sign(hash) to sign  
##pkcs1_15.new(key).verify(hash, signature) to verify.               

#key generation : 
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key() #Export the private key into PEM format (text-based encoding) This key is secret — used for signing messages
    public_key = key.publickey().export_key()#Extract and export the public key from the private key
    # This key is shareable — used for verifying signatures
    return private_key, public_key  #We convert RSA keys to PEM format so they can be safely stored, shared, and reused in a standard, readable format understood by cryptographic libraries.

#message sign creation  
def sign_message(message, private_key_pem):
    if not message.strip():   # Prevent empty messages
        print("Cannot sign an empty message.")
        return None
    private_key = RSA.import_key(private_key_pem)   #  load private key object
    message_bytes = message.encode('utf-8')         #   convert text 222 bytes
    h = SHA256.new(message_bytes)                   #  compute SHA-256 hash
    signer = pkcs1_15.new(private_key)              #  create signer with private key
    signature = signer.sign(h)                      #   uses my private RSA key to encrypt the message’s hash, creating a unique digital signature
    return signature                                # 13: return signature bytes

#Verify the Signature
def verify_signature(message, signature, public_key_pem):
    if not message.strip():   # Prevent empty messages
        print("Cannot verify an empty message.")
        return False
    public_key = RSA.import_key(public_key_pem)     #  load public key object
    message_bytes = message.encode('utf-8')         #  text 222 bytes
    h = SHA256.new(message_bytes)                   # compute SHA-256 hash This ensures the hash matches what the sender originally signed.
    verifier = pkcs1_15.new(public_key)             #  create verifier with public key (decrypt)
    try:
        verifier.verify(h, signature)              #  uses the public key to decrypt the signature and check if it matches the hash of the received message — confirming the message is original and not altered.
        return True                                 # if the signature is valid
    except (ValueError, TypeError):
        return False                                # invalid signature

def main():
    print("=== Digital Signature Playground ===")    # 21: header
    private_key_pem, public_key_pem = generate_keys()# 22: generate keys
    last_signature = None                            # 23: storage for last signature
    last_message = None                              # 24: storage for last message

    while True:
        print("\nMenu: 1=show keys  2=sign  3=verify  q=quit")  # 25: menu
        choice = input("Choice: ").strip()                    # 26: user choice

        if choice == "1":             # 27: show keys (PEM decode to readable text)
            print("\n--- PUBLIC KEY ---")
            print(public_key_pem.decode('utf-8'))
            print("\n--- PRIVATE KEY ---")
            print(private_key_pem.decode('utf-8'))
            # NOTE: never print private key in real apps

        elif choice == "2":             # 28: sign a new message and store signature
            msg = input("Enter message to sign: ").strip()
            if not msg:
                print("Cannot sign an empty message.")
                continue
            sig = sign_message(msg, private_key_pem)
            if sig is None:
                continue
            last_signature = sig
            last_message = msg
            print("\nSignature (hex):")
            print(sig.hex())                  # 29: show full signature in hex

        elif choice == "3":             # 30: verify
            if last_signature is not None:
                msg = input("Enter message to verify (stored signature will be used): ").strip()
                if not msg:
                    print("Cannot verify an empty message.")
                    continue
                sig = last_signature
                valid = verify_signature(msg, sig, public_key_pem)
                if valid:
                    print("Signature valid.")
                else:
                    print("⚠️ Message does not match stored signature!")
            else:
                print("No stored signature available. Cannot verify message without a signature.")

        elif choice.lower() == "q":
            print("Bye.")   # 33: exit message
            break

        else:
            print("Unknown choice.")  # 34: fallback

if __name__ == "__main__":
    main()  # 35: run the program
