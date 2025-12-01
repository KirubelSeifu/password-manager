import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# File Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_KEY_FILE = os.path.join(SCRIPT_DIR,'vault.key')
PASSWORDS_FILE = os.path.join(SCRIPT_DIR,'passwords.enc')

def generate_key_from_password(password):
    """Derive a secure encryption key from the master password."""
    # Convert password to bytes
    password_bytes =password.encode()
    
    # Create a salt (If vault.key doesn't exist yet, make one)
    if not os.path.exists(VAULT_KEY_FILE):
        salt = os.urandom(16)  # This Secure random salt
        with open(VAULT_KEY_FILE,'wb') as f:
            f.write(salt)
    else:
        with open(VAULT_KEY_FILE,'rb') as f:
            salt = f.read(16)  # Read existing salt
    
    # Derive key using PBKDF2 (Password-Based Key Derivation Function 2)
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 480000, # High Iteration Count For Security
    )       
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def initialize_vault():
    """ Check If This Is The First Run And Set Up The Master Password. """
    if not os.path.exists(VAULT_KEY_FILE):
        print("\n--- First Run: Create Master Password ---")
        print("This Password Will Encrypt ALL Your Stored Passwords.")
        print("DO NOT FORGET IT. It Cannot Be Recovered.\n")
        
        while True:
            master_pw = input("Set Your Master Password: ")
            confirm_pw = input("Confirm Master Password: ")
            if master_pw == confirm_pw:
                # Generate And Save The Key (Which Also Creates The salt file)
                generate_key_from_password(master_pw)
                print("Value Initialized Successfully!")
                return master_pw
            else:
                print("Password Do Not Match. Try Again.")
    else:
        # Vault exists, ask for master password to unlock  
        print("\n--- Unlock Vault ---")
        master_pw = input("Enter master password: ")
        
        #Try To Generate The Key (Will Fail If Password Is Wrong When Reading salt)
        try:
            generate_key_from_password(master_pw)
            return master_pw
        except Exception:
            print("Incorrect Master Password Or Corrupted Vault.")
            return None

def add_password(cipher, password_list):
    """Add A New Password Entry (encrypted)"""
    print("\n--- Add New Password ---")
    service = input("Enter The Website/App Name: ")
    username = input("Enter Your Username/Email: ")
    password = input("Enter Your Password: ")
    
    # Encrypt The Password
    encrypted_password = cipher.encrypt(password.encode())
    encrypted_password_str = base64.urlsafe_b64encode(encrypted_password).decode()
    
     #Create The Entry With The ENCRYPTED Password String
    entry ={
        'service': service,
        'username': username,
        'password': encrypted_password_str
    }
    
    #Add To in-memory List And Save The Updated List To File
    password_list.append(entry)
    save_passwords(password_list)  # FIXED: Removed cipher parameter
    print(f"Password for {service} added successfully!")
  
def save_passwords(passwords):  # FIXED: Removed cipher parameter
    """ Save Password To JSON File."""
    try:
       with open(PASSWORDS_FILE,'w') as file:
           json.dump(passwords,file,indent=4)
    except Exception as e:
        print(f"Error Saving Tasks: {e}")
          
def load_passwords():  # FIXED: Removed cipher parameter
    """Load Passwords From JSO File."""
    if not os.path.exists(PASSWORDS_FILE):
        return[]
    
    try:
        with open(PASSWORDS_FILE,'r') as file:
            passwords = json.load(file)
            return passwords
    except Exception as e:
        print(f"Error Loading Passwords: {e} ")
        return[]

def view_passwords(cipher, password_list):
    """View All Stored Passwords (Decrypted)"""    
    print("\n--- Stored Passwords---")
    if not password_list:
        print("No Password Stored Yet.")
        return
    for i,entry in enumerate(password_list,1):
        try:
            # Decrypt The Password
            encrypted_bytes = base64.urlsafe_b64decode(entry['password'])
            decrypted_password = cipher.decrypt(encrypted_bytes).decode()
            print(f"{i}. Service:  {entry['service']}")
            print(f"   Username: {entry['username']}")
            print(f"   Password: {decrypted_password}")
            print("-" * 30)  
        except Exception as e:
            print(f"Error Decoding Password For {entry['service']}: {e}")

def main():
    """Main Program Loop"""
    print("\n==== Secure Password Manger ===")
    
    #Initialize Or Unlock The Vault
    master_password = initialize_vault()
    if not master_password:
        print("Failed To Unlock Vault. Exiting.")
        return
    
    # Generate The Encryption Key Object
    encryption_key = generate_key_from_password(master_password)
    cipher = Fernet(encryption_key)
    
    # Load Existing Passwords - FIXED: Actually call load_passwords()
    password_list = load_passwords()  # FIXED: Initialize the variable
    
    # Main Menu Loop - FIXED: Proper indentation INSIDE main()
    while True:
        print("\n--- Password Manager Menu ---")
        print("1. Add New Password")
        print("2. View All Passwords")
        print("3. Exit")

        choice = input("Please Enter Your Choice (1-3): ")

        if choice == "1":
            add_password(cipher, password_list)
        elif choice == "2":
            view_passwords(cipher, password_list)
        elif choice == "3":
            print("Good Bye!")
            break
        else: 
            print("Invalid Choice. Please enter 1, 2, or 3.")
    
if __name__ == "__main__":
     main()