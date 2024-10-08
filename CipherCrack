import hashlib
import argparse

# ASCII banner for CipherCrack
def show_banner():
    banner = r"""
      /$$$$$$  /$$           /$$                          
     /$$__  $$|__/          | $$                          
    | $$  \__/ /$$  /$$$$$$ | $$$$$$$   /$$$$$$   /$$$$$$ 
    | $$      | $$ /$$__  $$| $$__  $$ /$$__  $$ /$$__  $$
    | $$      | $$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
    | $$    $$| $$| $$  | $$| $$  | $$| $$_____/| $$      
    |  $$$$$$/| $$| $$$$$$$/| $$  | $$|  $$$$$$$| $$      
     \______/ |__/| $$____/ |__/  |__/ \_______/|__/      
                   | $$                                   
                   | $$                                   
                   |__/                                   
      /$$$$$$                               /$$           
     /$$__  $$                             | $$           
    | $$  \__/  /$$$$$$  /$$$$$$   /$$$$$$$| $$   /$$     
    | $$       /$$__  $$|____  $$ /$$_____/| $$  /$$/     
    | $$      | $$  \__/ /$$$$$$$| $$      | $$$$$$/      
    | $$    $$| $$      /$$__  $$| $$      | $$_  $$      
    |  $$$$$$/| $$     |  $$$$$$$|  $$$$$$$| $$ \  $$     
     \______/ |__/      \_______/ \_______/|__/  \__/     
    """
    print(banner)

# Dictionary attack to crack hash
def crack_hash(hash_value, algorithm, wordlist):
    with open(wordlist, 'r', encoding="utf-8") as file:
        for line in file:
            password = line.strip()
            # Hash the password based on the algorithm provided
            hashed_password = hash_password(password, algorithm)

            if hashed_password == hash_value:
                return password
    return None

# Hash the password using the selected algorithm
def hash_password(password, algorithm):
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm: Use 'md5', 'sha1', or 'sha256'.")

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description="CipherCrack - A Simple Password Hash Cracking Tool")
    parser.add_argument("hash_value", help="The hash value to crack")
    parser.add_argument("algorithm", help="The hash algorithm (md5, sha1, sha256)")
    parser.add_argument("wordlist", help="Path to the wordlist file")
    args = parser.parse_args()

    print(f"[+] Attempting to crack {args.algorithm} hash: {args.hash_value}")
    
    cracked_password = crack_hash(args.hash_value, args.algorithm, args.wordlist)
    
    if (cracked_password):
        print(f"[+] Password found: {cracked_password}")
    else:
        print("[-] No match found.")

if __name__ == "__main__":
    main()
