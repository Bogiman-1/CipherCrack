# CipherCrack


**CipherCrack** is a simple yet effective password hash cracking tool designed for cybersecurity enthusiasts and professionals. It uses dictionary attacks to crack common hash types such as MD5, SHA-1, and SHA-256. This tool helps users understand the vulnerabilities associated with weak passwords and demonstrates how easy it can be to crack hashes using pre-made wordlists. **CipherCrack** is primarily intended for educational purposes and should only be used on authorized systems or for ethical hacking practices.

### **Features:**
- Supports cracking of MD5, SHA-1, and SHA-256 hashes.
- Performs dictionary attacks using a custom wordlist.
- Fast and efficient, suitable for both beginners and professionals.

---

### **Usage Instructions:**

1. **Install Python Dependencies** (if necessary):
   - No external libraries required; uses Python’s built-in `hashlib` module.

2. **Prepare a Wordlist:**
   - Use a wordlist like `rockyou.txt` or create your own with common passwords.

3. **Run the Script:**

   ```bash
   python CipherCrack.py <hash> <algorithm> <wordlist>
   ```

   - `<hash>`: The hash you want to crack (e.g., `5d41402abc4b2a76b9719d911017c592`).
   - `<algorithm>`: Hash algorithm to use (`md5`, `sha1`, or `sha256`).
   - `<wordlist>`: Path to the wordlist file (e.g., `wordlist.txt`).

4. **Example:**

   ```bash
   python CipherCrack.py 5d41402abc4b2a76b9719d911017c592 md5 wordlist.txt
   ```

   - In this example, the tool will attempt to crack the MD5 hash for "hello" using the provided wordlist.

---

### **Output:**
- If the password is found, it will display:
  ```bash
  [+] Password found: hello
  ```

- If the password isn't in the wordlist, it will display:
  ```bash
  [-] No match found.
