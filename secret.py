import os
import json
import base64
import ctypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass

SALT_FILE = "password_salt.bin"
DATA_FILE = "encrypted_passwords.bin"
ITERATIONS = 480000  #PBKDF2迭代次数，越高越安全但解密越慢

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_passwords(passwords: dict, master_password: str) -> None:
    salt = os.urandom(16)   #生成随机盐值
    key = generate_key(master_password, salt)  #根据口令生成key
    cipher_suite = Fernet(key)   #根据key使用Fernet加密算法生成加密套件

    #加密所有密码
    encrypted_data = {}
    for name, pwd in passwords.items():
        encrypted_data[name] = cipher_suite.encrypt(pwd.encode()).decode()
    
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    with open(DATA_FILE, 'w') as f:
        json.dump(encrypted_data, f)

    print(f"successfully stored {len(passwords)} secrets")

def decrypt_passwords(master_password: str) -> dict:
    try:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
        with open(DATA_FILE, 'r') as f:
            encrypted_data = json.load(f)

        key = generate_key(master_password, salt)
        cipher_suite = Fernet(key)

        decrypt_passwords = {}
        for name, encrypted_pwd in encrypted_data.items():
            decrypt_passwords[name] = cipher_suite.decrypt(encrypted_pwd.encode()).decode()
        
        return decrypt_passwords
    except Exception as e:
        print(f"decrypt failed: {str(e)}")
        return None

def secure_erase(data: str) -> None:
    #安全擦除内存中的数据
    if isinstance(data, str):
        data = data.encode()
        for i in range(3):  #多次覆盖，增强安全性
            ctypes.memset(id(data), 0, len(data))
            

def add_secrets():
    passwords = {}
    print("\nplease enter your secrets for store (input nothing for end):")
    while True:
        name = input("\nsecret name:").strip()
        if not name:
            break
        pwd = getpass(f"{name}'s secret:")
        passwords[name] = pwd

    if passwords:
        master_pwd = getpass("enter your key:")
        confirm_pwd = getpass("re-enter your key:")
        if master_pwd == confirm_pwd:
            encrypt_passwords(passwords, master_pwd)
            secure_erase(master_pwd)
            secure_erase(confirm_pwd)
        else:
            print("mismatch between two inputs")

def print_secrets():
    master_pwd = getpass("enter your key:")
    passwords = decrypt_passwords(master_pwd)
    if passwords:
        for name, pwd in passwords.items():
            print(f"{name} : {pwd}")
        
        secure_erase(master_pwd)
        for pwd in passwords.values():
            secure_erase(pwd)
    else:
        print("Error! the key is error!")

if __name__ == "__main__":
    add_secrets()