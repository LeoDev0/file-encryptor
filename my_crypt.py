# 1- Refatorar o código usando orientação a objetos para diminuir as repetições
# 2- Implementar a desencriptação via keyfile
# 3- Implementar encriptação recursiva (criptografar arquivos dentro das pastas da pasta principal) pastas) 

from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time
from getpass import getpass
from huepy import *
import zipfile

# Aqui são selecionados apenas os arquivos no diretório, excluindo pastas dentro dele
arquivos = []
for c in os.listdir():
    if os.path.isfile(c) == True:
        arquivos.append(c)

# Função que dá o nome do arquivo zipado
zip_name = os.getcwd().split('/')[-1]+'.zip'


def ls():
    print('-' * 100)
    print(lightcyan('Files in this directory: '))
    print()
    for c in os.listdir():
        if os.path.isdir(c) == True:
            print(blue(c))
        else:
            print(c)

def encrypt_and_zip():
    input_da_senha = getpass('\nCrie uma senha: ') # Aqui a senha é escolhida
    senha = input_da_senha.encode()  # Converte pra bytes
    salt = b'u\xfc\x18\x05j\xac\x97>\xcb1m\x9c\x95\x8d2\xb6'  # Pode ser gerado uma nova com 'import os --> os.urandom(16)'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(senha))  # Chave gerada
    fernet = Fernet(key)
    print('\nEncrypting and compressing all files...')

    for filename in arquivos:
        if filename != 'my_crypt.py':
            with open(filename, 'rb') as f:
                data = f.read()
            encrypted = fernet.encrypt(data)
            with open(filename+'.enc', 'wb') as f:
                f.write(encrypted)
                os.remove(filename)

    # Zipando os arquivos encriptados
    arquivos_encriptados = []
    for c in os.listdir():
        if os.path.isfile(c) == True:
            arquivos_encriptados.append(c)
    
    zf = zipfile.ZipFile(zip_name, 'w')
    for c in arquivos_encriptados:
        if c != 'my_crypt.py' and c != '.my_crypt.py.swp':
            zf.write(c, compress_type=zipfile.ZIP_DEFLATED)
            os.remove(c)



def decrypt_and_unzip():
    # Unziping stuff
    with zipfile.ZipFile(zip_name) as zf:
        zf.extractall()
        os.remove(zip_name)

    arquivos_encriptados = []
    for c in os.listdir():
        if os.path.isfile(c) == True:
            arquivos_encriptados.append(c)

    input_da_senha = getpass('\nDigite sua senha: ')  # Aqui a senha é escolhida
    senha = input_da_senha.encode()  # Converte pra bytes
    salt = b'u\xfc\x18\x05j\xac\x97>\xcb1m\x9c\x95\x8d2\xb6'  # Pode ser gerado uma nova com 'import os --> os.urandom(16)'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(senha))  # Chave gerada
    fernet = Fernet(key)
    print('\nDecompressing and decrypting files...')

    for filename in arquivos_encriptados:
        if filename != 'my_crypt.py':
            with open(filename, 'rb') as f:
                data = f.read()
            encrypted = fernet.decrypt(data)
            with open(filename[:-4], 'wb') as f:
                f.write(encrypted)
                os.remove(filename)



def decrypt_allfiles():
    input_da_senha = getpass('\nDigite sua senha: ')  # Aqui a senha é escolhida
    senha = input_da_senha.encode()  # Converte pra bytes
    salt = b'u\xfc\x18\x05j\xac\x97>\xcb1m\x9c\x95\x8d2\xb6'  # Pode ser gerado uma nova com 'import os --> os.urandom(16)'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(senha))  # Chave gerada
    fernet = Fernet(key)
    print('\nDecrypting all files...')

    for filename in arquivos:
        if filename != 'my_crypt.py':
            with open(filename, 'rb') as f:
                data = f.read()
            encrypted = fernet.decrypt(data)
            with open(filename[:-4], 'wb') as f:
                f.write(encrypted)
                os.remove(filename)



def encrypt_allfiles():
    input_da_senha = getpass('\nCrie uma senha: ') # Aqui a senha é escolhida
    senha = input_da_senha.encode()  # Converte pra bytes
    salt = b'u\xfc\x18\x05j\xac\x97>\xcb1m\x9c\x95\x8d2\xb6'  # Pode ser gerado uma nova com 'import os --> os.urandom(16)'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(senha))  # Chave gerada
    fernet = Fernet(key)
    print('\nEncrypting all files...')

    for filename in arquivos:
        if filename != 'my_crypt.py':
            with open(filename, 'rb') as f:
                data = f.read()
            encrypted = fernet.encrypt(data)
            with open(filename+'.enc', 'wb') as f:
                f.write(encrypted)
                os.remove(filename)


def encrypt():
    filename = input("\nType the name of the file you want to encrypt: ")
    input_da_senha = getpass('\nCreate a password: ') # Aqui a senha é escolhida
    print('\nEncrypting stuff...')
    senha = input_da_senha.encode()  # Converte pra bytes
    salt = b'u\xfc\x18\x05j\xac\x97>\xcb1m\x9c\x95\x8d2\xb6'  # Pode ser gerado uma nova com 'import os --> os.urandom(16)'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(senha))  # Chave gerada
    fernet = Fernet(key)


    with open(filename, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(filename + '.enc', 'wb') as f:
        f.write(encrypted)
        os.remove(filename)



def decrypt():
    filename = input("\nEncrypted file's name (ends with '.enc'): ")
    input_da_senha = getpass('\nType your password: ')  # Aqui a senha é escolhida
    print('\nEncrypting stuff...')
    senha = input_da_senha.encode()  # Converte pra bytes
    salt = b'u\xfc\x18\x05j\xac\x97>\xcb1m\x9c\x95\x8d2\xb6'  # Pode ser gerado uma nova com 'import os --> os.urandom(16)'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(senha))  # Chave gerada
    fernet = Fernet(key)

    with open(filename, 'rb') as f:
        data = f.read()
    encrypted = fernet.decrypt(data)
    with open(filename[:-4], 'wb') as f:
        f.write(encrypted)
        os.remove(filename)


rodando = True
while rodando == True:

    print('-'*100)
    decide = str(input('''\n\nWhat do you want to do?
    
    1) Encrypt a single file
    
    2) Decrypt a single file
    
    3) Encrypt all files in the directory
    
    4) Decrypt all files in the directory

    5) Compress and encrypt all files

    6) Decompress and decrypt all files
    
    7) List files in this directory
    
    8) Exit
    
    '''))


    if decide == '1':
        ls()
        encrypt()
        print('\nData encrypted succesfully!')

    elif decide == '2':
        ls()
        decrypt()
        print('\nData decrypted succesfully!')

    elif decide == '3':
        encrypt_allfiles()
        print('\nData encrypted succesfully!')

    elif decide == '4':
        decrypt_allfiles()
        print('\nData decrypted succesfully!')

    elif decide == '5':
        encrypt_and_zip()
        print('\nData encrypted and compressed succesfully!')

    elif decide == '6':
        decrypt_and_unzip()
        print('\nData decompressed and decrypted succesfully!')

    elif decide == '7':
        ls()

    elif decide == '8':
        rodando = False
        print('\nShutting down...')
        time.sleep(2)

    else:
        print('\nInvalid entry! Your options are between 1-8.')





# Salvando chave num arquivo de texto
'''with open('teste.txt', 'wb') as f:
    f.write(key)'''
