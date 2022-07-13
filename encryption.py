import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from sys import getsizeof

def encryption(filename,enc_key):
    
    backend = default_backend()
    key = b'\xa9\x15!\xbc\x857\x18\xca?8\x95\x8a\x0f\xbdR\xd2\x10\xfc\xd2\xb8\xd2n\xda\xc9\xcd\xd4a\x95d\xc6e\x94'
    iv = b'\xa6\x19\x1fm\x80W\x8a/\xab;-@$]\x80-'    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    encryption_code(filename,cipher,enc_key)

# ----------reading the file----------


def read_file(name):
    tf = open(name, "r")
    text = tf.read()
    return text
    tf.close()

# ----------converting to binary----------


def con_bin(n):
    bnr = bin(n).replace('0b', '')
    x = bnr[::-1]  # this reverses an array
    while len(x) < 8:
        x += '0'
    bnr = x[::-1]
    return bnr


# ----------converting to ASCII----------
def dna_enc(text):
    ASCII_values = []
    for character in text:
        ASCII_values.append(ord(character))

    #print(ASCII_values)

    binary = []
    for a in ASCII_values:
        binary.append(con_bin(a))
    #print(binary)

    # -------------converting to dna--------------
    # dnl = []
    d = ''
    A = '00'
    C = '01'
    G = '10'
    T = '11'
    for a in binary:
        for i in range(0, len(a), 2):
            op = str(a[i])+str(a[i+1])
            dna = ''
            if(op == A):
                dna += 'A'
            elif(op == C):
                dna += 'C'
            elif(op == G):
                dna += 'G'
            elif(op == T):
                dna += 'T'
            d = d+dna
    #print("After DNA :"+d)  # dna encrypted string
    return d

# -------vigenere cipher--------


def vigenere(mes, ke):
    if(mes == 'A' and ke == 'C'):
        res = 'G'
    elif(mes == 'A' and ke == 'T'):
        res = 'A'
    elif(mes == 'A' and ke == 'A'):
        res = 'T'
    elif(mes == 'A' and ke == 'G'):
        res = 'C'
    elif(mes == 'C' and ke == 'C'):
        res = 'T'
    elif(mes == 'C' and ke == 'T'):
        res = 'C'
    elif(mes == 'C' and ke == 'A'):
        res = 'G'
    elif(mes == 'C' and ke == 'G'):
        res = 'A'
    elif(mes == 'G' and ke == 'C'):
        res = 'A'
    elif(mes == 'G' and ke == 'T'):
        res = 'G'
    elif(mes == 'G' and ke == 'A'):
        res = 'C'
    elif(mes == 'G' and ke == 'G'):
        res = 'T'
    elif(mes == 'T' and ke == 'C'):
        res = 'C'
    elif(mes == 'T' and ke == 'T'):
        res = 'T'
    elif(mes == 'T' and ke == 'A'):
        res = 'A'
    elif(mes == 'T' and ke == 'G'):
        res = 'G'
    return res


def vig_enc(d, key):
    enc = ''
    split_d = [d[i:i+len(key)] for i in range(0, len(d), len(key))]
    
    for each_split in split_d:
        i = 0
        for n in range(0, len(each_split)):
            enc += vigenere(each_split[n], key[n % len(key)])
    #print("Vigenere cipher: "+enc)
    return enc


# --AES------

def aes_enc(enc,cipher):
    encryptor = cipher.encryptor()
    ct = encryptor.update(enc.encode()) + encryptor.finalize()
    #print("ct:")
    #print(ct)
    return ct


def save(fname, ct):
    file = open(fname, 'wb')
    file.write(ct)
    file.close()


def encryption_code(filename,cipher,enc_key):
    f_content = read_file(filename)
    
    fc_len = len(f_content)
    
    pad=0
    if(fc_len % 16 != 0):
        a = fc_len % 16        
        pad = 16-a       # no. of extra spaces to be padded
        

    # print(pad)
    while(pad):
        f_content += ' '
        pad = pad-1
    
    dna_code = dna_enc(f_content)
    
    key_dna = encryption_key(enc_key)

    vig_code = vig_enc(dna_code, key_dna)

    aes_code = aes_enc(vig_code,cipher)

    save("enc"+filename, aes_code)


def encryption_key(keyn):
    content = keyn
    dna_code = dna_enc(content)
    #print("Key dna: "+dna_code)
    return dna_code


def aes_dec(text,cipher):
    decryptor = cipher.decryptor()
    pt = decryptor.update(text) + decryptor.finalize()
    #print(pt.decode())
    return pt.decode()


