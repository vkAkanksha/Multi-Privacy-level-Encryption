import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import encryption

def decryption(filename,dkey):
    
    # ----------reading the file----------
    tf1 = open(filename, "rb")
    text = tf1.read()
    tf1.close()
   
    # ------aes decryption-----
    backend = default_backend()
    key = b'\xa9\x15!\xbc\x857\x18\xca?8\x95\x8a\x0f\xbdR\xd2\x10\xfc\xd2\xb8\xd2n\xda\xc9\xcd\xd4a\x95d\xc6e\x94'
    iv = b'\xa6\x19\x1fm\x80W\x8a/\xab;-@$]\x80-'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    pt = decryptor.update(text) + decryptor.finalize()
    # print(pt.decode())

    aesd = pt.decode()  #AES decrypted message
     
    key = encryption.encryption_key(dkey)

    # -------vigenere decoding--------


    def vigenere_d(enc_msg, ke):
        if(ke == 'C'):
            if(enc_msg == 'G'):
                msg = 'A'
            elif(enc_msg == 'T'):
                msg = 'C'
            elif(enc_msg == 'A'):
                msg = 'G'
            elif(enc_msg == 'C'):
                msg = 'T'
        elif(ke == 'T'):
            if(enc_msg == 'A'):
                msg = 'A'
            elif(enc_msg == 'C'):
                msg = 'C'
            elif(enc_msg == 'G'):
                msg = 'G'
            elif(enc_msg == 'T'):
                msg = 'T'
        elif(ke == 'A'):
            if(enc_msg == 'T'):
                msg = 'A'
            elif(enc_msg == 'G'):
                msg = 'C'
            elif(enc_msg == 'C'):
                msg = 'G'
            elif(enc_msg == 'A'):
                msg = 'T'
        elif(ke == 'G'):
            if(enc_msg == 'C'):
                msg = 'A'
            elif(enc_msg == 'A'):
                msg = 'C'
            elif(enc_msg == 'T'):
                msg = 'G'
            elif(enc_msg == 'G'):
                msg = 'T'
        return msg


    split_aesd = [aesd[i:i+len(key)] for i in range(0, len(aesd), len(key))]
    
    dec = ''
    for each_split in split_aesd:
        i = 0
        for n in range(0, len(each_split)):
            dec += vigenere_d(each_split[n], key[n % len(key)])
    #print("Vigenere cipher decode: "+dec)

    bina = ''
    # --DNA decodeing-----------
    for i in dec:
        if(i == 'A'):
            bin = '00'
        elif(i == 'C'):
            bin = '01'
        elif(i == 'G'):
            bin = '10'
        elif(i == 'T'):
            bin = '11'
        bina += bin
    # print(bina)

    split_d = [bina[i:i+8] for i in range(0, len(bina), 8)]
    # print(split_d)


    asci = []
    lis = []
    li = []


    for each in split_d:
        res = 0
        for ele in each:
            res = (res << 1) | int(ele)
        li.append(res)
    # print(li)

    rs = ""
    for val in li:
        rs = rs + chr(val)
    # print(str(rs))

    file = open("dec"+filename, 'w')
    file.write(str(rs))
    file.close()
