from cryptBreak import cryptBreak
from BitVector import *
from tqdm import tqdm

BLOCKSIZE = 16
numbytes = BLOCKSIZE // 8
PassPhrase = "Hopes and dreams of a million years" 
f = open('cipherText.txt', 'r')
encrypted_bv = BitVector(hexstring=f.read())

for RandomInteger in tqdm(range(65536)):
    key_bv = BitVector ( intVal = RandomInteger , size =16 )
    decryptedMessage = cryptBreak ('cipherText.txt', key_bv )
    if 'Ferrari'  in decryptedMessage:
        print ('Encryption Broken !')
        print(RandomInteger)
        print(decryptedMessage)
        break
f.close()