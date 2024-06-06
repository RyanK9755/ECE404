from BitVector import *

#######################################################################
# Citation: Lecture 2 code: DecryptForFun.py, Avinash Kak
#######################################################################

def cryptBreak (ciphertextFile, key_bv):
# Arguments :
# * ciphertextFile : String containing file name of the ciphertext
# * key_bv : 16 -bit BitVector for the decryption key
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8
    PassPhrase = "Hopes and dreams of a million years" 
    f = open(ciphertextFile, 'r')
    encrypted_bv = BitVector(hexstring=f.read())

    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
    for i in range(0,len(PassPhrase) // numbytes):
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
        bv_iv ^= BitVector(textstring = textstr)      

    decrypted_bv = BitVector(size = 0)

    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^=  previous_decrypted_block
        previous_decrypted_block = temp
        bv ^=  key_bv
        decrypted_bv += bv

    decrypted_message = decrypted_bv.get_text_from_bitvector()
    f.close()
    return decrypted_message
