import sys
from BitVector import *
class AES():

    # class constructor- when creating an AES object, the
    # class’s constructor is executed and instance variables
    # are initialized

    ######################################################
    #CITATION: LECTURE 8 CODE BY PROF AVI KAK USED FOR HW4
    ######################################################
    def __init__(self, keyfile:str)-> None:
        self.AES_modulus = BitVector(bitstring='100011011')
        f = open(keyfile, 'r')
        self.subBytesTable = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
        self.invSubBytesTable = [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]
        self.key_bv = BitVector(textstring = f.read())
        self.key_words = self.gen_key_schedule_256()
        f.close()

    def gee(self, keyword, round_constant):
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = self.subBytesTable[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant
    
    def gen_key_schedule_256(self):
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = self.key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = self.subBytesTable[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8]
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        num_rounds = 14
        round_keys = [None for i in range(num_rounds+1)]
        for i in range(num_rounds+1):
            round_keys[i] = key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]
        return round_keys

    def bv_to_state(self, bv):
        statearray = [[0 for x in range(4)] for x in range(4)]
        for i in range(4):
            for j in range(4):
                statearray[j][i] = bv[32*i + 8*j:32*i + 8*(j+1)]
        return statearray

    def state_to_bv(self, bv_state):
        return bv_state[0][0] + bv_state[1][0] + bv_state[2][0] + bv_state[3][0] + bv_state[0][1] + bv_state[1][1] + bv_state[2][1] + bv_state[3][1] + bv_state[0][2] + bv_state[1][2] + bv_state[2][2] + bv_state[3][2] + bv_state[0][3] + bv_state[1][3] + bv_state[2][3] + bv_state[3][3]

    def shiftRows(self, bv_state, encrypt):
        if encrypt:
            return [[bv_state[0][0], bv_state[0][1], bv_state[0][2], bv_state[0][3]],
                    [bv_state[1][1], bv_state[1][2], bv_state[1][3], bv_state[1][0]],
                    [bv_state[2][2], bv_state[2][3], bv_state[2][0], bv_state[2][1]],
                    [bv_state[3][3], bv_state[3][0], bv_state[3][1], bv_state[3][2]]]
        else:
            return [[bv_state[0][0], bv_state[0][1], bv_state[0][2], bv_state[0][3]],
                    [bv_state[1][3], bv_state[1][0], bv_state[1][1], bv_state[1][2]],
                    [bv_state[2][2], bv_state[2][3], bv_state[2][0], bv_state[2][1]],
                    [bv_state[3][1], bv_state[3][2], bv_state[3][3], bv_state[3][0]]]
    
    def mixColumns(self, bv_state, round, encrypt):
        if round == 13:
            return bv_state      
        if encrypt:
            x2 = BitVector(bitstring='00000010')
            x3 = BitVector(bitstring='00000011')
            for i in range(4):
                s_0j = bv_state[0][i]
                s_1j = bv_state[1][i]
                s_2j = bv_state[2][i]
                s_3j = bv_state[3][i]

                x2_0 = x2.gf_multiply_modular(s_0j, self.AES_modulus, 8)                
                x3_0 = x3.gf_multiply_modular(s_1j, self.AES_modulus, 8)    

                x2_1 = x2.gf_multiply_modular(s_1j, self.AES_modulus, 8)                
                x3_1 = x3.gf_multiply_modular(s_2j, self.AES_modulus, 8)

                x2_2 = x2.gf_multiply_modular(s_2j, self.AES_modulus, 8)                
                x3_2 = x3.gf_multiply_modular(s_3j, self.AES_modulus, 8)

                x2_3 = x2.gf_multiply_modular(s_3j, self.AES_modulus, 8)                
                x3_3 = x3.gf_multiply_modular(s_0j, self.AES_modulus, 8)
                
                bv_state[0][i] = x2_0 ^ x3_0 ^ s_2j ^ s_3j
                bv_state[1][i] = s_0j ^ x2_1 ^ x3_1 ^ s_3j 
                bv_state[2][i] = s_0j ^ s_1j ^ x2_2 ^ x3_2
                bv_state[3][i] = x3_3 ^ s_1j ^ s_2j ^ x2_3

        else:
            zE = BitVector(bitstring='00001110')
            zB = BitVector(bitstring='00001011')
            zD = BitVector(bitstring='00001101')
            z9 = BitVector(bitstring='00001001') 

            for i in range(4):
                s_0j = bv_state[0][i]
                s_1j = bv_state[1][i]
                s_2j = bv_state[2][i]
                s_3j = bv_state[3][i]

                zE_0 = zE.gf_multiply_modular(s_0j, self.AES_modulus, 8)                
                zB_0 = zB.gf_multiply_modular(s_1j, self.AES_modulus, 8)                
                zD_0 = zD.gf_multiply_modular(s_2j, self.AES_modulus, 8)                
                z9_0 = z9.gf_multiply_modular(s_3j, self.AES_modulus, 8)
                
                zE_1 = zE.gf_multiply_modular(s_1j, self.AES_modulus, 8)                
                zB_1 = zB.gf_multiply_modular(s_2j, self.AES_modulus, 8)                
                zD_1 = zD.gf_multiply_modular(s_3j, self.AES_modulus, 8)                
                z9_1 = z9.gf_multiply_modular(s_0j, self.AES_modulus, 8)
                
                zE_2 = zE.gf_multiply_modular(s_2j, self.AES_modulus, 8)                
                zB_2 = zB.gf_multiply_modular(s_3j, self.AES_modulus, 8)                
                zD_2 = zD.gf_multiply_modular(s_0j, self.AES_modulus, 8)                
                z9_2 = z9.gf_multiply_modular(s_1j, self.AES_modulus, 8)
                
                zE_3 = zE.gf_multiply_modular(s_3j, self.AES_modulus, 8)                
                zB_3 = zB.gf_multiply_modular(s_0j, self.AES_modulus, 8)                
                zD_3 = zD.gf_multiply_modular(s_1j, self.AES_modulus, 8)                
                z9_3 = z9.gf_multiply_modular(s_2j, self.AES_modulus, 8)

                bv_state[0][i] = zE_0 ^ zB_0 ^ zD_0 ^ z9_0
                bv_state[1][i] = z9_1 ^ zE_1 ^ zB_1 ^ zD_1 
                bv_state[2][i] = zD_2 ^ z9_2 ^ zE_2 ^ zB_2
                bv_state[3][i] = zB_3 ^ zD_3 ^ z9_3 ^ zE_3  
        return bv_state

    def subBytes(self, bv_state, encrypt):
        if encrypt:
            return [[BitVector(size = 8, intVal = self.subBytesTable[int(wordindex)]) for wordindex in rowindex] for rowindex in bv_state]
        else:    
            return [[BitVector(size=8, intVal = self.invSubBytesTable[int(wordindex)]) for wordindex in rowindex] for rowindex in bv_state]
    
    def addRoundKey(self, bv_state, bv, round, encrypt):
        if encrypt:
            bv = self.state_to_bv(bv_state)
            bv ^= self.key_words[round + 1]
            return bv

        else:
            bv = self.state_to_bv(bv_state)
            bv ^= self.key_words[13 - round]
            return bv
    
    def encrypt(self, plaintext:str, ciphertext:str)-> None:

        f = open(plaintext, 'r')
        bv_plaintext = BitVector(textstring = f.read())  
        f.close()
        ciphertext_bv = BitVector(size = 0)

        if (len(bv_plaintext) % 128 != 0): 
            bv_plaintext.pad_from_right(128 - (len(bv_plaintext) % 128))

        for i in range(len(bv_plaintext) // 128):
            bv = bv_plaintext[i * 128:(i + 1) * 128]
            bv ^= self.key_words[0]
            bv_state = self.bv_to_state(bv)

            for round in range(14):
                bv_state = self.subBytes(bv_state, 1)
                bv_state = self.shiftRows(bv_state, 1)
                bv_state = self.mixColumns(bv_state, round, 1)
                bv = self.addRoundKey(bv_state, bv, round, 1)
                bv_state = self.bv_to_state(bv)
            ciphertext_bv += self.state_to_bv(bv_state)

        f = open(ciphertext, "w")
        f.write(ciphertext_bv.get_hex_string_from_bitvector())
        f.close()

    def decrypt(self, ciphertext:str, decrypted:str)-> None:

        f = open(ciphertext, "r")
        bv_ciphertext = BitVector(hexstring = f.read())
        f.close()
        plaintext_bv = BitVector(size = 0)
        
        for i in range(len(bv_ciphertext) // 128):
            bv = bv_ciphertext[i * 128:(i + 1) * 128]
            bv ^= self.key_words[14]
            bv_state = self.bv_to_state(bv)

            for round in range(14):
                bv_state = self.shiftRows(bv_state, 0)
                bv_state = self.subBytes(bv_state, 0)
                bv = self.addRoundKey(bv_state, bv, round, 0)
                bv_state = self.bv_to_state(bv)
                bv_state = self.mixColumns(bv_state, round, 0)
            plaintext_bv += bv

        f = open(decrypted, "w") 
        f.write(plaintext_bv.get_text_from_bitvector())
        f.close()
        
    def encrypt_block(self, iv):

        iv ^= BitVector(bitstring=self.key_words[0])
        state_array = self.bv_to_state(iv)
        for round in range(14):
            state_array = self.subBytes(state_array, 1)
            state_array = self.shiftRows(state_array, 1)
            state_array = self.mixColumns(state_array, round, 1)
            state_array = self.addRoundKey(state_array, iv, round, 1)
            state_array = self.bv_to_state(state_array)
        return self.state_to_bv(state_array)

    def ctr_aes_image(self, iv, image_file, enc_image):
        '''
        Inputs:
        iv (BitVector): 128-bit initialization vector
        image_file (str): input .ppm file name
        enc_image (str): output .ppm file name

        Method Description:
        * This method encrypts the contents in image_file
        using CTR mode AES and
        writes the encrypted
        content to enc_image
        * Method returns void
        '''
        image_bv = BitVector(filename=image_file)
        bv = image_bv.read_bits_from_file(17*8)
        f = open(enc_image, 'wb')
        bv.write_to_file(f)

        while(image_bv.more_to_read):
            bv = image_bv.read_bits_from_file(128)
            if bv.length() != 128:
                bv.pad_from_right(128 - bv.length())
            bv ^= self.encrypt_block(iv)
            bv.write_to_file(f)
            iv = BitVector(intVal = iv.int_val() + 1)
        f.close()
        
    def x931(self, v0, dt, totalNum, outfile):
        """
        Inputs:
        v0 (BitVector): 128-bit seed value
        dt (BitVector): 128-bit date/time value
        totalNum (int): total number of pseudo-random numbers
        to generate
        Method Description:
        * This method uses the arguments with the X9.31
        algorithm to compute
        totalNum number of pseudo
        random numbers, each
        represented as BitVector
        objects.
        * These numbers are then written to the output file in
        base 10 notation.
        * Method returns void
        """
        f = open(outfile, "w")
        dt_enc = self.encrypt_block(dt)
        for num in range(totalNum):
            r_j = self.encrypt_block(dt_enc ^ v0)
            f.write(str(int(r_j))+"\n")
            v0 = self.encrypt_block(dt_enc ^ r_j)
        f.close()

if __name__ == "__main__":
    cipher = AES(keyfile=sys.argv[3])
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[4])
    elif sys.argv[1] == "-i":
        cipher.ctr_aes_image(iv= BitVector(textstring="counter-mode-ctr"),image_file=sys.argv[2],enc_image=sys.argv[4])    
    else:
        cipher.x931(v0=BitVector(textstring="counter-mode-ctr"), dt=BitVector(intVal=501,size=128), totalNum=int(sys.argv[2]), outfile=sys.argv[4])
