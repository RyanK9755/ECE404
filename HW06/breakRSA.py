import sys
import random
from BitVector import *
from PrimeGenerator import *
from solve_pRoot import *
    #######################################################
    #CITATION: LECTURE 12 CODE BY PROF AVI KAK USED FOR HW6
    #######################################################

class RSA():

    def __init__(self, e)-> None:

        self.e = e
        self.p = 0
        self.q = 0
        self.d_bv = BitVector(intVal = self.e).multiplicative_inverse(BitVector(intVal = ((self.p - 1) * (self.q - 1))))
        self.n = BitVector(intVal=self.p).int_val() * BitVector(intVal=self.q).int_val()
        
    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a
    
    def generate_key(self, p_s, q_s):
        prime = PrimeGenerator(bits=128, debug=0)
        p = prime.findPrime()
        q = prime.findPrime()
        while((p == q) or (self.gcd(p-1, self.e) != 1) or (self.gcd(q-1, self.e) != 1)):
            p = prime.findPrime()
            q = prime.findPrime()
        p_f = open(p_s, "w")
        q_f = open(q_s, "w")
        p_f.write(str(p))
        q_f.write(str(q))
        p_f.close()
        q_f.close()

        self.p = p
        self.q = q
        self.n = BitVector(intVal=self.p).int_val() * BitVector(intVal=self.q).int_val()

    def encrypt(self, enc, plaintext):
        f = open(enc, 'w')
        plaintext_bv = BitVector(filename=plaintext)
        self.generate_key('p.txt','q.txt')

        while(plaintext_bv.more_to_read):
            block = plaintext_bv.read_bits_from_file(128)
            block.pad_from_right(128-block.length())
            block.pad_from_left(128)
            encrypted = BitVector(intVal=pow(block.int_val(), self.e, self.n), size=256)
            f.write(encrypted.get_bitvector_in_hex())
        f.close()
        
    def encrypt_files(self, plaintext:str, enc1:str, enc2:str, enc3:str, n_1_2_3:str)-> None:
        f = open(n_1_2_3, 'w')
        pf = open('p.txt', 'w')
        qf = open('q.txt', 'w')

        self.encrypt(enc1, plaintext)
        pf.write(str(self.p))
        pf.write("\n")
        qf.write(str(self.q))
        qf.write("\n")
        f.write(str(self.n))
        f.write("\n")

        self.encrypt(enc2, plaintext)
        pf.write(str(self.p))
        pf.write("\n")
        qf.write(str(self.q))
        qf.write("\n")
        f.write(str(self.n))
        f.write("\n")

        self.encrypt(enc3, plaintext)
        pf.write(str(self.p))
        pf.write("\n")
        qf.write(str(self.q))
        qf.write("\n")
        f.write(str(self.n))

        f.close()
        pf.close()
        qf.close()
        
    def break_rsa(self, enc1:str, enc2:str, enc3:str, n_1_2_3:str, cracked:str):

        decrypted = open(cracked, 'w')
        f1 = open(enc1, 'r')
        f2 = open(enc2, 'r')
        f3 = open(enc3, 'r')
        fn = open(n_1_2_3, 'r')
        n1 = int(fn.readline())
        n2 = int(fn.readline())
        n3 = int(fn.readline())
        enc1_bv = BitVector(hexstring = f1.read())
        enc2_bv = BitVector(hexstring = f2.read())
        enc3_bv = BitVector(hexstring = f3.read())
        n1_bv = BitVector(intVal = n1)
        n2_bv = BitVector(intVal = n2)
        n3_bv = BitVector(intVal = n3)
        f1.close()
        f2.close()
        f3.close()
        fn.close()

        M = n1 * n2 * n3
        M1 = BitVector(intVal = (M // n1))
        M1_inv = M1.multiplicative_inverse(n1_bv).int_val()
        M2 = BitVector(intVal = (M // n2))
        M2_inv = M2.multiplicative_inverse(n2_bv).int_val()
        M3 = BitVector(intVal=(M // n3))
        M3_inv = M3.multiplicative_inverse(n3_bv).int_val()

        decrypted_bv = BitVector(size = 0)
        for i in range((enc1_bv.length() // 256)):
            c1 = (enc1_bv[i*256:(i+1)*256]).int_val()
            c2 = (enc2_bv[i*256:(i+1)*256]).int_val()
            c3 = (enc3_bv[i*256:(i+1)*256]).int_val()

            X = ((c1 * M1.int_val() * M1_inv) + (c2 * M2.int_val() * M2_inv) + (c3 * M3.int_val() * M3_inv)) % M
            decrypted_bv += BitVector(intVal = solve_pRoot(self.e, X), size = 128)
        decrypted.write(decrypted_bv.get_bitvector_in_ascii())
        decrypted.close()

if __name__ == "__main__":
    cipher = RSA(e=3)
    if sys.argv[1] == "-e":
        cipher.encrypt_files(plaintext=sys.argv[2], enc1=sys.argv[3], enc2=sys.argv[4], enc3=sys.argv[5], n_1_2_3=sys.argv[6])
    elif sys.argv[1] == "-c":
        cipher.break_rsa(cracked=sys.argv[6], enc1=sys.argv[2], enc2=sys.argv[3], enc3=sys.argv[4], n_1_2_3=sys.argv[5])
