import sys
import random
from BitVector import *
from PrimeGenerator import *
    #######################################################
    #CITATION: LECTURE 12 CODE BY PROF AVI KAK USED FOR HW6
    #######################################################

class RSA():

    def __init__(self, e)-> None:

        self.e = e
        self.p = int((open('p.txt', 'r')).read())
        self.q = int((open('q.txt', 'r')).read())
        self.d_bv = BitVector(intVal = self.e).multiplicative_inverse(BitVector(intVal = ((self.p - 1) * (self.q - 1))))
        self.d = int(self.d_bv)
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

    def crt(self, bv, d):

        v_p = pow(bv.int_val(), d.int_val(), self.p)
        v_q = pow(bv.int_val(), d.int_val(), self.q)
        x_q = self.q * (BitVector(intVal = self.q).multiplicative_inverse(BitVector(intVal = self.p))).int_val()
        x_p = self.p * (BitVector(intVal = self.p).multiplicative_inverse(BitVector(intVal = self.q))).int_val()
        return ((v_p * x_q) + (v_q * x_p)) % self.n

    def encrypt(self, plaintext:str, ciphertext:str)-> None:

        plaintext_bv = BitVector(filename=plaintext)
        f = open(ciphertext, "w")

        while(plaintext_bv.more_to_read):
            block = plaintext_bv.read_bits_from_file(128)
            block.pad_from_right(128-block.length())
            block.pad_from_left(128)
            encrypted = BitVector(intVal=pow(block.int_val(), self.e, self.n), size=256)
            f.write(encrypted.get_bitvector_in_hex())
        f.close()

    def decrypt(self, ciphertext:str, recovered_plaintext:str)-> None:
        
        encrypted = open(ciphertext, 'r')
        encrypted_bv = BitVector(hexstring=encrypted.read())
        encrypted.close()
        decrypted = open(recovered_plaintext, 'w')
        decrypted_bv = BitVector(size = 0)

        for i in range((encrypted_bv.length() // 256)):
            bv = encrypted_bv[i*256:(i+1)*256]
            decrypted_bv += BitVector(intVal = self.crt(bv, self.d_bv), size = 128)
        decrypted.write(decrypted_bv.get_bitvector_in_ascii())
        decrypted.close()
        
if __name__ == "__main__":
    cipher = RSA(e=65537)
    if sys.argv[1] == "-g":
        cipher.generate_key(p_s=sys.argv[2], q_s=sys.argv[3])
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[5])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])