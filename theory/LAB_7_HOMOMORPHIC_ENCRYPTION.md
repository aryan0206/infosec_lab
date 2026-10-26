# Lab 7 study card

Read [the connected explanation](IS_LAB_ENDSEM_THEORY.md#3-lab-7-partial-homomorphic-encryption-manual-pp-54-60). Manual pp. 54-60 explicitly ask for Paillier encrypted addition, RSA encrypted multiplication and ElGamal multiplication as an additional exercise.

`Paillier: Enc(a) * Enc(b) mod n² -> a+b mod n.` `Textbook RSA: Enc(a) * Enc(b) mod N -> a*b mod N.` `ElGamal: multiply both ciphertext components mod p -> a*b mod p.` Do not decrypt the operands during the combine step. Validate inputs, ciphertext ranges, key parameters and wraparound. Run `py 07_homomorphic_encryption/homomorphic_demo.py`, then practise `standalone_submissions/rsa_product.py` and `standalone_submissions/paillier_sum.py`.
