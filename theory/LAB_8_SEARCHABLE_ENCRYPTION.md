# Lab 8 study card

Read [the connected explanation](IS_LAB_ENDSEM_THEORY.md#4-lab-8-searchable-encryption-manual-pp-61-68). Manual pp. 61-68 ask for ten documents, AES protection, an inverted index and search, and sketch Paillier for PKSE. Its Paillier sketch omits a workable equality-search protocol because randomized encryption does not produce stable matching ciphertexts.

Run `py 08_searchable_encryption/index_demo.py`. It stores keyed HMAC tokens mapped to IDs, so search returns IDs and the document stays protected. The index leaks repeated queries, matching IDs and result sizes. The patient, grant and voting programs use narrower scenario-specific search routines. Never label their ordinary metadata lookup as a complete cryptographic SSE scheme.
