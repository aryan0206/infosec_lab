# Quick reference

| Wording | Equation / operation | Template |
|---|---|---|
| Multiply RSA-encrypted values | `c=(c1*c2)%N`; verify modular equality separately; ordinary product matches only when no wrap occurs | `standalone_submissions/generated/rsa_product.py` |
| Add Paillier-encrypted values | `c=product(ciphertexts) % n²`; decrypt final only | `standalone_submissions/paillier_sum.py` |
| Multiply ElGamal-encrypted values | Multiply each ciphertext component modulo prime `p`; decrypt final product modulo `p` | `standalone_submissions/elgamal_product.py` |
| AES-192 | 24-byte key | `standalone_submissions/generated/grant_portal.py` |
| AES-256-CBC | 32-byte key, fresh 16-byte IV, PKCS7 | `standalone_submissions/generated/e_voting_demo.py` (educational demo) |
| RSA signature | Sign canonical bytes with private key, verify public key | `core.py` |
| SHA-256/512 | Hash exact UTF-8 or file bytes | `core.py` |
| Search disclosure | Patient search shows all five fields only after verification; grant/voting search returns metadata | generated patient/grant/voting submissions |
| Persistent records | JSON read/write with stable key files | `store.py` |

Verify **before** decrypting protected records. Validate total `< n` for Paillier and note RSA product wraps modulo `N`. MD5 is used only where explicitly required.

For a new question, use `START_TOOLKIT.bat` or `python -B exam_router.py` to preview the closest one-file submission. FULL means the named operation is implemented, not that every line of a different question is covered. The patient pattern needs the supplied JSON/CSV dataset (menu **L** imports it; **9 exits**); the grant roles are not authenticated; voting is educational and lacks trusted timestamps and threshold decryption.
