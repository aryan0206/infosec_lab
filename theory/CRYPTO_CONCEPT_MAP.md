# Concept map

`Question wording -> primitive -> key owner -> failure gate`:

| Wording | Primitive | Key owner | Gate |
|---|---|---|---|
| Keep description confidential | AES | authorized decryptor | GCM tag or signature before display |
| Send AES key securely | RSA-OAEP | recipient private key | unwrap errors block decrypt |
| Detect change | SHA-256/512 | no key | trusted reference hash needed |
| Prove signer | RSA/ElGamal signature | signer private key; verifier public key | verification failure blocks access |
| Add encrypted amounts | Paillier | tally private key | verify inputs, decrypt final only |
| Multiply encrypted amounts | textbook RSA/ElGamal | decryption private key | check modulo result |
| Locate encrypted record | index | index/search key where used | return ID first, decrypt only with authorization |
