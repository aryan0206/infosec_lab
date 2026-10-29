# IS Lab Manual coverage matrix

Source: `../IS Lab Manual_merged.pdf`, all 68 PDF pages read. Page numbers below are **PDF pages**. Pages 1–8 contain the cover, contents, outcomes and instructions; page 7 explicitly permits modified and combined exam questions. Pages 44–45 are dividers. The counted items below are the manual's numbered tasks and distinct requested subparts, not background theory or inferred variations. **Fully Supported** means runnable existing code covers the stated operation with test evidence; it does **not** imply option 10 can compose it. **Partially Supported** means some requested steps work. **Unsupported** means the requested operation/workflow is absent. **Unverified** means a plausible implementation exists but the exact task was not verified. The last column explicitly says whether option 10 can generate the exercise without source edits.

Abbreviations: `classical` = `01_basic_ciphers/classical.py`; `symmetric` = `02_symmetric_encryption/aes_des_demo.py`; `asymmetric` = `03_asymmetric_cryptography/asymmetric_demo.py`; `DH` = `04_key_management_access_control/dh_demo.py`; `hash` = `05_hashing_integrity_networking/hash_demo.py`; `socket` = `05_hashing_integrity_networking/socket_hash_demo.py`; `signature` = `06_digital_signatures/signature_demo.py`; `index` = `08_searchable_encryption/index_demo.py`; `engine` = `components/general_application.py`; `builder` = `general_builder.py`. Test names are in `tests/`.

## Lab 1 — classical ciphers (PDF pp. 9–13; tasks pp. 12–13)

| ID | Explicit manual task | Status | Source and test evidence / precise gap | Option 10 |
| --- | --- | --- | --- | --- |
| 1.1a | Additive cipher, key 20, encrypt/decrypt supplied text | Fully Supported | `classical:affine(a=1,b=20)`; `test_toolkit.NavigationTests.test_router_and_lab_examples` exercises affine roundtrip. | No classical component |
| 1.1b | Multiplicative cipher, key 15 | Fully Supported | `classical:affine(a=15,b=0)` and same test; 15 is invertible mod 26. | No |
| 1.1c | Affine cipher, keys 15 and 20 | Fully Supported | `classical:affine`; same test covers roundtrip, though not this exact phrase. | No |
| 1.2a | Vigenère, keyword `dollars` | Unverified | `classical:vigenere` exists; no named Vigenère test or exact-vector test located. | No |
| 1.2b | Autokey, key 7 | Fully Supported | `classical:autokey`; `test_router_and_lab_examples` roundtrip. | No |
| 1.3 | Playfair, keyword `GUIDANCE` | Partially Supported | `classical:playfair`; `test_router_and_lab_examples` roundtrip; padding/J normalization changes exact plaintext representation, and the manual vector is not tested. | No |
| 1.4 | Hill 2×2, supplied matrix | Partially Supported | `classical:hill2`; `test_router_and_lab_examples` roundtrip; supplied matrix `[3,3;2,7]` has determinant 15 mod 26, but exact vector is untested. | No |
| 1.5 | Infer additive key from `CIW`→`yes`; decipher `XVIEWYWI` | Unsupported | No known-plaintext attack function in `classical` or named test. | No |
| 1.6 | Infer affine key from `ab`→`GL`; decipher cryptogram | Unsupported | `classical:affine` implements transformation, not key recovery/cryptanalysis. | No |
| 1.A1 | Brute-force additive birthday cryptogram | Unsupported | No brute-force enumeration/English ranking in `classical`. | No |
| 1.A2a | Identify transposition attack from given oracle example | Unsupported | `classical:rail_fence` is one transposition cipher; no oracle analysis. | No |
| 1.A2b | Infer transposition permutation/key size | Unsupported | No permutation-key solver. | No |
| 1.A3 | Vigenère with keyword `HEALTH` | Unverified | `classical:vigenere` exists; exact prompt and roundtrip untested. | No |

## Lab 2 — symmetric encryption (PDF pp. 14–21; tasks pp. 20–21)

| ID | Explicit manual task | Status | Source and test evidence / precise gap | Option 10 |
| --- | --- | --- | --- | --- |
| 2.1 | DES fixed-key encryption/decryption | Partially Supported | `symmetric:roundtrip` labels a TripleDES construction using repeated key material; no manual fixed DES key/vector test. | No DES choice |
| 2.2 | AES-128 fixed-key roundtrip | Partially Supported | `symmetric:roundtrip` uses random AES-CBC key/IV; `engine:aes_encrypt/aes_decrypt` uses generated keys, not supplied fixed key. | AES-128 CBC/GCM records only |
| 2.3 | Time DES versus AES-256 | Partially Supported | `symmetric:roundtrip` reports timings for demo data; no comparable manual benchmark/test. | No benchmark |
| 2.4 | Triple DES fixed-key roundtrip | Partially Supported | `symmetric:roundtrip` has TripleDES, but repeats a key and does not use the supplied fixed key/vector. | No 3DES |
| 2.5 | AES-192 fixed key and expansion/initial/main/final round trace | Partially Supported | `engine:aes_encrypt` supports 192-bit library AES; no key schedule or internal round trace. | Encryption only |
| 2.A1a | Five messages under DES and AES-128/192/256 in different modes | Partially Supported | `engine:aes_encrypt` covers AES CBC/GCM; DES and requested mode sweep absent. | Partial AES subset |
| 2.A1b | Graph timing for those variants | Unsupported | No plot/benchmark generator in builder or named test. | No |
| 2.A1c | Compare cipher-mode timings | Unsupported | No multi-mode timing study. | No |
| 2.A2a | DES two supplied blocks and exact ciphertext | Unsupported | No fixed-vector DES operation/test. | No |
| 2.A2b | Decrypt those DES blocks | Unsupported | Same gap. | No |
| 2.A3 | AES-256 fixed-key roundtrip | Partially Supported | `engine:aes_encrypt/aes_decrypt` supports AES-256; generated keys differ from manual key. | AES-256 CBC/GCM records |
| 2.A4 | DES-CBC with fixed IV/key | Unsupported | No fixed-key DES-CBC interface. | No |
| 2.A5 | AES-CTR with fixed nonce/key | Unsupported | `engine:aes_encrypt` accepts CBC/GCM only; `builder:validate_config` rejects unsupported modes. | No CTR |

## Lab 3 — public key cryptography (PDF pp. 22–31; tasks pp. 30–31)

| ID | Explicit manual task | Status | Source and test evidence / precise gap | Option 10 |
| --- | --- | --- | --- | --- |
| 3.1 | RSA encryption/decryption with supplied `(n,e,d)` | Partially Supported | `asymmetric:rsa_oaep_roundtrip` generates keys; `engine:rsa_product` does textbook modular arithmetic, not general supplied-key text encryption. | OAEP key wrapping only |
| 3.2 | ECC encryption/decryption of supplied message | Partially Supported | `asymmetric:ec_hybrid_roundtrip` is ECDH/HKDF/AES-GCM hybrid, not direct EC or EC ElGamal encryption. | No ECC |
| 3.3 | ElGamal encrypt/decrypt supplied text/parameters | Partially Supported | `asymmetric:elgamal_roundtrip` uses toy integer group, not arbitrary text/parameters. | Signatures only |
| 3.4a | RSA-2048 plus secp256r1 file transfer/key exchange | Unsupported | No file-transfer client/server combining RSA and ECC. `engine:send` sends configured JSON records. | No |
| 3.4b | 1 MB/10 MB timing, size and security comparison | Unsupported | No such benchmark/test. | No |
| 3.5 | Peer-to-peer Diffie–Hellman exchange and timing | Partially Supported | `DH:exchange(p=23,g=5)` toy arithmetic; no peer protocol/timing; no builder component. | No |
| 3.A1 | ElGamal with supplied p=7919,g=2,h=6465,x=2999 | Unsupported | `asymmetric:elgamal_roundtrip` hardcodes toy parameters; no supplied-parameter interface. | No |
| 3.A2 | Additional ECC roundtrip | Partially Supported | `asymmetric:ec_hybrid_roundtrip` only hybrid form; no exact task test. | No |
| 3.A3 | Toy RSA n=323,e=5,d=173 text roundtrip | Unsupported | No input path for those toy key values and text encoding. | No |
| 3.A4 | ElGamal patient-record transfer with secp256r1 and measurements | Unsupported | Finite-field ElGamal and secp256r1 are conflated in manual wording; no EC ElGamal record-transfer component. | No |
| 3.A5 | RSA/ElGamal/ECC 1 KB and 10 KB performance comparison | Unsupported | No combined benchmark. | No |

## Lab 4 — key management and access control (PDF pp. 32–43; tasks pp. 39–43)

| ID | Explicit manual task/subrequirement | Status | Source and test evidence / precise gap | Option 10 |
| --- | --- | --- | --- | --- |
| 4.1a | Secure subsystem communication using RSA and DH | Partially Supported | `DH:exchange` toy and `asymmetric:rsa_oaep_roundtrip` separate; no composed channel. | No DH |
| 4.1b | Scalable key generation, distribution and revocation | Partially Supported | `engine:Application.__init__` persists keys; no distribution/revocation protocol. | Key creation only |
| 4.1c | Extensible subsystem registration | Unsupported | No dynamic subsystem/KMS API. | No |
| 4.2a | Rabin KMS with configurable 1024-bit key generation | Partially Supported | `asymmetric:rabin_roots` uses toy p=7,q=11; no KMS/key-size support. | No Rabin |
| 4.2b | Secure API for public/private key distribution | Unsupported | No Rabin key-distribution API; distributing private keys securely is unspecified. | No |
| 4.2c | Key revocation and update | Unsupported | `engine:Application` has no revocation lifecycle. | No |
| 4.2d | Automatic 12-month renewal | Unsupported | No expiry/rotation scheduler. | No |
| 4.2e | Secure private-key storage | Partially Supported | `engine:Application.__init__` writes private key files unencrypted; no filesystem protections. | Persistence only |
| 4.2f | Detailed KMS audit trail | Partially Supported | `engine:records/verify` maintains record hash chain, not key-event audit. | Record chain only |
| 4.2g | HIPAA/privacy compliance | Unverified | No compliance assessment/evidence; cannot infer compliance from code. | No claim |
| 4.2h | Explain Rabin versus RSA trade-offs | Partially Supported | Background/demo in `asymmetric:rabin_roots`; no verified KMS comparison output. | No |
| 4.A1a | DigiRights ElGamal 2048-bit master key and content encryption API | Unsupported | `engine:elgamal_keys/sign` are signature-only, max menu 1024; no content encryption API. | No |
| 4.A1b | Restricted private-key distribution and creator access | Unsupported | Role PIN/permissions in `engine:allowed/authenticate` do not implement DRM key distribution/creator ownership. | No |
| 4.A1c | Limited-time/revocable access | Unsupported | No expiry/revocation policy. | No |
| 4.A1d | Key revoke/renew every 24 months | Unsupported | No renewal lifecycle. | No |
| 4.A1e | Secure key storage and audit logs | Partially Supported | Persistent local files and record chain exist, but not protected DRM key storage/key audit. | Partial primitives |
| 4.A2 | Partial RSA private-key/factoring attack and mitigation | Unsupported | No attack/analysis script or named test. | No |

## Lab 5 — hashing/integrity/networking (PDF pp. 46–48; tasks pp. 47–48)

| ID | Explicit manual task | Status | Source and test evidence / precise gap | Option 10 |
| --- | --- | --- | --- | --- |
| 5.1 | 5381 × 33 + ASCII, 32-bit mask hash | Fully Supported | `hash:lab_hash`; `test_toolkit.NavigationTests.test_manual_5381_additive_hash`. | SHA-family digest instead |
| 5.2 | Socket hash server/client and altered-message detection | Fully Supported | `socket:server/client`; `test_socket_hash_local_roundtrip`, `test_socket_hash_tampering_detected`. | TCP records, not hash echo |
| 5.3 | Compare MD5/SHA-1/SHA-256 on 50–100 strings, timing/collisions | Partially Supported | `hash:compare(count=50)` implements comparison; no named benchmark correctness test or plot. | Digests selectable, no benchmark |
| 5.A1 | Multipart send/reassemble/hash/compare | Partially Supported | `socket:client` concatenates two prompted parts before one send; no multipart wire framing/reassembly. | No multipart |

## Lab 6 — digital signatures (PDF pp. 48–53; tasks pp. 52–53)

| ID | Explicit manual task | Status | Source and test evidence / precise gap | Option 10 |
| --- | --- | --- | --- | --- |
| 6.1a | Website RSA key creation/sign/verify with supplied Alice/Bob values | Partially Supported | `signature` RSA-PSS demo and `engine:verify_signature`; no supplied textbook RSA website keys/vectors. | Generated RSA-PSS records |
| 6.1b | Repeat steps with newly generated RSA keys | Partially Supported | `signature` generates new RSA-PSS keys; no website step-by-step interface. | Generated RSA-PSS records |
| 6.1c | Exchange signed messages with partner | Unsupported | No partner-signed message exchange/verification workflow; `engine:send` submits values for server-side signing. | No |
| 6.2a | Apply ElGamal scheme to sign/verify same steps | Partially Supported | `engine:elgamal_sign/verify`; `test_general_builder.test_arbitrary_roles_permissions_and_pin` exercises 512-bit generated records. Does not reproduce website vectors. | Yes, records |
| 6.2b | Apply “Schnor” scheme to sign/verify same steps | Partially Supported | `engine:schnorr_sign/verify`; `test_general_builder.test_schnorr_generated_signature` passes altered-signature/restart test. No website vectors. | Yes, records |
| 6.3 | Diffie–Hellman “asymmetric encryption” same steps | Unsupported | DH is key agreement, not a signature/encryption standard; `DH:exchange` toy only. | No |
| 6.4 | Client-server exchange of signed messages and observations | Partially Supported | `engine:send/handle_packet` length-framed records; server signs submitted values. `test_general_builder.test_separate_client_server_programs` tests network, not sender signature verification. | Partial |
| 6.A1 | Explore external RSA module, CIA-triad encryption/signature/hash demo | Partially Supported | `asymmetric:rsa_oaep_roundtrip`, `signature`, `hash` separate; no integrated CIA demo or exact external module test. | Partial primitives |

## Lab 7 — homomorphic encryption (PDF pp. 54–60; tasks p. 60)

| ID | Explicit manual task | Status | Source and test evidence / precise gap | Option 10 |
| --- | --- | --- | --- | --- |
| 7.1 | Paillier encrypt 15 and 25, add ciphertexts, decrypt sum | Fully Supported | `core.py:paillier_keypair/encrypt/add/decrypt`; `test_toolkit.CoreTests.test_paillier`; `engine:aggregate`. | Yes, integer fields |
| 7.2 | Textbook RSA ciphertext multiplication 7 × 3 | Fully Supported | `core.py:rsa_product`; `test_toolkit.CoreTests.test_rsa_product`; `engine:rsa_product`. | Yes, educational operation |
| 7.A1a | ElGamal encrypted multiplication | Fully Supported | `standalone_submissions/elgamal_product.py`; `test_generated_submissions.test_elgamal_menu_alone`. | No; separate submission |
| 7.A1b | Two-party Paillier split inputs/combined ciphertext | Partially Supported | `engine:aggregate` sums local encrypted records; no two-party interactive protocol. | Local aggregation |
| 7.A1c | Threshold partial homomorphic decryption | Partially Supported | `engine:shamir_split/reconstruct`, `test_general_builder.test_different_schema_aes_paillier_signature_aggregate`; reconstructs lambda locally, no distributed Paillier partial decrypt. | Shamir key recovery only |
| 7.A1d | Paillier versus ElGamal performance comparison | Unsupported | No combined benchmark. | No |

The medical “encrypted greater-than” worked example on pp. 55–59 is background rather than a numbered task. Its ElGamal multiplication does **not** implement a secure comparison; no such comparison is claimed here.

## Lab 8 — searchable encryption/security tools (PDF pp. 61–68; tasks pp. 67–68)

| ID | Explicit manual task | Status | Source and test evidence / precise gap | Option 10 |
| --- | --- | --- | --- | --- |
| 8.1a | Build 10-document SSE corpus | Partially Supported | `index:make_index` accepts documents; `index_demo.py` has fixed demo corpus, not a generated arbitrary corpus UI. | Configurable records, no corpus workflow |
| 8.1b | AES-encrypt/decrypt SSE documents | Partially Supported | `index_demo.py` uses AES encrypted documents; no named SSE end-to-end test. `engine:aes_encrypt/decrypt` tests records. | Encrypted fields |
| 8.1c | Inverted word index to encrypted document IDs | Partially Supported | `index:token/make_index` HMAC-protects words; returned document IDs remain plaintext. | Exact-field HMAC index only |
| 8.1d | Encrypted query, search, decrypt matching documents | Partially Supported | `index:search` HMAC equality lookup; `engine:search/decrypt` exact fields, no full-text document retrieval. | Exact-field search |
| 8.2a | Build 10-document PKSE corpus | Partially Supported | Plain corpus support in `index_demo.py`, no PKSE workflow. | Records only |
| 8.2b | Paillier-encrypt/decrypt PKSE document identifiers/content | Partially Supported | `engine:paillier_encrypt/decrypt` handles bounded integers, not searchable documents. | Integer records |
| 8.2c | Paillier encrypted inverted word-to-ID index | Unsupported | No Paillier searchable index/trapdoor; randomized Paillier encryption cannot be matched by fresh ciphertext equality. | No |
| 8.2d | PKSE encrypted query/search/decrypt document IDs | Unsupported | No working PKSE protocol. | No |
| 8.A1 | GnuPG encrypted storage/transmission plus signature verification | Unverified | `09_security_tools/README.md` documents usage; no executed GnuPG workflow/test found. | No |
| 8.A2 | Snort IDS install, rules and alert demonstration | Unverified | `09_security_tools/README.md` documents usage; no executed Snort test/artifact found. | No |

## Algorithm and concept inventory (background; excluded from item counts)

| Manual pages | Named algorithm/concept | Coverage in toolkit / option 10 |
| --- | --- | --- |
| 9–13 | Additive, multiplicative, affine, Vigenère, autokey, Playfair, Hill, rail/keyless/keyed transposition, known-plaintext and brute-force attacks | `classical` implements encryption variants and rail fence; no general attack solvers or transposition permutations; none in option 10. |
| 10, 14–21 | DES, Triple DES, AES-128/192/256, ECB/CBC/CFB/OFB/CTR and rounds/key expansion | `symmetric` educational AES/TripleDES CBC demo; option 10 AES CBC/PKCS7 and GCM only, all three key sizes; no DES/CTR/round trace. |
| 22–31 | RSA, ECC/ECDH, finite-field ElGamal, Diffie–Hellman, Rabin | Separate RSA-OAEP, EC hybrid, toy ElGamal/DH/Rabin; option 10 RSA-OAEP wrap only. |
| 32–43 | KDF/entropy, lifecycle, RBAC/ABAC, MAC/DAC/Bell–LaPadula, timing/probabilistic controls | Option 10 `engine:allowed/authenticate` provides configurable roles, own/equality condition and shared PIN; not full policy/KMS implementation. |
| 46–53 | 5381 hash, MD5, SHA-1/256, RSA/ElGamal/Schnorr signatures | Option 10 `builder:validate_config` exposes SHA-1/224/256/384/512, SHA3-224/256/384/512, MD5, HMAC-256/512 and RSA-PSS/ElGamal/Schnorr record signatures; individual variants differ in test coverage. |
| 54–60 | Paillier addition, RSA and ElGamal multiplication, threshold homomorphic operations | Option 10 Paillier sums/weighted sums/mean, RSA multiplication, Shamir recovery; ElGamal product separate; no true threshold Paillier. |
| 61–68 | SSE, PKSE, GnuPG, Snort | HMAC exact lookup and AES fields; no full PKSE or executable GnuPG/Snort integration. |

**Counted manual items:** see `FINAL_GAP_REPORT.md` for computed totals. The explicit-task matrix distinguishes manual requirements from the inferred exam variations in `ADDITIONAL_QUESTION_COVERAGE.md`.
