# Four confirmed previous endsem questions: requirement matrix

Evidence: the pasted previous-question text dated 26/10/2026 CCE-C, 24/10/2026 IT-D, 23/10/2026 IT-B, and 28/10/2025 CCE-A. These are confirmed examples, not a promise about the next paper. In the table, `C` means `core.py`; `P/G/V` mean the patient/grant/voting development programs in `10_integrated_scenarios/`. The four tested one-file exports are in `standalone_submissions/generated/`; regenerate them with `tools/build_submissions.py` after source changes. Menu wording is written exactly enough to find the operation.

| Question and requirement | Algorithm / module / menu | Test and closest template | Limit or exam parameter |
|---|---|---|---|
| A input boxes/cost, bounds 1..N-1 | textbook RSA; `C.rsa_product`; standalone menu 2 | `CoreTests.test_rsa_product`; `standalone_submissions/generated/rsa_product.py` | Enter exam `p,q,e` or supplied `N,e,d`; second form has sample, not full, key validation. |
| A encrypt both; separate ciphertext-only multiplication; decrypt/compare | `C.rsa_multiply_encrypted`; standalone menu 2 | same test/template | Output now labels modular equality and ordinary-product equality separately; ordinary product needs `<N`. No OAEP. |
| A menu and modularity | standalone menu 1/2/0 | manual run; same template | No hardcoded exam values. |
| B exact fields and two named files | `P.load_dataset`, `P.encrypt_dataset`; menu L/2, 9 Exit | Bulk CSV/JSON import and isolated-menu tests; P | Supplied paper data must first be transcribed to CSV/JSON. Stored files are JSON without extensions. |
| B display dataset, AES encrypt | `P.records`, AES-GCM; menu 1/2 | patient flow; P | AES-GCM is allowed because mode unspecified. Plain dataset file is required by question. |
| B SHA-256 by ID | `P.hash_record`; menu 3 | patient missing-ID test; P | Hashes canonical plaintext record. |
| B RSA sign/verify dataset and tamper detection | `P.sign_dataset`, `P.verify`; menu 4/5 | patient tamper test; P | Signature covers encrypted payload and plaintext digest, not an external file outside the signed envelope. |
| B Paillier glucose total | `P.aggregate`; menu 6 | patient sum/empty tests; P | Requires integer glucose and sum below `n`. |
| B search diagnosis; verified decrypt by ID; exit | `P.search`, `P.verified_record`; menu 7/8/9 | multiple/no-match, malformed/tamper, isolated-menu tests; P | Search returns all five fields only after verification; plaintext dataset display remains a separate requested menu item. |
| C submit ID/description/amount | `G.submit`; Researcher 1 | `GrantTests.test_flow_restart_tamper`; G | Amount is a nonnegative integer unit. |
| C AES-192 description; Paillier amount | 24-byte AES-GCM key, `C.paillier_encrypt`; Researcher 1 | grant flow; G | Exact AES mode not supplied. |
| C MD5 record hash; RSA signature on hash | `G.submit`, `G.verified`; Researcher 1/Reviewer 1 | grant tamper test; G | MD5 collision-unsafe, used only as explicitly asked. Protected fields are ciphertext/ID. |
| C persistent records/view earlier | `store.py`, `G.submitted_views`; Researcher 2 | grant restart and menu tests; G | All saved records display encrypted fields, hashes, signatures and verification state; demo key files must remain. |
| C verify/recompute; search by ID without contents; decrypted hex | `G.verified`, `G.search`, `G.description_hex`; Reviewer 1/2/3 | grant search/tamper test; G | Reviewer search returns only ID + verification state. |
| C verify selected grants, ciphertext aggregation, final decrypt only | `G.aggregate`; Finance 1 | selected/missing/duplicate/tamper/boundary tests; G | New records have a signed submission policy capping each amount at 1,000,000,000,000; finance rejects any selection whose worst-case sum may reach `n`, and refuses legacy unbounded records. No individual amount decryption. |
| C role menus, invalid/tampering handling | `G.main`; role 1/2/3 | API tests; menu smoke check in final audit | Menus are role workflow, not user authentication. |
| D ballot fields, SHA-512, AES-256-CBC | `V.cast`, `C.cbc_encrypt`; Voter 2 | `VotingTests.test_period_search_tally_tamper`; V | CBC needs signed metadata for integrity. |
| D RSA-4096 wrap/unwrap AES key | `V.cast`, `V.verify`, `C.rsa_wrap/unwrap`; Voter 2/Server 3 | voting round trip; V | RSA key generated once per demo directory. |
| D ElGamal signature on SHA-512 digest | `C.elgamal_sign_digest/verify`; Voter 2/Server 3 | voting verification; V | Tiny 467 group is educational and insecure. Voter identity binding absent. |
| D Paillier candidate ID and encrypted tally | `V.cast` stores encrypted ID and one-hot indicators; Authorities 4 | voting counts test; V | Count vector needed for per-candidate totals; ID sum alone insufficient. |
| D trusted timestamp, deadline | `V.cast`, `V.verify`; Voter 2/Server 3 | out-of-period and generated-menu deadline tests; V | Deadline is enforced, but local clock is **not** a trusted timestamp authority. |
| D server verify SHA/signature, searchable constituency/time | `V.verify`, `V.search`; Server 3 | search/tamper test; V | HMAC token index and timestamp filtering are not full SSE. |
| D tally at election end, threshold final decryption, roles, persistence | `V.tally`, `store.py`; Authorities 4 | generated-menu early-tally rejection, isolated final tally, restart tests; V | Tally rejects attempts before the configured end. Two approvals are only a simulation; one local private key exists. No actual threshold Paillier. Roles lack login. |

## Stage 2 runnable completeness audit

Current storage update: new patient, grant and voting records use explicit version 2 hex encodings. Versionless legacy records remain readable and verifiable without conversion. This changes storage representation, not the question-function status below; voting remains an educational demonstration.

Status refers to the generated scripts, each copied alone into a temporary directory and run in Python isolated mode. `Partial` identifies behavior that does not fully meet the question.

| Question | Requirement group | Status | Runnable evidence or missing part |
|---|---|---|---|
| A | Two inputs, exam RSA parameters, bounds 1..N-1, menu and functions | Complete for the stated toy RSA exercise | Both parameter modes, normal and invalid input menu runs. |
| A | Encrypt separately, multiply ciphertexts only, decrypt and compare | Complete for modular equality | Normal run verifies 2×3=6; wrapping run explains why ordinary product differs from the result modulo N. |
| B | Named plaintext/encrypted files, five supplied fields, display, AES encryption | Partial | Files and menu work across restart; `L` imports supplied CSV/JSON in one step, and `9` exits. A paper-only dataset still requires transcription to CSV/JSON. |
| B | SHA-256 by ID, RSA dataset signing and tamper verification | Complete for the local dataset | Menu signs, verifies, hashes by ID; corrupted signature blocks verified decryption. |
| B | Paillier glucose total, diagnosis search, verified decrypt by ID | Complete for imported, verified data | Sum and verified decrypt run. Diagnosis search displays all five fields for each matching patient and blocks malformed or tampered data. |
| C | Researcher submission with AES-192, Paillier, MD5, RSA signing | Complete for the specified operations | Menu submits and displays encrypted saved record; 24-byte AES key gives AES-192. |
| C | Reviewer verify/hash, indexed ID lookup without contents, decrypted description hex | Complete for the specified operations | Verify/search/hex menu run; modified signature blocks description decryption. ID lookup is a linear scan, not a separate index data structure. |
| C | Finance selected-ciphertext aggregate and final-only decrypt | Partial | For records submitted under the new bounded policy, the menu rejects any selection whose worst-case total reaches `n` and decrypts only the aggregate. Legacy unbounded records are refused. This relies on the trusted local submission path, not a cryptographic range proof. |
| C | Role menus, persistence, invalid/tamper handling, all outputs | Partial | Menu workflows, restart, invalid ID and tamper cases run. Role selection has no identity authentication, so access control is only a demonstration. |
| D | Ballot fields, SHA-512, AES-256-CBC, RSA-4096 key wrapping | Partial | Cast/verify menu and 4096-bit key check run. Ballot bytes are made from a canonical in-memory record, not a separate ballot file. |
| D | Voter ElGamal signature and identity/non-repudiation | Partial | Signature verifies, but the tiny teaching group is insecure and voter keys are created per ballot without verified identity binding. |
| D | Paillier choice encryption and ciphertext-only tally | Partial | Candidate ID and encrypted indicator vector are stored; final counts use indicator homomorphism. No proof binds Paillier values to the signed AES choice. |
| D | Trusted timestamp and election deadline | Partial | Local timestamp is checked and early tally refused; no trusted authority signs or vouches for the timestamp. |
| D | Server verify, encrypted search by constituency/time | Partial | SHA/signature checks and token/time search run. The HMAC token lookup is not a formal searchable-encryption scheme. |
| D | Threshold final decryption and role-based access | Missing | Two fixed approval strings simulate authorization; one local Paillier key can decrypt. Menus have no authenticated roles. |

Question D remains an **educational demonstration**, not a complete implementation of the national e-voting specification.

## Routing principle

Classify wording by operation first, then use the full row set above to check the proposed template. A single RSA or Paillier match does not satisfy dataset, menu, persistence, verification, search or role requirements.
