# Master builder component catalogue

## Schema-driven generator (builder option 10)

This path accepts user-entered role names and fields. Fields support text, integer, and boolean types; required status; text lengths and choices; integer bounds; AES encryption; and exact HMAC search. Role policies select submit, view, verify, search, approve, decrypt, aggregate, keys, textbook RSA product, hex dump, loopback TCP send and serve; all/own record access; equality conditions on a field; visible fields; decryptable fields; and optional role PIN authentication. The generated program creates its runtime JSON and key files beside itself under `demo_data/<generated name>/`. Run `python generated.py --self-test` for a smoke test.

| Component | Option 10 status | Evidence / limit |
| --- | --- | --- |
| AES-128/192/256 CBC with random IV and PKCS7; AES-GCM with random nonce and tag | Configurable; tested CBC-128 and GCM-128/192/256 | CBC encryption is not authenticated unless a signature is selected. |
| SHA-1/224/256/384/512, SHA3-224/256/384/512, MD5 | Configurable record digest | SHA3-256 and SHA-256 exercised in generated applications; other choices use Python `hashlib` but have not each been exercised in a generated application. SHA-1/MD5 are collision-unsafe. |
| HMAC-SHA-256/512 exact index | Configurable and tested | Both variants tested in generated applications; equality and frequency leak. |
| RSA-PSS 2048/3072/4096 | Configurable; 2048 tested | Larger sizes are implemented but incompletely tested in option 10. |
| RSA-OAEP SHA-256 fresh per-record AES key wrapping | Configurable; tested | One AES key per record, wrapped with persisted RSA public key; local private key file remains unencrypted. |
| ElGamal modular signature with runtime 512/1024-bit prime | Configurable; 512 tested | Uses base 2 without proof it generates the full group; 1024 is not exercised in option 10 tests. |
| Schnorr signature with runtime DSA subgroup parameters 1024/2048/3072 | Configurable; 1024 tested | Sign/verify, tamper rejection and restart tested. Larger groups are partial. This is separate from ElGamal. |
| Textbook RSA modular multiplication | Configurable; tested | Separate educational operation; no semantic security. |
| Paillier encrypted integer sums, weighted sums, mean | Configurable and tested at 1024 bits | 2048 is implemented but not exercised in option 10 tests; local input bounds are not range proofs. |
| Shamir threshold reconstruction of Paillier lambda | Configurable; 2-of-3 tested | Shares are local files, not a distributed partial-decryption protocol. |
| Canonical JSON, hash chain, nonce uniqueness, freshness window, JSON persistence | Configurable and tested | Local chain has no trusted external head. |
| TCP client/server architecture with decimal length-prefixed JSON, exact reads and malformed frame handling | Configurable and tested | Generates shared engine plus separate server/client launchers; concurrent clients are handled with serialized writes. No TLS, automatic retry, multipart reassembly or custom wire format. |
| UDP | Unsupported | Not found in audited Lab 5 manual; option 10 rejects UDP architecture requests. |
| Offset/hex/ASCII dumps | Configurable and tested | Applies only to fields the role may decrypt. |
| Role PIN authentication, operation and field permissions | Configurable and tested | PIN identifies a shared role; local key and account files are not protected from a user with filesystem access. |
| Diffie-Hellman agreement, ElGamal encrypted multiplication, multipart hash transfer, GnuPG/Snort integration, external chain anchor, range proofs, remote authenticated transport, prose conversion | Unsupported in option 10 | Some have separate educational examples; the generator does not claim them. |

The menu creates a complete program for its supported operations. It does not translate arbitrary prose into a correct application. Source files and fixed examples remain useful for syllabus exercises outside the composition engine.

The numbered **7 Features/templates** menu shows this catalogue in the toolkit. The configurable records engine accepts Expense ID, Project ID, Category, Description, and a nonnegative integer Amount. It stores runtime files beside the generated submission under `demo_data/<submission name>/`.

| Feature | Satisfies / input | Dependency and prerequisite | Limit |
| --- | --- | --- | --- |
| AES-GCM 128/192/256 | Encrypt/decrypt Description; UTF-8 text; choose bits in builder | `cryptography>=41` | Local key file is unprotected. |
| Paillier | Encrypt Amount and homomorphically add ciphertexts; integer 0..1e12 | `cryptography>=41` | No cryptographic range proof. |
| SHA-256 | Hash canonical ID, project, category, description field and amount field | Standard library | Hash alone does not authenticate the writer. |
| SHA-512 | Same canonical record hash with SHA-512; RSA-PSS also uses SHA-512 | Standard library for hash; `cryptography` for RSA | Hash alone does not authenticate the writer. |
| MD5 | Same record hash when a question explicitly demands MD5 | Standard library; exclusive with SHA-256 | Collision-unsafe, including when signed. |
| Researcher RSA signature | Sign record digest; verify before sensitive operations | `cryptography>=41`; SHA-256 default or MD5 if explicitly selected | Persistent local key does not prove a human identity. |
| Reviewer RSA signature | Sign each decision bound to original record hash | `cryptography>=41`; approval and researcher signature | Role menu does not authenticate reviewer. |
| Approval | Save approved/rejected decision and reason; use latest verified decision | SHA-256 default or MD5 if explicitly selected | An explicit new decision can reverse a rejection. |
| Audit chain | Hash each append-only submission/decision with preceding event hash | Standard library | No trusted external anchor; a privileged attacker could recompute a chain. Signatures add protection while keys remain private. |
| Search | Find ID; show only ID, project, category, decision, verification | Standard library | Linear scan; metadata is plaintext. |
| Aggregate | Distinct IDs, same project, approval and verification checks; decrypt final Paillier sum | Paillier; ID list, project, budget | Final total is visible. No zero-knowledge range proof. |
| Demo | E1=120 and E2=80 approved, E3=50 rejected in P1 | Menu selection; approval and aggregate for full demonstration | Practice data only. |
| Roles | Researcher, reviewer, finance, administrator menus | Menu choice | Workflow labels, not enforced access control. |

## Networked record workflow

Under **General application → Custom**, choose `tcp_framed`. The builder adds its required components: persistent per-entity RSA enrolment, a separate receiver RSA key, fresh AES-GCM key per packet, RSA-OAEP wrapping, Paillier encrypted counts, signed canonical packet fields, increasing sequence/replay checks, HMAC exact-keyword tokens, and an accepted-event hash chain. You can choose AES-128/192/256, RSA/OAEP SHA-256/512, HMAC SHA-256/512, field labels, maximum count, local port, and a role-to-operation map. The seven supported operations are enrol, set up keys, send, receive, search, verified note decrypt, and encrypted aggregate. Generated code uses loopback `127.0.0.1`, a decimal length/newline frame, and persistent files beside the generated `.py`.

This workflow has a defined packet shape: entity ID, sequence, group, UTC timestamp, keyword, count, and note. Labels and role assignments can change; new packet fields or entirely new operations require a new component and tests. Role menus are workflow labels, not authentication. A sender timestamp is not a trusted timestamp. Search exposes plaintext keyword metadata and equality/frequency. The aggregate bound relies on the enrolled sender's local input validation; it is not a cryptographic range proof. The hash chain has no external trusted anchor. These limits appear in generated checklists.

The voting entry is a separate fixed educational template. It does not implement trusted timestamps, bound voter identities, or true threshold Paillier. The older RSA and ElGamal arithmetic templates remain available in `standalone_submissions/`; the Master Builder currently does not compose them into records applications. A patient-specific five-field dataset and authenticated login are not implemented by the configurable records engine. Review the exact exam question before treating any submission as complete.
