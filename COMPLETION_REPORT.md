# Build and evidence report

## Current stage: patient dataset, Lab 5 integrity, Lab 7 ElGamal

The patient menu now uses `9` for Exit and `L` to load a supplied CSV or JSON dataset with the five exam fields into an empty `Patient_records` file. The importer validates the whole dataset before writing, refuses duplicate IDs and refuses to replace existing data. AES/signature processing, versioned encoding, legacy reads and existing keys are unchanged. If the question supplies patient rows only on paper, they must first be transcribed to CSV or JSON; the dataset is not bundled.

The official manual's page 47 specifies a 5381 initial value, multiplication by 33, **addition** of each character code and a 32-bit mask; `hash_demo.py` now follows that formula. `socket_hash_demo.py client --tamper` deliberately changes a transmitted byte while retaining the original local hash, so the two-terminal run visibly reports a mismatch. This is a local, unauthenticated teaching demonstration.

`standalone_submissions/elgamal_product.py` is a new self-contained standard-library terminal exercise for Lab 7 ciphertext multiplication. It accepts group, key and operand inputs, multiplies ciphertext pairs, decrypts the combined ciphertext and checks the product modulo p. The Lab 7 development demo imports its function. Small groups and modular wrap are clearly labeled as educational limits. The existing four generated submissions remain synchronized; only the patient generated file changed in this stage.

Actual checks with `C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`, `PYTHONDONTWRITEBYTECODE=1` and `PYTHONIOENCODING=utf-8`:

```powershell
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -v
# Ran 40 tests in 41.564s — OK (baseline before edits: 36/36)
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py --check
# CURRENT: 4 generated submissions match their sources
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B 07_homomorphic_encryption/homomorphic_demo.py
# Exit 0; sample ElGamal product verified True
```

The full suite includes isolated temporary-directory menu runs for the generated patient submission and standalone ElGamal file, plus patient import validation/restart and a local socket tampering test. No Git operations were performed.

## Terminal navigation and exam launch readiness

`START_TOOLKIT.bat` now selects a working Python 3.10+ interpreter from `IS_LAB_PYTHON`, `py -3`, `python`, or `python3`, then runs setup and the terminal router. Setup checks the interpreter and reports the `cryptography>=41` requirement without blocking the standard-library RSA submission. The router ranks only standalone files, previews the exact file/command, inputs, dependency, data location, and FULL/PARTIAL/UNSUPPORTED coverage, checks for missing dependencies or stale generated files, and asks before launch. Its phrase matching is advisory; the patient menu numbering and the grant/voting security limits remain explicitly visible. Cryptographic algorithms and record formats were not changed in this stage.

Using `C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe` with `PYTHONDONTWRITEBYTECODE=1` and `PYTHONIOENCODING=utf-8`, the pre-edit full suite passed **30/30**. The final generator check printed `CURRENT: 4 generated submissions match their sources`; the final full suite passed **36/36**. Six new navigation tests cover the Windows batch entry point, question ranking, preview content, dependency/stale-file checks, invalid choices and launch confirmation. A terminal walk-through of the patient preview was also run and cancelled before launch. The three integrated generated files were regenerated only to correct an outdated encoding comment; the RSA export was byte-for-byte unchanged.

```powershell
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B check_setup.py --require-cryptography
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py --check
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -v
```

## Current update: version 2 hex records with legacy reads

This section supersedes earlier statements below that say new records still use Base64. New patient envelopes and grant/voting records include `format_version: 2`; byte-valued record fields use lowercase hex and Paillier ciphertext strings use `0x` hex. New `keys.json` files mark version 2 and store the AES key in hex. Versionless records and key files retain Base64/decimal decoding, their original signed canonical JSON, and their original bytes on disk during reads and restarts. RSA PEM files and voting `index.key` remain unchanged. Unknown versions and malformed v2 hex are rejected. The two v1 grant signature variants both remain reviewable; only amount-policy signed grants may enter finance aggregation.

Baseline before this update: **26/26 tests passed**. After implementation, generator `--check` reported `CURRENT: 4 generated submissions match their sources`, and the final full suite passed **30/30** tests. The tests include legacy/v2 coexistence, signatures, restarts, tampering, and isolated terminal runs of all four exported submissions without project-local imports. No production security claims have changed; the voting demonstration still lacks trusted timestamping, authenticated voter roles, formal searchable encryption and threshold Paillier.

Commands run from the project root with `PYTHONDONTWRITEBYTECODE=1` and `PYTHONIOENCODING=utf-8`:

```powershell
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py --check
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -v
```

## Focused correctness stage after Stage 2

The unchanged starting tree passed **22/22** tests before edits. Patient diagnosis search now verifies the signed encrypted dataset before decrypting, then displays all five fields for every matching patient. Multiple matches, no match, unsigned access, malformed files and tampering were exercised in source and standalone-menu tests.

Paillier here encodes nonnegative integers in `0..n-1`; decrypting a sum of `n` returns `0`. The grant submission path now caps each amount at `1,000,000,000,000`, signs the existing MD5 digest with a domain marking that checked policy, and leaves stored JSON fields and Base64 encodings unchanged. Finance requires that signature domain and checks `selected_count × cap < n` before homomorphic addition. This conservatively guarantees that a selected sum cannot wrap for records created by the updated submission path. Older records still verify for review but cannot enter a finance aggregate until re-submitted; their original signature carries no enforceable amount bound. This is an application check, not a cryptographic range proof against a malicious submitter with access to the local signing key.

Commands run from the project root with `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, and bundled Python `C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`:

```powershell
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -v
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -p test_toolkit.py -v
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -p test_generated_submissions.py -v
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py --check
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -v
```

Actual results: baseline **22/22**, updated development-source suite **19/19**, generator produced four files, isolated export suite **7/7**, check mode reported `CURRENT: 4 generated submissions match their sources`, and final full suite passed **26/26**. The final full suite also includes an additional malformed-structure patient test added after the standalone run. Generator consistency testing confirms identical exports from identical inputs and permits only standard-library or `cryptography` imports. The RSA and voting exports did not change bytes in this stage, and all four ran in isolated temporary directories during the final suite.

## Stage 2 update: standalone submissions

This section supersedes the Stage 1 statements below that call the integrated scenarios multi-file exam submissions. The development scenarios still import `core.py` and `store.py`; their four current one-file exports live in `standalone_submissions/generated/`. `tools/build_submissions.py` produces them deterministically, and `--check` detects source changes requiring regeneration. See `standalone_submissions/README.md` for commands and persistence behavior.

The Stage 2 tests copy each export by itself into a fresh temporary directory and run actual terminal menus with Python `-I -B`, no `PYTHONPATH`, and only standard-library or `cryptography` imports. They cover normal, invalid, security-negative, and restart paths, including the voting deadline and a post-close count. The detailed requirement-by-requirement result is in `PREVIOUS_QUESTIONS_ANALYSIS.md`; the voting export remains an explicitly incomplete educational demonstration. Existing JSON/Base64 serialization has not changed.

Stage 2 commands run from the project root with bundled Python `C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe` (with `PYTHONDONTWRITEBYTECODE=1` and `PYTHONIOENCODING=utf-8`):

```powershell
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -v
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B tools/build_submissions.py --check
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s tests -v
```

The first command, before Stage 2 changes, ran **17 tests, all passing**. Generation produced four files. The check reported `CURRENT: 4 generated submissions match their sources`. The final command ran **22 tests, all passing**. The five new tests include two fresh output directories with matching file hashes and one isolated temporary directory for each exported menu. The voting test also reads its persisted RSA private key and confirms a 4096-bit key. No original project data directory was used by those isolated tests.

## Source audit and build order

The supplied 68-page merged manual is the primary lab-topic source. Its contents page and lab headings identify eight labs. The four pasted previous questions supply actual endsem scenario details. The midsem ZIP was inspected for its README, master guide, crypto blocks, previous-question analysis, playbook, router, setup check, standalone bank and 15 practice variants. Its best reusable ideas were the quick router, exam checklist, one-file submission bank and explicit dependency check. These were **rewritten** for endsem algorithms; no midsem files were copied into this project. The large 15-variant bank was deliberately excluded because it duplicates architectures and is not confirmed endsem evidence. The original ZIP and sources were not changed. The connected theory guide was created first, before code, with dedicated Lab 7 and 8 sections.

## Directory tree (source files)

```text
IS-Lab-Endsem/
  README.md  COMPLETION_REPORT.md  PREVIOUS_QUESTIONS_ANALYSIS.md
  index.html  requirements.txt  check_setup.py  START_TOOLKIT.bat
  exam_router.py  core.py  store.py  sample_patient_records.json
  00_START_HERE/ EXAM_ROUTER.md EXAM_QUICK_REFERENCE.md
                 EXAM_EXECUTION_GUIDE.md QUESTION_REQUIREMENT_CHECKLIST.md
  01_basic_ciphers/ classical.py
  02_symmetric_encryption/ aes_des_demo.py
  03_asymmetric_cryptography/ asymmetric_demo.py
  04_key_management_access_control/ dh_demo.py
  05_hashing_integrity_networking/ hash_demo.py socket_hash_demo.py
  06_digital_signatures/ signature_demo.py
  07_homomorphic_encryption/ homomorphic_demo.py
  08_searchable_encryption/ index_demo.py
  09_security_tools/ README.md
  10_integrated_scenarios/ patient_records.py grant_portal.py e_voting_demo.py
  theory/ IS_LAB_ENDSEM_THEORY.md LAB_7_HOMOMORPHIC_ENCRYPTION.md
          LAB_8_SEARCHABLE_ENCRYPTION.md CRYPTO_CONCEPT_MAP.md
  reusable_blocks/ CRYPTO_BLOCKS.md
  standalone_submissions/ rsa_product.py paillier_sum.py
  practice_variants/ README.md
  tests/ test_toolkit.py check_index.js
```

There are no empty topic directories. `demo_data/` is generated only by running integrated menus and can be removed for a clean practice reset.

## Confirmed question to file summary

| Question | Main program | Core/support | Test | Material limitation |
|---|---|---|---|---|
| A RSA boxes × cost | `standalone_submissions/generated/rsa_product.py` | `standalone_submissions/rsa_product.py` source | RSA core + both standalone parameter modes + isolated menu | Exact ordinary product only when `< N`. |
| B patients | `standalone_submissions/generated/patient_records.py` | patient scenario + AES-GCM, RSA-PSS, Paillier, JSON store | patient flow, bulk import, restart, empty/missing/malformed, tamper + isolated menu | Supplied CSV/JSON imports through `L`; paper-only data requires transcription. |
| C grants | `standalone_submissions/generated/grant_portal.py` | grant scenario + AES-192-GCM, MD5, RSA-PSS, Paillier, JSON store | grant flow, selected IDs, restart, tamper, role menu + isolated menu | Role selection is not identity authentication; MD5 is collision-unsafe. |
| D voting | `standalone_submissions/generated/e_voting_demo.py` | voting scenario + SHA-512, AES-256-CBC, RSA-4096 OAEP, toy ElGamal, Paillier, token index | voting flow, search, timestamp, restart, tamper + isolated menu | Trusted timestamp, true threshold Paillier and formal searchable encryption are **not implemented**. |

The detailed requirement/menu/function/test mapping is in `PREVIOUS_QUESTIONS_ANALYSIS.md`.

## Manual lab coverage

| Manual lab | Evidence from PDF | Implemented demonstration | Remaining gap |
|---|---|---|---|
| 1 Basic symmetric (pp. 9-13) | additive, multiplicative, affine, Vigenere, autokey, Playfair, Hill, transposition | `classical.py` affine (includes additive/multiplicative cases), Vigenere, autokey, Playfair, Hill 2×2, rail fence | Not every keyed-transposition or attack exercise solved. |
| 2 Advanced symmetric (pp. 14-21) | DES, AES, 3DES and timing/modes | `aes_des_demo.py` CBC round trips/timing; `core.py` AES-GCM/CBC | No full mode-by-mode timing study. DES-equivalent uses 3DES K,K,K. |
| 3 Asymmetric (pp. 22-31) | RSA, ElGamal, ECC, Rabin | `asymmetric_demo.py`; `core.py` RSA/key wrapping | Toy integer ElGamal/Rabin; ECC uses ECDH + AES, as direct ECC plaintext encryption is not a standard primitive. |
| 4 Advanced asymmetric/key management (pp. 32-43) | RSA/ElGamal/Rabin, DH, RBAC, revocation, enterprise key services | `dh_demo.py`, persistent demo keys, role menus | No secure central key API, renewal service, audit/compliance implementation. |
| 5 Hashing (pp. 46-48) | 5381 custom hash, socket integrity, MD5/SHA-1/SHA-256 comparison | `hash_demo.py`, `socket_hash_demo.py` | Socket path is local training traffic and not authenticated. |
| 6 Signatures (pp. 48-53) | RSA signatures, ElGamal/Schnorr/DH exploration | `signature_demo.py`, `core.py` RSA/ElGamal | No Schnorr signature or external website exercise. |
| 7 Partial homomorphic (pp. 54-60) | Paillier sum, RSA product, ElGamal product | `homomorphic_demo.py`, two standalones, core | Small RSA/ElGamal demo parameters are educational. No full benchmarking/secure multiparty protocol. |
| 8 Searchable encryption (pp. 61-68) | ten-document AES/index SSE exercise, Paillier PKSE sketch, GnuPG/Snort additional | `index_demo.py` with ten AES-encrypted documents and HMAC token index; theory and tools guide | Formal SSE, workable Paillier PKSE equality protocol, GnuPG/Snort live exercises absent. |

## Verification actually run

From project root using the bundled Python 3.12.14 and `cryptography` 50.0.2:

```powershell
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' check_setup.py
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m compileall -q .
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m unittest discover -s tests -v
$env:NODE_PATH='C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\node_modules'
& 'C:\Users\Laptop\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe' tests/check_index.js
```

The original build baseline ran **14 tests, all passing**, with Python 3.12.14 and `cryptography` 50.0.2. Its setup check printed `READY`, compilation exited 0, and a headless Edge/Playwright run opened the local `file:` page, counted 19 cards and 27 local links, and filtered to six Paillier matches. In the subsequent first-stage correction, the same suite was captured at 14/14 before edits; strengthened tests exposed four expected failures before the implementation fixes; the final first-stage suite ran **17 tests, all passing**. The patient, grant and voting API paths were tested; full human walk-through of every menu prompt was not performed.

## First-stage correction status

`standalone_submissions/rsa_product.py` and `core.py` now distinguish modular from ordinary product verification and validate decryption of entered operands. Grant Researcher menu option 2 displays every saved submission with encrypted fields, hashes, signatures and verification status; serialization remains unchanged. Voting tally rejects requests before the configured end and labels the remaining mechanisms as demonstrations. The RSA standalone was copied and run successfully in a clean temporary directory. Patient, grant and voting are still multi-file development programs and **not ready as self-contained exam submissions**. No hex serialization migration or broad lab/theory expansion has been performed.

## Known limitations / do not claim

- This is an educational study toolkit, not a production privacy/security application. Unencrypted local private keys and AES keys are stored in `demo_data`; menu roles have no login or identity proof.
- MD5 is present because Question C demands it. It does not provide modern collision resistance. Small ElGamal and classical/DES examples are insecure by design.
- Voting uses the local machine clock, not a trusted timestamp authority. Its two approval strings are **not threshold decryption**; one local Paillier private key decrypts the final sum. The keyed index is not a full formal SSE scheme. The supplied previous voting question's true threshold/trusted timestamp requirements remain unmet.
- The voting record's toy voter public key is generated with the ballot and has no verified voter identity binding. RSA server signing protects stored metadata in this local demo, but a real election needs authenticated clients and independent authorities.
- Paillier totals and textbook RSA products are modulo their respective moduli. The programs check relevant simple bounds, but no production-grade range proof or malicious participant protection is implemented.
- The grant tally has a conservative application bound for records submitted under the current policy and refuses older unbounded records. It still has no cryptographic range proof against a malicious submitter who controls the local signing key. The voting demo does not prove that its Paillier ciphertexts encode the same choice as the signed AES ballot.
- The manual's large enterprise key management services, live GnuPG/Snort work and a real Paillier-based PKSE protocol remain study topics rather than runnable completed services.

## Most useful practice order

1. Run `standalone_submissions/rsa_product.py` with both exam-parameter input modes and a wrapping product.
2. Run `standalone_submissions/paillier_sum.py` and explain why ciphertexts multiply for addition.
3. Enter sample patient data, encrypt/sign, verify, search and deliberately tamper a practice copy.
4. Submit two grants, restart, verify, search and aggregate selected IDs.
5. Walk through the voting demo and state its simulation limits out loud.

For a new question, underline exact operations and modes, run the mechanism router, fill the requirement checklist, adapt fields/menus, then demonstrate each success and failure path. Do not treat a router match as complete coverage.
