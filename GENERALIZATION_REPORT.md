# General application generator: audit and handoff

## Architecture and exam path

`START_TOOLKIT.bat` resolves its own folder and launches `master_builder.py`. Choose **3 Launch solution builder → 10 Build schema-driven application**. Enter fields and role names, select algorithms and **standalone** or **TCP client/server** architecture, review the configuration, then generate. Option **11 Search component catalog** filters algorithms, operations, dependencies and status. The builder embeds configuration in `components/general_application.py`. Standalone mode writes one `.py`; TCP mode writes a shared engine plus separate `_server.py` and `_client.py` launchers. Keep the three TCP files together. Start `python -B <stem>_server.py` in one terminal, then `python -B <stem>_client.py` in another. The generated program accepts `--self-test` and creates `demo_data/<script stem>/` for records, keys, shares and role PIN files.

The older fixed ledger, network and voting examples remain available and were not changed. No scenario-specific preset was added. The menu validates dependencies: RSA-OAEP wrapping needs an AES encrypted field; Shamir needs Paillier aggregation; aggregate operations need an integer field; TCP send needs submit permission and a TCP port; hex dumps need decrypt permission; role conditions require a plaintext field. Unsupported and incompatible choices raise errors before generation.

## Option 10 component status

| Component | Selectable status | Evidence and limit |
| --- | --- | --- |
| AES-128/192/256 CBC with random IV and PKCS7; GCM with random nonce and tag | Implemented | CBC-128 and GCM-128/192/256 round trips, padding boundaries and GCM tampering tested. Other CBC sizes use the same code but lack a separate generated-app test. |
| SHA-224/256/384/512, SHA3-224/256/384/512, MD5 | Implemented | SHA-256 and SHA3-256 exercised through generated records; other variants use `hashlib` but lack individual generated-app tests. MD5 is collision-unsafe. |
| HMAC-SHA-256/512 exact search | Implemented and tested | Indexed tokens contain no plaintext field value, but equality/frequency leak. |
| RSA-OAEP SHA-256 fresh AES key wrapping per record | Implemented and tested | RSA public/private files persist separately. Private key file is unencrypted. |
| RSA-PSS with 2048/3072/4096-bit keys | Implemented; 2048 tested | Signature checks reject tampering. Larger keys are not separately tested in option 10. |
| ElGamal modular signature with runtime 512/1024-bit prime | Implemented; 512 tested | Private value is in a separate local file; base 2 is not proven to generate the full group. 1024 is incompletely tested. |
| Schnorr signature with runtime DSA subgroup parameters at 1024/2048/3072 bits | Implemented; 1024 tested | Distinct algorithm from ElGamal. Signing, verification, altered-signature rejection and restart tested; larger groups partial. |
| Textbook RSA ciphertext multiplication | Implemented and tested | Educational modular multiplication, separate from RSA-OAEP. No semantic security. |
| Paillier encryption, sum, weighted sum, mean, aggregate bounds | Implemented; 1024 tested | 2048 is incompletely tested. Sender-side bounds are not cryptographic range proofs. Mean is returned for unweighted sums only. |
| Shamir threshold reconstruction for Paillier lambda | Implemented; 2-of-3 tested | One share is refused. Local share files reconstruct a key; this is not distributed partial decryption. |
| Canonical JSON, hash chain, nonce replay rejection, freshness window, persistence | Implemented and tested | Middle deletion/reordering and tampering tested. No trusted external chain anchor; final deletion cannot be proven locally. Local timestamps are not trusted timestamps. |
| Decimal length-prefixed TCP client/server | Implemented and tested | Separate generated programs, multiple clients with serialized persistent writes, invalid requests, disconnects and malformed/incomplete frames tested. No TLS; role PIN travels in plaintext. |
| UDP, multipart transfer and custom wire formats | Unsupported | The audited Lab 5 manual specifies socket client/server and an additional multipart exercise; it does not specify UDP. Option 10 rejects unsupported architecture names. |
| Offset/hex/ASCII dump | Implemented and tested | Available only for fields authorized for decrypt. |
| Arbitrary roles, schema, field/record permissions and optional PIN | Implemented and tested | PIN identifies a shared role; access to local key/account files defeats this boundary. |

The generator composes only its listed operations. It does not parse arbitrary exam prose, produce cryptographic range proofs, anchor a chain externally, or provide secure remote transport. It cannot promise that an arbitrary requirement outside the catalog is satisfied.

Remaining limits: approval decisions are local chain entries rather than separately signed decisions; the menu still asks for some default algorithm parameters when a component is disabled. TCP has no TLS, automatic retry, UDP, multipart reassembly or arbitrary message format. CBC with no selected signature has no authenticated integrity guarantee. Keep local private keys and account files confidential.

Manual audit: `../IS Lab Manual_merged.pdf` pages 47–48 request a socket hash client/server and a multipart additional exercise; page 53 names ElGamal, “Schnor” and Diffie-Hellman; pages 60–61 cover Paillier, textbook RSA and searchable encryption. The manual's Lab 5 comparison also names SHA-1. UDP was not found in the audited manual. Option 10 supports SHA-1 hashing with a collision warning, Schnorr signatures, and TCP record submission. It does not generate the manual's multipart hash exchange, Diffie-Hellman key agreement, ElGamal encrypted multiplication, GnuPG/Snort workflows, or UDP. Those remain separate examples or unsupported components, so complete syllabus coverage is not claimed.

## Menu-generated acceptance applications

Both were configured by driving `master_builder.main()` through its numbered **10** menu prompts and generated without source edits. `tests/test_general_builder.py` executes the generated `--self-test` and runtime operations. Saved outputs:

- `exam_output/general_acceptance/parcels.py` plus `parcels_server.py` and `parcels_client.py`: arbitrary “Dispatch Scribe” and “Route Inspector” roles; text/integer fields; role PIN and permissions; AES-256-GCM with RSA-OAEP per-record wrapping; ElGamal signatures; HMAC search; 30-second freshness; nonce replay rejection; textbook RSA; TCP send/serve with concurrent clients and malformed/incomplete frame checks; chain reorder/middle-deletion and invalid-signature checks.
- `exam_output/general_acceptance/samples.py`: arbitrary “Sample Collector”, “Lab Analyst” and “Decision Curator” roles; three-field schema; approval permission; AES-128-CBC/PKCS7; SHA3-256 record digest; HMAC-SHA-512; RSA-PSS; Paillier sum/weighted sum; 2-of-3 Shamir reconstruction with single/duplicate share refusal; bounds, restart, hex dump and tamper tests.

Two additional applications were generated through the actual `START_TOOLKIT.bat → 3 → 10` path using redirected menu input files. Both ran their standalone `--self-test` without source edits:

- `exam_output/general_application_20261028_094732.py`, `general_application_20261028_094732_server.py`, `general_application_20261028_094732_client.py`: “Archive Writer”, one encrypted searchable text field, AES-128-GCM, RSA-OAEP wrapping, ElGamal signature and TCP architecture. Launcher transcript: `exam_output/bat_acceptance_one_new.log`.
- `exam_output/general_application_20261028_094735.py`: “Intake Clerk” and “Audit Mathematician”, encrypted text plus Paillier integer, AES-192-CBC, RSA-PSS and 2-of-3 Shamir. Launcher transcript: `exam_output/bat_acceptance_two_new.log`.

Run either file with `python -B <file> --self-test` or without `--self-test` for its menu. Runtime files are created only when run. The test report is `exam_output/general_acceptance_test.log`.

## Verification

The targeted acceptance suite passed **5 tests** (`exam_output/general_acceptance_test.log`). The complete suite passed **61 tests** in 76.896 seconds (`exam_output/full_suite_20261028_quick.log`). Both BAT-generated files separately printed `SELF-TEST PASSED`; the TCP acceptance test also ran separate client/server programs and sent invalid and concurrent requests. The BAT launcher opened from its own folder and its parent folder. Physical File Explorer double-click was not performed. No Git commands were run.

## Cleanup

The prior cleanup removed `../IS-Lab-Endsem.zip` and `../IS_Lab_Endsem_Portable.zip` after confirming every non-Git archive path existed in the project. This upgrade did not delete files or rebuild archives.
