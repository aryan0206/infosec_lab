# Requirement checklist (copy beside a new question)

| Requirement | Input | Function/file | Menu item | Output shown | Failure tested |
|---|---|---|---|---|---|
| Exact algorithm/mode/key length | | | | | |
| Input bounds/duplicate IDs | | | | | |
| File names/dataset fields | | | | | |
| Hash/signature covers exact bytes | | | | | |
| Verify before decrypt | | | | | |
| Ciphertext-only combination | | | | | |
| Search disclosure limit | | | | | |
| Restart/persistent keys | | | | | |
| Role restriction | | | | | |
| Timestamp/deadline | | | | | |

Do not claim a row is complete until you can demonstrate its normal and failure paths.

Before launch, write down the router's exact standalone file and command, required inputs, dependency, and persistence location. Mark each question line **FULL**, **PARTIAL**, or **UNSUPPORTED**; do not treat a matched title as proof of completeness. The router requires confirmation before running a file.

## Verified checks for the known patient and grant questions

| Question requirement | Verified result | Test evidence / remaining condition |
|---|---|---|
| Patient diagnosis search displays matching patient fields | The search returns all five fields from verified AES-decrypted records, including multiple case-insensitive matches; no match returns `[]`. | `PatientTests.test_diagnosis_search_multiple_none_malformed_and_tampered`; isolated generated-menu test. |
| Patient supplied dataset and exit menu | `L` imports a supplied CSV/JSON file with five required fields into an empty dataset, without partial writes on validation failure; `9` exits. | `PatientTests.test_bulk_dataset_import_is_validated_before_write` and isolated generated-menu tests. Paper-only data must be transcribed to CSV/JSON. |
| Patient search blocks unverified access | Search refuses unsigned, tampered and malformed records before showing decrypted fields. | Same source and isolated menu tests. The separate plaintext dataset display remains part of the question. |
| Grant amount and Paillier total bounds | New submissions accept integer amounts in `0..1,000,000,000,000`; finance checks `selected_count × 1,000,000,000,000 < n` before ciphertext aggregation. | `GrantTests.test_paillier_range_and_bounded_aggregate`; isolated generated-menu boundary test. This is a conservative bound, not a cryptographic range proof. |
| Grant persistence across the amount-bound policy change | Older valid signatures still verify for review, but finance refuses digest-only signatures because their amount range was not established by the newer submission check. | Legacy-signature rejection test; re-submit unbounded grants to include them in a bounded tally. The separate version 2 format change is described below. |

## Verified record-format compatibility

| Check | Verified result |
|---|---|
| New patient/grant/voting records | Explicit `format_version: 2`; byte fields are lowercase hex and Paillier ciphertext strings use `0x` hex. |
| Legacy records and keys | Missing marker selects v1 Base64/decimal decoding. Original signed canonical JSON is verified unchanged; reads and restarts do not rewrite stored files. |
| Grant signature variants | Both v1 digest-only and v1 amount-policy signatures verify for review. Only amount-policy signed records, including v2 records, can enter the bounded finance tally. |
| Invalid formats | Unknown versions, malformed lowercase hex, changed version markers, and tampered signatures fail verification or raise an input error. |
| Standalone copies | All four generated menus run in isolated temporary folders without project-local imports; deterministic generation and check mode are tested. |

These rows are covered by `tests/test_versioned_formats.py` and `tests/test_generated_submissions.py`. The voting protocol limitations recorded elsewhere remain unchanged.

## Lab 5 and Lab 7 practice checks

| Exercise | Verified behavior | Limitation |
|---|---|---|
| Lab 5 5381 hash | `hash_demo.py` uses `(hash * 33 + character code) & 0xffffffff`, as specified on manual page 47. | This teaching hash is not cryptographically secure. |
| Lab 5 socket tampering | Run `socket_hash_demo.py server` in one terminal and `socket_hash_demo.py client --tamper` in another; the client displays differing local and received-message hashes. | Local unauthenticated demonstration. |
| Lab 7 ElGamal multiplication | `standalone_submissions/elgamal_product.py` accepts group/key/operands, multiplies two ciphertexts, decrypts, and verifies the product modulo p in a terminal menu. | Small-group educational ElGamal; ordinary product may wrap modulo p. |
