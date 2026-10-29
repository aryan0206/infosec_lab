# IS Lab Endsem toolkit

## Tomorrow: start here

1. In File Explorer, double-click **START_TOOLKIT.bat**. Choose **1 Check examination PC readiness** first. No terminal commands or question pasting are needed. The old portable ZIP was removed because it was stale; use this project folder.
2. If needed, choose **2 Set up requirements**. It creates a local `.venv` after confirmation and can use a matching offline `wheelhouse/`. Never copy `.venv` between PCs.
3. Choose **3 Launch solution builder**, then **10 Build schema-driven application** to enter arbitrary role names, fields, permissions, algorithms and operations. The older numbered families remain examples.
4. Enter field definitions and role policies, review the printed configuration, then confirm generation. Older families still use Basic, Full, or Custom feature selection.
5. Type **Y** to generate a new one-file Python submission. The exact `.py` and `.checklist.txt` paths are printed under **exam_output**.
6. Read the checklist against the actual exam question. Choose whether to open the folder, run the program, and perform validation tests. The program's own numbered menu accepts records and runs the chosen operations.

The outer menu also has **4 Open generated submissions** and **0 Exit**. Within the builder, **7 Features/templates** includes copies of older fixed RSA, Paillier, and ElGamal examples; **8 Run/verify output** finds existing generated files. Invalid choices stay in the menu. Errors stay visible until you close the window. Generated `.py` files contain their implementation in one file; submit the selected `.py`, not the checklist. Runtime keys and records appear under `exam_output/demo_data/<generated_filename>/`. The validation choice runs an isolated functional self-test for configurable records submissions; fixed templates receive syntax validation only and must be run manually.

Option 10 supports configurable text/integer/boolean schemas, AES-CBC/GCM, SHA and SHA3 record hashes, HMAC search, RSA-OAEP per-record wrapping, RSA-PSS, ElGamal or Schnorr signatures, textbook RSA multiplication, Paillier aggregates, Shamir reconstruction, hash chains, replay/freshness checks, standalone or separate TCP client/server output, hex dumps, persistence, role PINs, and operation/field permissions. **11 Search component catalog** shows operations, dependencies and status. For TCP output, run the generated `_server.py` in one terminal and `_client.py` in another; keep the shared generated `.py` beside them. See [GENERALIZATION_REPORT.md](GENERALIZATION_REPORT.md) for tested variants and exact gaps. Option 10 requires `cryptography>=41,<51` even when encryption is disabled.

The configurable records engine supports AES-128/192/256-GCM descriptions, Paillier amounts and encrypted aggregate, SHA-256, SHA-512, or MD5 record hashes, researcher and separate reviewer RSA signatures, approval decisions, searchable metadata, persistent events/keys, and a hash-chain audit. Presets enable useful combinations; Custom controls individual features. Role menus are workflow labels, not user authentication. The local event chain detects accidental or naive tampering but has no trusted external anchor; someone who can rewrite all files and access keys can defeat it. MD5 is collision-unsafe. The voting choice copies an existing educational demo and remains partial.

For networked signed records, choose **6 General application → 3 Custom → `tcp_framed`** from the numbered feature list. The builder adds the required encryption, signatures, replay, HMAC search and audit components, then asks for AES key size, SHA choices, roles and their operation numbers, field labels, count bound and loopback port. The generated file is still standalone. The workflow has a defined packet schema and seven supported operations; labels and role assignments are configurable, while new data fields or new operation types require additional implementation and tests. See [COMPONENT_CATALOG.md](COMPONENT_CATALOG.md).

**Before the exam:** use CPython 3.10-3.14 (3.12 preferred); cryptographic builds need `cryptography>=41,<51`. Standard-library-only Custom builds need no package. The ZIP can include a verified wheelhouse for Windows x64 / CPython 3.12; use setup option 2 for offline installation. If Python is missing, arrange a permitted user-local installation in advance. The voting template is educational and does not fully implement the original voting question. See [EXAM_QUICK_START.txt](EXAM_QUICK_START.txt) and [COMPATIBILITY_MATRIX.md](COMPATIBILITY_MATRIX.md).

Open `START_TOOLKIT.bat` on Windows. The BAT menu works even if Python is missing. It checks a project-local `.venv`, the Python launcher, common installed paths, `IS_LAB_PYTHON`, and a Codex runtime if present. Supported versions are CPython 3.10-3.14; 3.12 is preferred. Crypto builds need `cryptography>=41,<51`, while hash-only Custom builds use the standard library. Install and test permitted packages **before** the exam. The older [exam execution guide](00_START_HERE/EXAM_EXECUTION_GUIDE.md) describes fixed templates and is background reference.

This project is separate from the supplied midsem ZIP. It provides reusable code in `core.py`, JSON persistence in `store.py`, individual Lab 1-8 demonstrations, standalone RSA/Paillier/ElGamal arithmetic scripts, and three integrated development menus. The integrated development programs import `core.py` and `store.py`; use the generated one-file exports for the four known exam patterns.

**Exam submission status:** the confirmed exam permits only one self-contained `.py` file per solution, except genuine client-server tasks. The four files in [standalone_submissions/generated](standalone_submissions/generated/) are reproducible one-file exports and have been tested independently in clean temporary directories. The programs in `10_integrated_scenarios/` remain development sources. The voting export is an educational demonstration and does not fully satisfy its original question. See [standalone submission instructions](standalone_submissions/README.md).

New patient, grant and voting records use version 2 hex encodings. Existing versionless Base64 records and keys remain readable and are not rewritten; see [the format notes](standalone_submissions/README.md).

Read [the completion and limitations report](COMPLETION_REPORT.md) before using the voting example or claiming full manual coverage.

Run from this directory:

```powershell
python -B check_setup.py
python -B exam_router.py
python -B tools/build_submissions.py --check
python -B -m unittest discover -s tests -v
```

The patient menu uses **9 = Exit**. Select **L** to load the supplied five-field dataset from a JSON list or CSV file into an empty patient directory; then use 2 Encrypt and 4 Sign. This creates `Patient_records` and `encrypted_patient_records` under `demo_data/patients` beside the chosen script. `sample_patient_records.json` is a practice fixture only. Keys are unencrypted local demonstration keys; protect them on a shared machine. Deleting keys without deleting records makes old ciphertext undecryptable.

The voting program generates and saves an RSA-4096 key once at its first start, which may take time. Its local timestamp and two-authority approval are simulations. It is not a real election system. See [limitations](COMPLETION_REPORT.md).

The manual is the primary topic source; the four pasted questions are confirmed past examples. The manual asks students to work individually and warns against plagiarism/LLM use during lab sessions. Follow your exam rules. This toolkit is for preparation and adaptation, not a claim that a stored program will answer every variation unchanged.
