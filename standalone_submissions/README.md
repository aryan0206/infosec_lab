# One-file endsem submissions

The four files in `generated/` are **generated outputs**. Their source of truth is the existing development code: `core.py`, `store.py`, the corresponding `10_integrated_scenarios/*.py`, and `standalone_submissions/rsa_product.py`. Do not manually maintain duplicate logic in `generated/`.

From the project root, after editing development source:

```powershell
python -B tools/build_submissions.py
python -B tools/build_submissions.py --check
python -B -m unittest discover -s tests -p test_generated_submissions.py -v
```

Use the Python executable that passed `check_setup.py` if `python` is unavailable. The generator parses the modules, emits only reachable shared cryptographic definitions, rejects duplicate definitions or unexpected module-level code, removes project-local imports and the development path adjustment, then places demo data beside the generated file. It contains no timestamp, so the same source creates identical bytes. `--check` is read-only and fails for a missing or stale export.

**Submission:** Copy only the selected `.py` file from `generated/` to the exam submission location. RSA uses only the standard library. Patient, grant, and voting require the declared `cryptography` package installed beforehand. They create a `demo_data/<scenario>/` directory beside the copied script at runtime for records and keys. Keep those generated data/key files together across runs; never submit private keys unless the exam explicitly instructs you to submit generated data. Do not reuse old ciphertext after deleting its keys.

`elgamal_product.py` is another one-file, standard-library-only submission for the Lab 7 **additional** ElGamal multiplication exercise. Enter the small prime, generator, optional private exponent and two operands; it checks the product modulo the prime and explains wraparound. The Lab 7 development demo imports this same implementation. The generic `paillier_sum.py` remains a separate one-file template and needs `cryptography`.

For the generated patient file, choose **L** to load a supplied JSON list or CSV table with exact headers `Patient_id,Patient_name,Diagnosis,Blood_glucose,Treatment`. The target patient directory must be empty. Menu choices 1–8 follow the past question and **9 exits**. Copy a dataset file alongside the script or provide its absolute path; only the selected `.py` file is the submission code.

For terminal navigation, run `START_TOOLKIT.bat` on Windows or `python -B exam_router.py`. The router previews the exact file and command, required inputs, dependency, coverage and limitations, then asks before launching. Its phrase match does not certify a new exam question; use the requirement checklist for each line.

The voting file is an **educational demonstration**. It does not provide a trusted timestamp authority, verified voter identities, formal searchable encryption, or genuine threshold decryption. Its existence as a single file does not make the original voting question fully satisfied.

Current record format: new patient, grant and voting records carry `format_version: 2`. Byte-valued record fields use lowercase hex; Paillier ciphertext strings use `0x` hex. A missing marker is legacy v1, read with its original Base64/decimal encodings and verified over its original canonical JSON. Existing records are never converted automatically. New `keys.json` files also use version 2 with a hex AES key; existing versionless Base64 key files remain readable without being rewritten. PEM private keys and voting `index.key` stay in their original file formats. Unsupported versions and malformed v2 hex are rejected.

Legacy grant records with the amount-bound signature remain eligible for finance aggregation; older digest-only signatures remain reviewable but are excluded from finance aggregation until re-submitted. This preserves the amount-bound check without decrypting individual grant amounts.
