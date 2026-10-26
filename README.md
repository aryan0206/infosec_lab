# IS Lab Endsem toolkit

Start with [EXAM_EXECUTION_GUIDE.md](00_START_HERE/EXAM_EXECUTION_GUIDE.md), then open `START_TOOLKIT.bat` on Windows or run `python -B check_setup.py` and `python -B exam_router.py` from this folder. The launcher tries `IS_LAB_PYTHON`, `py -3`, `python`, then `python3`. Python 3.10+ is required; `cryptography>=41` is needed by every listed standalone except RSA. Install and test permitted packages **before** the exam.

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
