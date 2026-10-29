# Option 10 prompt cheat sheet — read this while entering a question

**Path:** `START_TOOLKIT.bat → 3 → 11` to check components, then builder `10` to configure. This is a question-reading guide, **not a scenario preset**. Use the exact question's names and numbers. Option 11 and `COMPONENT_CATALOG.md` determine whether an algorithm is actually supported.

## 1. Make a six-line plan before typing

| Write down | How to get it from the question |
| --- | --- |
| Fields | List the distinct values entered/stored **per record**. Do not count generated IVs, nonces, hashes, signatures, ciphertexts or keys as user fields. |
| Roles | List jobs with different permissions. Count roles, not people, hospitals or algorithms. |
| Operations per role | Underline action verbs and use only the exact names in the table below. |
| Access per role | Decide `all` or `own`, then any exact plaintext-field condition. |
| Crypto and bounds | Copy exact mode, key size, hash, signature, search, integer limits, freshness window and sharing threshold from the question. Do not silently substitute. |
| Architecture | `standalone` for one local program; `tcp_client_server` only when the question needs separate communicating programs and its security limits are acceptable. |

**Count example:** “Coordinator enters patient ID, site, notes and dosage” = **4 fields**. “Coordinator submits; Auditor verifies; Statistician aggregates” = **3 roles**. A fourth hospital does not add a fourth role. If the question requires individual accounts, option 10's shared-role PIN and `own` policy do not meet that requirement.

## 2. Copy the supported operation names exactly

At `Allowed operations, comma separated`, enter only the operations that role needs, such as `submit,view`. No spaces are necessary; the builder trims spaces. A role can have several operations.

| Question verb/requirement | Type | Prerequisite or important limit |
| --- | --- | --- |
| Enter, upload, create a record | `submit` | Role must be allowed to submit. |
| See stored fields or ciphertext | `view` | Shows selected fields, **not plaintext** for AES-encrypted fields. |
| Verify a record/signature/ledger | `verify` | The engine checks the ledger as it loads; there is no separate whole-ledger menu choice. |
| Exact search by a field | `search` | Mark that field `Exact HMAC search index = Y`. No full-text search. |
| Approve/reject | `approve` | Only the literal decisions `approved` and `rejected`. This rewrites a local record, not an independently signed decision event. |
| Read an AES field in plaintext | `decrypt` | Also name that field at `Fields permitted for decrypt`. |
| Paillier sum/weighted sum/mean | `aggregate` | Select a required, nonnegative integer `Paillier aggregate field`. The role sees final aggregate, not an individual decrypt menu. |
| Show offset/hex/ASCII dump | `hex_dump,decrypt` | Both operations and the encrypted field in `decrypt_fields` are required. |
| Educational RSA ciphertext multiplication | `rsa_product` | Enable `textbook_rsa`; separate from RSA-OAEP. |
| Show key-file paths | `keys` | This is **not** key administration, rotation or secure distribution. |
| TCP client sends records | `send,submit` | Select TCP port/architecture. PIN travels without TLS. |
| TCP server receives records | `serve` | Select TCP port/architecture. No sender-origin signature verification. |

The complete exact operation vocabulary in `general_builder.py:OPS` is `submit,view,verify,search,approve,decrypt,aggregate,keys,rsa_product,hex_dump,serve,send`. If the question asks for an action outside that vocabulary, check option 11 and report it as unsupported unless another implemented path proves otherwise.

## 3. Role-policy prompt decisions

| Prompt | Fill it when… | Leave blank when… |
| --- | --- | --- |
| `Require PIN authentication` | `Y` when a role must log in or its menu actions need role authentication. | `N` when the exercise does not require login. **Limit:** one PIN identifies the whole role, not a person. |
| `Record access all/own` | `own` for records submitted by this role; `all` for auditors/aggregators across roles. | Never blank intentionally; default is `all`. **Limit:** `own` compares role name, not individual account. |
| `Visible field names, comma separated (empty = all)` | Give exact internal field names, e.g. `case_id,status`, to limit what `view` returns. | Blank means **all fields visible to `view`**, including encrypted ciphertext objects. It does not mean “none.” |
| `Fields permitted for decrypt, comma separated` | List exact **AES-encrypted** internal field names the role may read in plaintext, e.g. `clinical_notes`. | Blank when the role must not decrypt. Do not select the `decrypt` operation with this blank. |
| `Record condition field (empty = none)` | The role is restricted to an exact value of a **plaintext, non-Paillier** field; the builder then asks that value. | No fixed equality condition is stated. It cannot express arbitrary site membership, time policy or individual ownership. |

**Field prompts:** choose `text`, `integer`, or `boolean`; mark `Required = Y` when the record cannot omit it. For text, enter length limits; leave `Allowed choices` blank unless the question supplies an exact allowed list. For integers, enter actual min/max. Set `Encrypt this field with AES = Y` for fields that need AES confidentiality. Set `Exact HMAC search index = Y` only for fields users must search exactly. If an integer is the Paillier aggregate field, keep its AES flag `N`; selecting it as the aggregate field encrypts it with Paillier.

**Common blank/zero prompts:** blank aggregate-field name disables Paillier; Shamir threshold `0` disables sharing; freshness `0` disables the window; blank TCP port selects standalone; blank record condition means no condition. A blank visible-field list means **all**, while a blank decrypt-field list means **none**. These two blanks have opposite effects.

## 4. Final compatibility check before `Generate? Y`

- `search` → at least one field marked searchable.
- `decrypt`/`hex_dump` → encrypted field and exact decrypt-field permission.
- `aggregate` → required nonnegative integer aggregate field; Shamir also needs this.
- RSA-OAEP wrapping → AES-encrypted field.
- `rsa_product` → textbook RSA component enabled.
- `send` → `submit`; `send`/`serve` → TCP port and architecture.
- Role condition → plaintext field, not AES or Paillier.

Review the printed configuration summary and `.checklist.txt`. The generator rejects some incompatible choices but cannot infer whether it satisfies every line of an unfamiliar question. See `FINAL_GAP_REPORT.md` for unsupported workflows and security limits.

**Critical summary check:** At least one intended submitter role must show `"operations": ["submit", ...]`. Also check role-name spelling and each decrypt/search/aggregate permission. The current self-test skips its submit/restart exercise when no role has `submit`, so `SELF-TEST PASSED` alone does not catch a missing submit operation.

## 5. PyCharm Terminal: run and test the generated file

Open **Terminal** in PyCharm. It should start at the project root; otherwise change to the folder containing `START_TOOLKIT.bat`. Replace `general_application_YYYYMMDD_HHMMSS.py` with the **exact** filename printed after `NEW SUBMISSION:`. The simple commands work in PowerShell or Command Prompt when `python` selects a supported interpreter with `cryptography` installed:

```powershell
python -B exam_output\general_application_YYYYMMDD_HHMMSS.py --self-test
python -B exam_output\general_application_YYYYMMDD_HHMMSS.py
```

The first command should print `SELF-TEST PASSED`; it is a **smoke test** in temporary storage. The second opens the real role/action menu and persists data under `exam_output/demo_data/<generated filename without .py>/`. You do **not** need a virtual environment specifically. You need supported Python with `cryptography>=41,<51`; run BAT option 1 on the exam PC to check readiness. If `python` in PyCharm Terminal says `ModuleNotFoundError: cryptography`, choose BAT option 2 to set up the package locally, select that interpreter in PyCharm, and retry. Do not copy this PC's `.venv` to another PC. The PyCharm **Run** button also works with the correctly configured interpreter; use Terminal if PIN input is awkward in Run.

**Menu practice for a four-field trial record:** select the submitter role, set/enter its PIN if configured, type `submit` at `Action:`, then enter values such as `P001`, `SITE-A`, `First trial note`, `20` in the configured field order. Save the printed Record ID. Submit `P002`, `SITE-A`, `Second trial note`, `30`. An auditor can `verify` a saved ID; `search` with internal field name `patient_id` and value `P001`; `hex_dump` with saved ID and field `clinical_notes`. An aggregator can enter the two saved IDs, leave weights blank, and enter Shamir share numbers `1,2` for a sum of 50 and mean 25.0. Use `back` to leave a role and `0` at `Role (...; 0 exit):` to quit. Rerun the same file to check persistence. These example values apply only if you configured those field names and operations.

**One-file submission:** for `standalone`, submit the generated `.py` named by `NEW SUBMISSION:`; keep its `.checklist.txt` for self-review. For `tcp_client_server`, keep the generated shared `.py`, `_server.py`, and `_client.py` together and start the server first. The generated `--self-test` does not certify tamper, replay, stale-time or every question-specific requirement.
