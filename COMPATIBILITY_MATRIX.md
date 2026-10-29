# Exam PC compatibility

| Item | CPython | Dependencies | Exam PC status |
| --- | --- | --- | --- |
| BAT menu and diagnostics | Windows command shell; no Python for the menu | None | Shows NOT READY if no supported interpreter is found. |
| Readiness, setup, builder, ZIP preparation | 3.10 through 3.14; 3.12 preferred | Standard library | 3.12.14 tested on Windows 11 x64. Other versions require a target-PC smoke test. |
| Custom hash/search/audit/approval records without crypto features | 3.10 through 3.14 | Standard library | Can generate and run without `cryptography`; records and amounts are plaintext. |
| Secure records, grant, encrypted aggregation, approval with RSA signatures, general with AES/RSA/Paillier | 3.10 through 3.14 | `cryptography>=41,<51` | 3.12.14 with cryptography 50.0.2 tested. |
| Fixed RSA/ElGamal arithmetic examples | 3.10 through 3.14 | Standard library | Existing tests cover them on 3.12. |
| Fixed Paillier/patient/grant/voting examples | 3.10 through 3.14 | `cryptography>=41,<51` | Existing tests cover them on 3.12; voting remains educational/partial. |

The 3.10 minimum follows the project's existing launcher policy and use of current language/library APIs. The upper bound is conservative for this toolkit; the packaged cryptography release may itself support newer Python. Only Windows CPython 3.12.14 x64 has been exercised here. Other minor versions or architectures are **not verified** until option 1 and a generated program's self-test pass on the actual PC. Python 3.8 and 3.9 are not supported by this toolkit. The toolkit's two generated records variants both compile on the selected interpreter before writing an exam file.

`cryptography` supplies AES-GCM and RSA-PSS and is used by the existing Paillier key generator. The standard-library profile does not import it. The wheelhouse is target-specific: Windows OS, CPU architecture and CPython ABI must match the manifest. Linux and macOS cannot run Windows executables or use Windows wheels. Virtual environments contain paths to their base interpreter and must be recreated after extraction.

If Python is absent, use an already-installed supported interpreter or arrange a permitted user-local full Python installation **before** the exam. A portable runtime is not included or tested. Do not assume the official embeddable ZIP supports pip/venv; it does not include pip by default. Without a permitted interpreter, the Python builder cannot run. Internet is needed for online setup; offline setup needs a matching, complete wheelhouse prepared and tested in advance.
