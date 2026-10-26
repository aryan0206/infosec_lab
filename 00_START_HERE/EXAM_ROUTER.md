# Mechanism-first router

`exam_router.py` ranks the five existing standalone submissions from operations in the question, then previews the exact `.py` path, launch command, inputs, dependency, persistence location, and FULL/PARTIAL/UNSUPPORTED coverage. It never launches without a separate confirmation. “Encrypted product” + “RSA” points to textbook RSA; “encrypted sum” points to Paillier. A scenario name alone never establishes coverage, and unmatched requirements still need manual comparison with the checklist.

The router checks generated one-file submissions against their sources before launch. A missing package or stale/missing file blocks launch with a diagnostic. RSA still works without `cryptography`; the other four catalog entries require it. The voting match is labelled an educational demonstration because major requirements of the original question remain unmet. Phrase matching is intentionally limited, so confirm the full requirement list before choosing a file.

If the required algorithm is ElGamal multiplication, use the one-file `standalone_submissions/elgamal_product.py`; the Lab 7 development demo imports the same function. If the task asks for true cryptographic SSE/PKSE or threshold decryption, the current standalone files do not satisfy it.
