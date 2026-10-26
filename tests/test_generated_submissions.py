"""Black-box checks for one-file exports, each copied into its own clean folder."""
import ast
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "standalone_submissions" / "generated"
NAMES = ("rsa_product", "patient_records", "grant_portal", "e_voting_demo")


def isolated_run(script, answers, timeout=90):
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(script)], cwd=script.parent,
        input=answers, text=True, capture_output=True, timeout=timeout, env=environment,
    )
    if result.returncode:
        raise AssertionError(f"{script.name} exited {result.returncode}: {result.stderr}\n{result.stdout}")
    return result.stdout


class GeneratedSubmissionTests(unittest.TestCase):
    def test_exports_are_current_deterministic_and_locally_independent(self):
        spec = importlib.util.spec_from_file_location("submission_builder", ROOT / "tools" / "build_submissions.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        first, second = builder.outputs(), builder.outputs()
        self.assertEqual(first, second)
        self.assertEqual(set(first), {f"{name}.py" for name in NAMES})
        for name, content in first.items():
            self.assertEqual((GENERATED / name).read_bytes(), content, f"Stale export: {name}")
            tree = ast.parse(content.decode("utf-8"), filename=name)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(node.module, {"core", "store"})
                    self.assertTrue(node.module.split(".")[0] in sys.stdlib_module_names or node.module.startswith("cryptography"), node.module)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertTrue(alias.name.split(".")[0] in sys.stdlib_module_names or alias.name.startswith("cryptography"), alias.name)
            self.assertNotIn("sys.path.insert", content.decode("utf-8"))
            self.assertNotIn("parents[1]/'demo_data'", content.decode("utf-8"))
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            for directory in (Path(a), Path(b)):
                subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools" / "build_submissions.py"), "--output-dir", str(directory)],
                               check=True, capture_output=True, text=True, timeout=20)
            self.assertEqual({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(a).iterdir()},
                             {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(b).iterdir()})

    def test_rsa_menu_alone(self):
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "rsa_product.py"
            shutil.copy2(GENERATED / script.name, script)
            output = isolated_run(script, "1\n1\n5\n11\n3\n2\n2\n3\n2\n0\n3\n2\n10\n10\n0\n")
            self.assertIn("Encrypted inputs (hex): 0x8, 0x1b", output)
            self.assertIn("Ordinary product verified: 6", output)
            self.assertIn("Both inputs must lie in 1..N-1", output)
            self.assertIn("Modular homomorphic equality verified", output)
            self.assertIn("Ordinary product not verified", output)
            self.assertEqual([p.name for p in Path(d).iterdir()], ["rsa_product.py"])
            bad_key = isolated_run(script, "1\n2\n55\n3\n2\n0\n")
            self.assertIn("Parameters fail sample round trips", bad_key)

    def test_elgamal_menu_alone(self):
        with tempfile.TemporaryDirectory() as d:
            script=Path(d)/'elgamal_product.py'
            shutil.copy2(ROOT/'standalone_submissions'/script.name,script)
            tree=ast.parse(script.read_text(encoding='utf-8'))
            self.assertFalse(any(isinstance(node,ast.ImportFrom) and node.module in {'core','store'} for node in ast.walk(tree)))
            output=isolated_run(script,'2\n1\n15\n2\n5\n1\n467\n2\n5\n2\n2\n3\n2\n30\n20\n0\n')
            self.assertIn('Set group parameters first',output)
            self.assertIn('p must be a prime',output)
            self.assertIn('Ciphertext-only product (hex):',output)
            self.assertIn('Modular homomorphic equality verified',output)
            self.assertIn('Ordinary product verified: 6',output)
            self.assertIn('Ordinary product wraps modulo p: 600',output)
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()),['elgamal_product.py'])

    def test_patient_menu_restart_and_tampering_alone(self):
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "patient_records.py"
            shutil.copy2(GENERATED / script.name, script)
            source=Path(d)/"supplied.json"
            source.write_text(json.dumps([{'Patient_id':'P1','Patient_name':'Ada','Diagnosis':'Diabetes','Blood_glucose':110,'Treatment':'Diet'}]),encoding='utf-8')
            output = isolated_run(script, f"L\n{source}\n2\n4\n5\n3\nP1\n6\n7\nDiabetes\n8\nP1\n9\n")
            self.assertIn("Loaded 1 patient records",output)
            self.assertIn("Dataset signed", output)
            self.assertIn("Verified", output)
            self.assertIn("decrypted_sum': 110", output)
            self.assertIn("encrypted_sum_hex': '0x", output)
            self.assertIn("'Patient_id': 'P1'", output)
            records = Path(d) / "demo_data" / "patients"
            self.assertTrue((records / "Patient_records").is_file())
            self.assertTrue((records / "encrypted_patient_records").is_file())
            self.assertTrue((records / "keys.json").is_file())
            self.assertTrue((records / "rsa_private.pem").is_file())
            restarted = isolated_run(script, f"1\n8\nP1\nL\n{source}\n9\n")
            self.assertIn("'Patient_id': 'P1'", restarted)
            self.assertIn("Patient data already exists", restarted)
            encrypted = records / "encrypted_patient_records"
            data = json.loads(encrypted.read_text(encoding="utf-8"))
            data["signature"] = "AAAA"
            encrypted.write_text(json.dumps(data), encoding="utf-8")
            rejected = isolated_run(script, "5\n8\nP1\n9\n")
            self.assertIn("Verification failed", rejected)
            self.assertIn("decryption blocked", rejected)
            self.assertIn("search blocked", isolated_run(script,"7\nDiabetes\n9\n"))

    def test_patient_search_full_matches_and_malformed_alone(self):
        with tempfile.TemporaryDirectory() as d:
            script=Path(d)/"patient_records.py"
            shutil.copy2(GENERATED/script.name,script)
            source=Path(d)/"supplied.json"
            source.write_text(json.dumps([
                {'Patient_id':'P1','Patient_name':'Ada','Diagnosis':'Diabetes','Blood_glucose':110,'Treatment':'Diet'},
                {'Patient_id':'P2','Patient_name':'Bea','Diagnosis':'diabetes type 2','Blood_glucose':95,'Treatment':'Medicine'},
                {'Patient_id':'P3','Patient_name':'Cal','Diagnosis':'Asthma','Blood_glucose':80,'Treatment':'Inhaler'}]),encoding='utf-8')
            answers=f"L\n{source}\n7\nDIAB\n2\n4\n7\nDIAB\n7\nunknown\n9\n"
            output=isolated_run(script,answers)
            self.assertIn("Verification failed; search blocked",output)
            self.assertIn("'Treatment': 'Diet'",output)
            self.assertIn("'Treatment': 'Medicine'",output)
            self.assertIn("'Blood_glucose': 110",output)
            self.assertIn("Verified matching patient records: []",output)
            records=Path(d)/"demo_data"/"patients"
            (records/"encrypted_patient_records").write_text('{bad',encoding='utf-8')
            malformed=isolated_run(script,"7\nDIAB\n9\n")
            self.assertIn("Malformed stored file",malformed)
            self.assertNotIn("'Treatment': 'Diet'",malformed)

    def test_grant_menu_restart_and_tampering_alone(self):
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "grant_portal.py"
            shutil.copy2(GENERATED / script.name, script)
            output = isolated_run(script, "1\n1\nG1\nStudy\n100\n2\n0\n2\n1\n2\nG1\n3\nG1\n0\n3\n1\nG1\n0\n0\n")
            self.assertIn("Submitted: G1", output)
            self.assertIn("AES encrypted description (hex):", output)
            self.assertIn("Description UTF-8 hex: 5374756479", output)
            self.assertIn("decrypted_final_total': 100", output)
            self.assertIn("encrypted_total_hex': '0x", output)
            records = Path(d) / "demo_data" / "grants"
            self.assertTrue((records / "grants.json").is_file())
            self.assertTrue((records / "keys.json").is_file())
            restarted = isolated_run(script, "1\n2\n0\n3\n1\nmissing\n0\n0\n")
            self.assertIn("Grant ID: G1", restarted)
            self.assertIn("Grant ID not found", restarted)
            data = json.loads((records / "grants.json").read_text(encoding="utf-8"))
            data[0]["signature"] = "AAAA"
            (records / "grants.json").write_text(json.dumps(data), encoding="utf-8")
            rejected = isolated_run(script, "2\n1\n3\nG1\n0\n3\n1\nG1\n0\n0\n")
            self.assertIn("('G1', False)", rejected)
            self.assertIn("Tampering detected; decrypt blocked", rejected)
            self.assertIn("Signature/hash failure; tally blocked", rejected)

    def test_grant_boundaries_alone(self):
        with tempfile.TemporaryDirectory() as d:
            script=Path(d)/"grant_portal.py"
            shutil.copy2(GENERATED/script.name,script)
            answers=("1\n1\nMAX\nLargest\n1000000000000\n"
                     "1\nOVER\nInvalid\n1000000000001\n"
                     "1\nNEG\nInvalid\n-1\n0\n"
                     "3\n1\nMAX\n1\nMAX,missing\n1\nMAX,MAX\n0\n0\n")
            output=isolated_run(script,answers)
            self.assertIn("decrypted_final_total': 1000000000000",output)
            self.assertIn("amount in 0..1000000000000",output)
            self.assertIn("Grant ID not found",output)
            self.assertIn("Select distinct existing IDs",output)

    def test_voting_menu_restart_deadline_and_tampering_alone(self):
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "e_voting_demo.py"
            shutil.copy2(GENERATED / script.name, script)
            now = datetime.now(timezone.utc)
            start = (now - timedelta(days=1)).isoformat()
            end = (now + timedelta(days=1)).isoformat()
            answers = f"1\n{start}\n{end}\n2\n2\nBAD\n3\nNorth\n2\nB1\n1\nNorth\n3\n1\n3\n2\nNorth\n\n\n4\nA\nB\n0\n"
            output = isolated_run(script, answers, timeout=120)
            self.assertIn("EDUCATIONAL DEMONSTRATION ONLY", output)
            self.assertIn("Invalid ballot", output)
            self.assertIn("Encrypted ballot stored", output)
            self.assertIn("AES-CBC ballot ciphertext (hex):", output)
            self.assertIn("RSA-wrapped AES key (hex):", output)
            self.assertIn("ElGamal signature (hex): {'r': '0x", output)
            self.assertIn("Paillier encrypted candidate ID (hex): 0x", output)
            self.assertIn("('B1', True)", output)
            self.assertIn("Tally blocked until the election closes", output)
            records = Path(d) / "demo_data" / "voting"
            self.assertTrue((records / "ballots.json").is_file())
            self.assertTrue((records / "keys.json").is_file())
            self.assertTrue((records / "rsa_private.pem").is_file())
            self.assertEqual(load_pem_private_key((records / "rsa_private.pem").read_bytes(), password=None).key_size, 4096)
            restarted = isolated_run(script, "3\n1\n0\n", timeout=120)
            self.assertIn("('B1', True)", restarted)
            # Test final aggregation after close through the copied file's own class.
            code = (
                "import importlib.util,sys; from pathlib import Path; "
                "from datetime import datetime,timedelta,timezone; "
                "s=importlib.util.spec_from_file_location('vote_export',sys.argv[1]); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                "a=m.VotingApp(Path(sys.argv[2]),clock=lambda:datetime.now(timezone.utc)+timedelta(days=2)); "
                "print(a.tally('A','B')['final_counts'])"
            )
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(script), str(records)],
                                    cwd=d, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("'1': 1", result.stdout)
            data = json.loads((records / "ballots.json").read_text(encoding="utf-8"))
            data[0]["server_record_signature"] = "AAAA"
            (records / "ballots.json").write_text(json.dumps(data), encoding="utf-8")
            rejected = isolated_run(script, "3\n1\n0\n", timeout=120)
            self.assertIn("('B1', False)", rejected)


if __name__ == "__main__":
    unittest.main()
