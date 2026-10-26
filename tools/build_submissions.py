"""Build deterministic, self-contained exam scripts from the development sources.

The builder parses top-level statements before assembling them. It rejects unexpected
module-level code and duplicate definitions instead of concatenating arbitrary files.
Only the shared functions referenced by a scenario (including transitive helpers) are
included; store functions are small and kept together for persistent records.
"""
import argparse
import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "standalone_submissions" / "generated"
SCENARIOS = {
    "patient_records": ROOT / "10_integrated_scenarios" / "patient_records.py",
    "grant_portal": ROOT / "10_integrated_scenarios" / "grant_portal.py",
    "e_voting_demo": ROOT / "10_integrated_scenarios" / "e_voting_demo.py",
}
RSA_SOURCE = ROOT / "standalone_submissions" / "rsa_product.py"


def read_tree(path):
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=str(path))


def segment(source, node):
    result = ast.get_source_segment(source, node)
    if result is None:
        raise ValueError(f"Cannot recover source for line {node.lineno}")
    return result


def is_main_guard(node):
    return (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Eq)
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "__main__"
    )


def is_module_docstring(node):
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)


def split_module(source, tree, role):
    imports, definitions, main_guards = [], [], []
    for node in tree.body:
        if is_module_docstring(node):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.module in {"core", "store"}:
                if role == "core":
                    raise ValueError("core.py unexpectedly imports a project module")
                continue
            imports.append(node)
        elif isinstance(node, ast.Expr) and segment(source, node).startswith("sys.path.insert("):
            if role != "scenario":
                raise ValueError(f"Unexpected path mutation in {role}")
            continue
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Assign, ast.AnnAssign)):
            definitions.append(node)
        elif is_main_guard(node):
            if role != "scenario":
                raise ValueError(f"Unexpected entry point in {role}")
            main_guards.append(node)
        else:
            raise ValueError(f"Unexpected top-level {type(node).__name__} in {role} at line {node.lineno}")
    if role == "scenario" and len(main_guards) != 1:
        raise ValueError("A scenario must have exactly one main entry point")
    return imports, definitions, main_guards


def defined_names(node):
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return [node.name]
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [child.id for target in targets for child in ast.walk(target) if isinstance(child, ast.Name)]


def core_closure(core_definitions, consumer_nodes):
    by_name = {}
    for node in core_definitions:
        for name in defined_names(node):
            if name in by_name:
                raise ValueError(f"Duplicate core definition: {name}")
            by_name[name] = node
    needed = {name for node in consumer_nodes for name in loaded_names(node) if name in by_name}
    selected = set()
    while needed:
        name = needed.pop()
        node = by_name[name]
        if id(node) in selected:
            continue
        selected.add(id(node))
        needed.update(other for other in loaded_names(node) if other in by_name and id(by_name[other]) not in selected)
    return [node for node in core_definitions if id(node) in selected]


def loaded_names(node):
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)}


def import_lines(import_nodes, used_bindings):
    """Normalize imports, and reject distinct imports that bind the same name."""
    entries, bindings = [], {}
    for node in import_nodes:
        for alias in node.names:
            if alias.name == "*":
                raise ValueError("Wildcard imports cannot be emitted in a submission")
            if isinstance(node, ast.Import):
                binding = alias.asname or alias.name.split(".")[0]
                statement = f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
            else:
                binding = alias.asname or alias.name
                dots = "." * node.level
                statement = f"from {dots}{node.module or ''} import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
            if binding not in used_bindings:
                continue
            previous = bindings.get(binding)
            if previous is not None and previous != statement:
                raise ValueError(f"Import binding collision for {binding}: {previous} / {statement}")
            if previous is None:
                bindings[binding] = statement
                entries.append(statement)
    return entries, set(bindings)


def render_scenario(name, path):
    core_source, core_tree = read_tree(ROOT / "core.py")
    store_source, store_tree = read_tree(ROOT / "store.py")
    scenario_source, scenario_tree = read_tree(path)
    core_imports, core_defs, _ = split_module(core_source, core_tree, "core")
    store_imports, store_defs, _ = split_module(store_source, store_tree, "store")
    scenario_imports, scenario_defs, guards = split_module(scenario_source, scenario_tree, "scenario")
    selected_core = core_closure(core_defs, store_defs + scenario_defs)
    all_definitions = selected_core + store_defs + scenario_defs
    seen = {}
    for node in all_definitions:
        for binding in defined_names(node):
            if binding in seen:
                raise ValueError(f"Definition collision for {binding}")
            seen[binding] = node
    used_bindings = set().union(*(loaded_names(node) for node in all_definitions + guards))
    imports, import_bindings = import_lines(core_imports + store_imports + scenario_imports, used_bindings)
    collisions = set(seen) & import_bindings
    if collisions:
        raise ValueError(f"Import/definition collision: {sorted(collisions)}")
    input_hash = hashlib.sha256((core_source + "\0" + store_source + "\0" + scenario_source).encode("utf-8")).hexdigest()[:16]
    sections = [
        f'"""Self-contained {name} exam demonstration. Generated; edit development sources instead.\n\n'
        f'Requires Python 3.10+ and the cryptography package. Source fingerprint: {input_hash}.\n'
        'Stored private keys are local teaching material, not protected key custody.\n"""',
        "# AUTO-GENERATED by tools/build_submissions.py. Regenerate after source changes.",
        "# Cryptographic bytes stay raw in memory; new records use hex, legacy records use Base64.",
    ]
    if name == "e_voting_demo":
        sections.append("# EDUCATIONAL ONLY: no trusted timestamp authority, voter identity binding, formal SSE, or threshold Paillier.")
    sections.append("\n".join(imports))
    for label, source, nodes in (
        ("Shared cryptographic functions", core_source, selected_core),
        ("Persistent record helpers", store_source, store_defs),
        ("Scenario workflow and menu", scenario_source, scenario_defs),
    ):
        sections.append(f"# ---- {label} ----")
        for node in nodes:
            block = segment(source, node)
            if label == "Scenario workflow and menu" and isinstance(node, ast.FunctionDef) and node.name == "main":
                old = "Path(__file__).resolve().parents[1]/'demo_data'"
                new = "Path(__file__).resolve().parent/'demo_data'"
                if block.count(old) != 1:
                    raise ValueError(f"Expected one data-directory expression in {name}.main")
                block = block.replace(old, new)
            sections.append(block)
    sections.append(segment(scenario_source, guards[0]))
    result = "\n\n".join(sections) + "\n"
    tree = ast.parse(result, filename=f"generated/{name}.py")
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {"core", "store"}:
            raise ValueError(f"Generated {name} still imports a toolkit module")
    if sum(is_main_guard(node) for node in tree.body) != 1:
        raise ValueError(f"Generated {name} lacks a single entry point")
    return result.encode("utf-8")


def outputs():
    rsa_source = RSA_SOURCE.read_text(encoding="utf-8")
    rsa_header = '"""Self-contained RSA product exam submission. Generated from the tested standalone source."""\n\n# AUTO-GENERATED by tools/build_submissions.py.\n\n'
    rsa_output = (rsa_header + rsa_source.rstrip() + "\n").encode("utf-8")
    ast.parse(rsa_output.decode("utf-8"), filename="generated/rsa_product.py")
    result = {"rsa_product.py": rsa_output}
    result.update({f"{name}.py": render_scenario(name, path) for name, path in SCENARIOS.items()})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="verify that existing exports match source; write nothing")
    args = parser.parse_args()
    built = outputs()
    if args.check:
        stale = [name for name, data in built.items() if not (args.output_dir / name).exists() or (args.output_dir / name).read_bytes() != data]
        if stale:
            raise SystemExit("Missing or stale exports: " + ", ".join(stale))
        print(f"CURRENT: {len(built)} generated submissions match their sources")
        return
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in built.items():
        target = args.output_dir / name
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)
        print(f"Generated {target} ({len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()[:16]})")


if __name__ == "__main__":
    main()
