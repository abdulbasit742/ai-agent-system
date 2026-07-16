import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from agent_version import __version__
from scripts.supply_chain_evidence import (
    IN_TOTO_STATEMENT_V1,
    PROVENANCE_MEDIA_TYPE,
    SPDX_MEDIA_TYPE,
    SPDX_VERSION,
    SLSA_PROVENANCE_V1,
    SupplyChainEvidenceError,
    build_provenance,
    build_spdx_sbom,
    create_evidence,
    evidence_names,
    verify_evidence,
)
from scripts.validate_wheel import EXPECTED_MODULES, EXPECTED_SCRIPTS, validate_wheel


COMMIT = "a" * 40
EPOCH = 1_700_000_000


def build_wheel(path: Path, module_marker: str = "") -> Path:
    dist_info = f"basit_agent_system-{__version__}.dist-info"
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: basit-agent-system\n"
        f"Version: {__version__}\n"
        "Requires-Python: >=3.11\n"
    )
    entry_points = "[console_scripts]\n" + "\n".join(
        f"{name} = {target}" for name, target in sorted(EXPECTED_SCRIPTS.items())
    ) + "\n"
    names = sorted(EXPECTED_MODULES) + [
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/RECORD",
    ]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for module in sorted(EXPECTED_MODULES):
            archive.writestr(module, f"# {module} {module_marker}\n")
        archive.writestr(f"{dist_info}/METADATA", metadata)
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/entry_points.txt", entry_points)
        archive.writestr(
            f"{dist_info}/RECORD",
            "\n".join(f"{name},," for name in names) + "\n",
        )
    return path


class SupplyChainEvidenceTests(unittest.TestCase):
    def test_spdx_sbom_is_deterministic_and_describes_all_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            summary = validate_wheel(wheel)
            first = build_spdx_sbom(wheel, summary, COMMIT, EPOCH)
            second = build_spdx_sbom(wheel, summary, COMMIT, EPOCH)
        self.assertEqual(first, second)
        self.assertEqual(SPDX_VERSION, first["spdxVersion"])
        self.assertEqual("MIT", first["packages"][0]["licenseDeclared"])
        self.assertEqual(sorted(EXPECTED_MODULES), sorted(item["fileName"] for item in first["files"]))
        self.assertEqual(1 + len(EXPECTED_MODULES), len(first["relationships"]))

    def test_spdx_module_hashes_change_with_module_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            one = build_wheel(root / "one.whl", "one")
            two = build_wheel(root / "two.whl", "two")
            first = build_spdx_sbom(one, validate_wheel(one), COMMIT, EPOCH)
            second = build_spdx_sbom(two, validate_wheel(two), COMMIT, EPOCH)
        self.assertNotEqual(first["files"][0]["checksums"], second["files"][0]["checksums"])

    def test_provenance_binds_artifact_source_and_build_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            provenance = build_provenance(wheel, validate_wheel(wheel), COMMIT, EPOCH)
        self.assertEqual(IN_TOTO_STATEMENT_V1, provenance["_type"])
        self.assertEqual(SLSA_PROVENANCE_V1, provenance["predicateType"])
        self.assertEqual(wheel.name, provenance["subject"][0]["name"])
        dependency = provenance["predicate"]["buildDefinition"]["resolvedDependencies"][0]
        self.assertEqual(COMMIT, dependency["digest"]["sha1"])
        parameters = provenance["predicate"]["buildDefinition"]["externalParameters"]
        self.assertEqual(EPOCH, parameters["sourceDateEpoch"])

    def test_create_and_verify_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            summary = validate_wheel(wheel)
            evidence = create_evidence(wheel, summary, COMMIT, EPOCH, root)
            names = verify_evidence(root, wheel, summary, COMMIT, EPOCH, evidence)
        self.assertEqual(2, len(names))
        self.assertEqual(SPDX_MEDIA_TYPE, evidence["sbom"]["media_type"])
        self.assertEqual(PROVENANCE_MEDIA_TYPE, evidence["provenance"]["media_type"])

    def test_evidence_files_are_canonical_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            summary = validate_wheel(wheel)
            evidence = create_evidence(wheel, summary, COMMIT, EPOCH, root)
            for record in evidence.values():
                path = root / record["filename"]
                payload = json.loads(path.read_text())
                self.assertEqual(
                    json.dumps(payload, sort_keys=True, indent=2) + "\n",
                    path.read_text(),
                )

    def test_verify_rejects_tampered_sbom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            summary = validate_wheel(wheel)
            evidence = create_evidence(wheel, summary, COMMIT, EPOCH, root)
            path = root / evidence["sbom"]["filename"]
            path.write_text(path.read_text() + " ")
            with self.assertRaisesRegex(SupplyChainEvidenceError, "digest mismatch"):
                verify_evidence(root, wheel, summary, COMMIT, EPOCH, evidence)

    def test_verify_rejects_semantically_modified_provenance_even_with_updated_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            summary = validate_wheel(wheel)
            evidence = create_evidence(wheel, summary, COMMIT, EPOCH, root)
            path = root / evidence["provenance"]["filename"]
            payload = json.loads(path.read_text())
            payload["predicate"]["buildDefinition"]["externalParameters"]["sourceDateEpoch"] += 1
            path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
            import hashlib

            evidence["provenance"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            evidence["provenance"]["size"] = path.stat().st_size
            with self.assertRaisesRegex(SupplyChainEvidenceError, "does not match"):
                verify_evidence(root, wheel, summary, COMMIT, EPOCH, evidence)

    def test_verify_rejects_wrong_media_type(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            summary = validate_wheel(wheel)
            evidence = create_evidence(wheel, summary, COMMIT, EPOCH, root)
            evidence["sbom"]["media_type"] = "application/json"
            with self.assertRaisesRegex(SupplyChainEvidenceError, "media type"):
                verify_evidence(root, wheel, summary, COMMIT, EPOCH, evidence)

    def test_verify_rejects_symlink_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            summary = validate_wheel(wheel)
            evidence = create_evidence(wheel, summary, COMMIT, EPOCH, root)
            path = root / evidence["sbom"]["filename"]
            backup = root / "sbom-backup.json"
            path.replace(backup)
            path.symlink_to(backup)
            with self.assertRaisesRegex(SupplyChainEvidenceError, "missing or unsafe"):
                verify_evidence(root, wheel, summary, COMMIT, EPOCH, evidence)

    def test_rejects_invalid_source_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            with self.assertRaisesRegex(SupplyChainEvidenceError, "40-character"):
                build_provenance(wheel, validate_wheel(wheel), "main", EPOCH)

    def test_rejects_runtime_dependency_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            summary = validate_wheel(wheel)
            summary["runtime_dependencies"] = 1
            with self.assertRaisesRegex(SupplyChainEvidenceError, "dependency-free"):
                build_spdx_sbom(wheel, summary, COMMIT, EPOCH)

    def test_rejects_unsafe_wheel_name(self):
        with self.assertRaisesRegex(SupplyChainEvidenceError, "unsafe"):
            evidence_names("../unsafe.whl")


if __name__ == "__main__":
    unittest.main()
