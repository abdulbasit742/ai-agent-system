import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from agent_version import __version__
from scripts.release_bundle import (
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    ReleaseBundleError,
    compare_wheels,
    create_bundle,
    verify_bundle,
)
from scripts.validate_wheel import EXPECTED_MODULES, EXPECTED_SCRIPTS


COMMIT = "a" * 40
EPOCH = 1_700_000_000


def build_wheel(path: Path, marker: str = "") -> Path:
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
            archive.writestr(module, f"# {module}\n")
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
        if marker:
            archive.writestr(f"{dist_info}/build-marker.txt", marker)
    return path


class ReleaseBundleTests(unittest.TestCase):
    def test_create_and_verify_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            manifest = create_bundle([wheel], root / "release", COMMIT, EPOCH)
            result = verify_bundle(root / "release")
        self.assertEqual("basit-agent-system", manifest["project"])
        self.assertEqual(__version__, result["version"])
        self.assertEqual(COMMIT, result["source_commit"])
        self.assertEqual(1, result["artifacts"])

    def test_manifest_and_checksums_are_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            create_bundle([wheel], root / "release-a", COMMIT, EPOCH)
            create_bundle([wheel], root / "release-b", COMMIT, EPOCH)
            manifest_a = (root / "release-a" / MANIFEST_NAME).read_bytes()
            manifest_b = (root / "release-b" / MANIFEST_NAME).read_bytes()
            checksums_a = (root / "release-a" / CHECKSUMS_NAME).read_bytes()
            checksums_b = (root / "release-b" / CHECKSUMS_NAME).read_bytes()
        self.assertEqual(manifest_a, manifest_b)
        self.assertEqual(checksums_a, checksums_b)

    def test_compare_identical_wheels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            second_dir = root / "second"
            second_dir.mkdir()
            second = second_dir / first.name
            shutil.copyfile(first, second)
            result = compare_wheels(first, second)
        self.assertTrue(result["reproducible"])
        self.assertEqual(64, len(result["sha256"]))

    def test_compare_rejects_different_wheel_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_dir = root / "one"
            second_dir = root / "two"
            first_dir.mkdir()
            second_dir.mkdir()
            name = f"basit_agent_system-{__version__}-py3-none-any.whl"
            first = build_wheel(first_dir / name, marker="one")
            second = build_wheel(second_dir / name, marker="two")
            with self.assertRaisesRegex(ReleaseBundleError, "not byte-for-byte reproducible"):
                compare_wheels(first, second)

    def test_create_rejects_invalid_source_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            with self.assertRaisesRegex(ReleaseBundleError, "40-character"):
                create_bundle([wheel], root / "release", "main", EPOCH)

    def test_create_rejects_nonempty_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            output = root / "release"
            output.mkdir()
            (output / "keep.txt").write_text("preserve")
            with self.assertRaisesRegex(ReleaseBundleError, "must be empty"):
                create_bundle([wheel], output, COMMIT, EPOCH)
            self.assertEqual("preserve", (output / "keep.txt").read_text())

    def test_create_rejects_symlink_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            link = root / "linked.whl"
            link.symlink_to(wheel)
            with self.assertRaisesRegex(ReleaseBundleError, "must not be symlinks"):
                create_bundle([link], root / "release", COMMIT, EPOCH)

    def test_create_rejects_duplicate_filenames(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            with self.assertRaisesRegex(ReleaseBundleError, "filenames must be unique"):
                create_bundle([wheel, wheel], root / "release", COMMIT, EPOCH)

    def test_verify_rejects_tampered_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            create_bundle([wheel], root / "release", COMMIT, EPOCH)
            bundled = root / "release" / wheel.name
            bundled.write_bytes(bundled.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ReleaseBundleError, "digest mismatch"):
                verify_bundle(root / "release")

    def test_verify_rejects_tampered_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            create_bundle([wheel], root / "release", COMMIT, EPOCH)
            path = root / "release" / MANIFEST_NAME
            manifest = json.loads(path.read_text())
            manifest["source"]["commit"] = "b" * 40
            path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            with self.assertRaisesRegex(ReleaseBundleError, "integrity check failed"):
                verify_bundle(root / "release")

    def test_verify_rejects_unexpected_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            create_bundle([wheel], root / "release", COMMIT, EPOCH)
            (root / "release" / "unexpected.txt").write_text("no")
            with self.assertRaisesRegex(ReleaseBundleError, "file boundary mismatch"):
                verify_bundle(root / "release")

    def test_verify_rejects_malformed_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = build_wheel(root / f"basit_agent_system-{__version__}-py3-none-any.whl")
            create_bundle([wheel], root / "release", COMMIT, EPOCH)
            (root / "release" / CHECKSUMS_NAME).write_text("not-a-checksum\n")
            with self.assertRaisesRegex(ReleaseBundleError, "malformed line"):
                verify_bundle(root / "release")


if __name__ == "__main__":
    unittest.main()
