import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.validate_wheel import (
    EXPECTED_MODULES,
    EXPECTED_SCRIPTS,
    WheelValidationError,
    validate_wheel,
)


class WheelValidatorTests(unittest.TestCase):
    def make_wheel(
        self,
        root: Path,
        *,
        version: str = "0.1.0",
        dependency: bool = False,
        missing_module: str | None = None,
        extra_source: str | None = None,
        second_dist_info: bool = False,
    ) -> Path:
        path = root / "basit_agent_system-0.1.0-py3-none-any.whl"
        dist_info = "basit_agent_system-0.1.0.dist-info"
        metadata = (
            "Metadata-Version: 2.1\n"
            "Name: basit-agent-system\n"
            f"Version: {version}\n"
            "Requires-Python: >=3.11\n"
        )
        if dependency:
            metadata += "Requires-Dist: unsafe-runtime\n"
        entries = ["[console_scripts]"] + [
            f"{name} = {target}" for name, target in sorted(EXPECTED_SCRIPTS.items())
        ]
        with zipfile.ZipFile(path, "w") as archive:
            for module in sorted(EXPECTED_MODULES):
                if module != missing_module:
                    archive.writestr(module, "# packaged module\n")
            if extra_source:
                archive.writestr(extra_source, "# unexpected\n")
            archive.writestr(f"{dist_info}/METADATA", metadata)
            archive.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n")
            archive.writestr(f"{dist_info}/entry_points.txt", "\n".join(entries) + "\n")
            archive.writestr(f"{dist_info}/RECORD", "")
            if second_dist_info:
                archive.writestr("other-1.0.dist-info/METADATA", metadata)
        return path

    def test_accepts_reviewed_dependency_free_wheel(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = validate_wheel(self.make_wheel(Path(directory)))
        self.assertEqual("basit-agent-system", summary["project"])
        self.assertEqual("0.1.0", summary["version"])
        self.assertEqual(0, summary["runtime_dependencies"])

    def test_rejects_runtime_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(Path(directory), dependency=True)
            with self.assertRaisesRegex(WheelValidationError, "runtime dependencies"):
                validate_wheel(wheel)

    def test_rejects_unexpected_python_source(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(Path(directory), extra_source="tests/secret_fixture.py")
            with self.assertRaisesRegex(WheelValidationError, "unexpected Python source"):
                validate_wheel(wheel)

    def test_rejects_missing_reviewed_module(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(Path(directory), missing_module="agent_policy.py")
            with self.assertRaisesRegex(WheelValidationError, "module boundary mismatch"):
                validate_wheel(wheel)

    def test_rejects_version_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(Path(directory), version="0.2.0")
            with self.assertRaisesRegex(WheelValidationError, "version"):
                validate_wheel(wheel)

    def test_rejects_multiple_dist_info_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = self.make_wheel(Path(directory), second_dist_info=True)
            with self.assertRaisesRegex(WheelValidationError, "exactly one"):
                validate_wheel(wheel)


if __name__ == "__main__":
    unittest.main()
