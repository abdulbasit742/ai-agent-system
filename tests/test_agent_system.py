import tempfile, unittest
from pathlib import Path
import agent_system as a

class Tests(unittest.TestCase):
    def test_guard(self):
        self.assertFalse(a.guard("git reset --hard HEAD~1")["allowed"])
        self.assertTrue(a.guard("python -m unittest")["allowed"])
    def test_scan(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); risky="allow_"+'origins=[\"*\"]\n'+"auth_"+"required=false\n"+"subprocess."+"run(x, shell=True)\n"; (p/"server.py").write_text(risky)
            ids={x["rule_id"] for x in a.scan(p)}
            self.assertTrue({"BAS010","BAS011","BAS012"}.issubset(ids))
    def test_scrub(self):
        token="sk-"+"abcdefghijklmnopqrstuvwxyz123456"; out,m=a.scrub("token="+token+"\nali@example.com")
        self.assertNotIn(token,out); self.assertGreaterEqual(len(m),2)
    def test_audit(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"audit.jsonl"; a.append_audit(p,"x",{"ok":True}); a.append_audit(p,"y",{"ok":True}); self.assertEqual(a.verify_audit(p),(True,2))

if __name__ == "__main__": unittest.main()
