#!/usr/bin/env python3
"""test_determinism.py - 再生成の安定性 + research除外強制分類 (basis階層)"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import classify


class TestDeterminism(unittest.TestCase):
    def _mkrepo(self, d: Path):
        (d / "scripts").mkdir(parents=True)
        for f in (ROOT / "scripts").glob("*.py"):
            shutil.copy(f, d / "scripts" / f.name)
        (d / "config").mkdir()
        shutil.copy(ROOT / "config" / "research-scanners.json", d / "config" / "research-scanners.json")

    def test_same_input_same_output(self):
        """同一observationsから2回生成 → feeds/iocs.csv + metadata.json がバイト一致"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            obs = td / "observations" / "2026" / "09" / "24"
            obs.mkdir(parents=True)
            obs.joinpath("24.jsonl").write_text("\n".join([
                json.dumps({"kind": "ip", "ip": "9.9.9.9", "event_type": "ssh-bruteforce", "day": "2026-09-24", "hits": 12}),
                json.dumps({"kind": "ip", "ip": "9.9.9.9", "event_type": "ssh-post-auth", "day": "2026-09-24", "hits": 2}),
                json.dumps({"kind": "ip", "ip": "8.8.4.4", "event_type": "http-scan", "day": "2026-09-24", "hits": 3}),
                json.dumps({"kind": "url", "url": "http://example.invalid/a", "day": "2026-09-24", "hits": 1}),
            ]) + "\n", encoding="utf-8")
            repo = td / "repo"
            self._mkrepo(repo)
            digests = []
            for _ in range(2):
                r = subprocess.run([sys.executable, "scripts/generate_feeds.py",
                                    "--observations-dir", str(obs)],
                                   cwd=repo, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace")
                self.assertEqual(r.returncode, 0, r.stderr)
                digests.append((
                    (repo / "feeds" / "iocs.csv").read_bytes(),
                    (repo / "metadata.json").read_text(encoding="utf-8"),
                ))
            self.assertEqual(digests[0][0], digests[1][0], "feeds/iocs.csv が再生成で一致しない")
            self.assertEqual(digests[0][1], digests[1][1], "metadata.json が再生成で一致しない")

    def test_generation_without_enrich_cache(self):
        """enrich-cacheが無くてもfeed生成できる (enrichment列は空)"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            obs = td / "observations" / "2026" / "09" / "24"
            obs.mkdir(parents=True)
            obs.joinpath("24.jsonl").write_text(
                json.dumps({"kind": "ip", "ip": "9.9.9.9", "event_type": "ssh-probe",
                            "day": "2026-09-24", "hits": 1}) + "\n", encoding="utf-8")
            repo = td / "repo"
            self._mkrepo(repo)
            r = subprocess.run([sys.executable, "scripts/generate_feeds.py",
                                "--observations-dir", str(obs),
                                "--enrich-cache", str(td / "nope.json")],
                               cwd=repo, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("OK", r.stdout)

    def test_research_config_forces_classification(self):
        """config一致 (official/verified) はresearch-scanner扱い+blocklist除外。heuristicは除外しない"""
        import generate_feeds as gf
        import normalize
        recs = normalize.aggregate([
            {"indicator": "66.132.172.138", "type": "ip",
             "first_seen": "2026-09-24", "last_seen": "2026-09-24",
             "hits": 1, "categories": ["http-scan"], "sources": ["http"], "size": None,
             "event_type": "http-scan"},
            {"indicator": "104.152.52.9", "type": "ip",  # heuristicエントリのprefix
             "first_seen": "2026-09-24", "last_seen": "2026-09-24",
             "hits": 1, "categories": ["ssh-post-auth"], "sources": ["ssh"], "size": None,
             "event_type": "ssh-post-auth"},
            {"indicator": "1.2.3.4", "type": "ip",
             "first_seen": "2026-09-24", "last_seen": "2026-09-24",
             "hits": 5, "categories": ["ssh-post-auth"], "sources": ["ssh"], "size": None,
             "event_type": "ssh-post-auth"},
        ])
        rp = gf.load_research_config()
        self.assertTrue(any(p.startswith("66.132") for p, _, _ in rp))
        rows = gf.build(recs, None, rp)
        by = {r["indicator"]: r for r in rows}
        # official (Censys) は強制分類
        self.assertEqual(by["66.132.172.138"]["event_type"], "research-scanner")
        self.assertEqual(by["66.132.172.138"]["severity"], "info")
        self.assertFalse(classify.in_blocklist(by["66.132.172.138"]["event_type"], 999))
        # heuristic (104.152.52.) は強制分類されない = 安全側
        self.assertEqual(by["104.152.52.9"]["event_type"], "ssh-post-auth")
        # heuristic該当IPはblocklist入りし得る (除外されない)
        self.assertTrue(classify.in_blocklist(by["104.152.52.9"]["event_type"], 5))


if __name__ == "__main__":
    unittest.main()
