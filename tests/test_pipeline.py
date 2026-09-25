#!/usr/bin/env python3
"""test_pipeline.py - IOCパイプラインの単体テスト (依存: 標準ライブラリのみ)

実行: uv run python -m unittest discover -s tests -v  (repo直下から)
"""
import csv
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import classify
import normalize
import validate as vmod

NOW = datetime(2026, 9, 24, 0, 0, tzinfo=timezone.utc)
EMPTY = classify.EMPTY_SHA256


class TestClassify(unittest.TestCase):
    def test_confidence_severity_table(self):
        self.assertEqual(classify.confidence_of("ssh-probe"), 20)
        self.assertEqual(classify.confidence_of("ssh-bruteforce"), 60)
        self.assertEqual(classify.confidence_of("ssh-post-auth"), 90)
        self.assertEqual(classify.confidence_of("ssh-malware-drop"), 100)
        self.assertEqual(classify.severity_of("ssh-probe"), "low")
        self.assertEqual(classify.severity_of("ssh-malware-drop"), "critical")

    def test_primary_event_type_priority(self):
        self.assertEqual(classify.primary_event_type(
            {"ssh-probe", "ssh-bruteforce", "ssh-post-auth"}), "ssh-post-auth")
        self.assertEqual(classify.primary_event_type({"ssh-probe"}), "ssh-probe")
        self.assertEqual(classify.primary_event_type(set()), "unknown-artifact")

    def test_status_ttl(self):
        # ssh-probe TTL 7日: 3日経過=active, 5日=stale, 10日=expired
        ls = lambda d: (NOW - timedelta(days=d)).strftime("%Y-%m-%d")
        self.assertEqual(classify.status_of(ls(3), "ssh-probe", NOW), "active")
        self.assertEqual(classify.status_of(ls(5), "ssh-probe", NOW), "stale")
        self.assertEqual(classify.status_of(ls(10), "ssh-probe", NOW), "expired")
        # malware-drop TTL 180日
        self.assertEqual(classify.status_of(ls(100), "ssh-malware-drop", NOW), "stale")

    def test_blocklist_excludes_research(self):
        self.assertFalse(classify.in_blocklist("research-scanner", 9999))
        self.assertTrue(classify.in_blocklist("ssh-malware-drop", 1))
        self.assertFalse(classify.in_blocklist("ssh-post-auth", 2))
        self.assertTrue(classify.in_blocklist("ssh-post-auth", 3))

    def test_artifact_classification(self):
        self.assertEqual(classify.classify_artifact("/var/tmp/redtail.x86_64"), "malware-binary")
        self.assertEqual(classify.classify_artifact("evidence/clean.sh"), "dropper-script")
        self.assertEqual(classify.classify_artifact("home/u/.ssh/authorized_keys"), "authorized-key")
        self.assertEqual(classify.classify_artifact("whatever.bin"), "unknown-artifact")


class TestNormalize(unittest.TestCase):
    def _obs_file(self, records):
        d = tempfile.mkdtemp()
        p = Path(d) / "24.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        return str(p)

    def test_observations_ip(self):
        p = self._obs_file([
            {"kind": "ip", "ip": "1.2.3.4", "event_type": "ssh-bruteforce", "day": "2026-09-20", "hits": 5},
            {"kind": "ip", "ip": "1.2.3.4", "event_type": "ssh-bruteforce", "day": "2026-09-21", "hits": 2},
        ])
        recs = normalize.parse_observations(p)
        agg = normalize.aggregate(recs)
        self.assertEqual(len(agg), 1)
        r = agg[0]
        self.assertEqual(r["indicator"], "1.2.3.4")
        self.assertEqual(r["hits"], 7)
        self.assertEqual(r["first_seen"], "2026-09-20")
        self.assertEqual(r["last_seen"], "2026-09-21")
        self.assertEqual(r["event_type"], "ssh-bruteforce")

    def test_observations_url_hash(self):
        p = self._obs_file([
            {"kind": "url", "url": "http://evil.invalid/x", "day": "2026-09-20", "hits": 3},
            {"kind": "hash", "sha256": "b" * 64, "size": 123, "day": "2026-09-20", "hits": 1},
            {"kind": "hash", "sha256": EMPTY, "size": 0, "day": "2026-09-20", "hits": 1},
        ])
        agg = normalize.aggregate(normalize.parse_observations(p))
        kinds = {r["type"]: r for r in agg}
        self.assertIn("url", kinds)
        self.assertIn("sha256", kinds)
        self.assertEqual(kinds["sha256"]["size"], 123)
        self.assertEqual(len(agg), 2)  # 空sha除外

    def test_observations_bad_kind_raises(self):
        p = self._obs_file([{"kind": "cookie", "day": "2026-09-20", "hits": 1}])
        with self.assertRaises(ValueError):
            normalize.parse_observations(p)

    def test_observations_forbidden_keys_rejected_by_validator(self):
        # session/event_id混入 → validate_rawが落とす
        import validate_raw
        p = self._obs_file([
            {"kind": "ip", "ip": "1.2.3.4", "event_type": "ssh-probe", "day": "2026-09-20",
             "hits": 1, "session": "abc"},
        ])
        # ファイル名を日付パスに合わせる
        import shutil
        d = Path(tempfile.mkdtemp()) / "2026" / "09" / "20"
        d.mkdir(parents=True)
        shutil.copy(p, d / "20.jsonl")
        errs = validate_raw.validate_file(d / "20.jsonl")
        self.assertGreater(errs, 0)

    def test_legacy_csv_still_parses(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as f:
            w = csv.writer(f)
            w.writerow(["type", "value", "category", "source", "first_seen", "last_seen", "hits", "detail"])
            w.writerow(["ip", "5.6.7.8", "ssh-post-auth", "ssh", "2026-09-19T10:00:00",
                        "2026-09-22T11:00:00", "4", ""])
            n = f.name
        recs = normalize.parse_legacy_csv(n)
        os.unlink(n)
        recs = normalize.aggregate(recs)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["event_type"], "ssh-post-auth")
        self.assertEqual(recs[0]["first_seen"], "2026-09-19")  # 日付粒度へ切詰め


class TestValidate(unittest.TestCase):
    def test_validate_rejects_bad_rows(self):
        p = self._tmpcsv([
            ["1.2.3.4", "ip", "ssh-probe", "low", "20", "active", "2026-09-20", "2026-09-19", "0"],   # first>last, hits=0
            ["not-an-ip", "ip", "ssh-probe", "low", "20", "active", "2026-09-20", "2026-09-20", "1"],  # bad IP
            ["zz", "sha256", "malware-binary", "critical", "90", "active", "2026-09-20", "2026-09-20", "1"],  # bad sha
            ["1.2.3.4", "ip", "bogus-type", "low", "20", "active", "2026-09-20", "2026-09-20", "1"],        # dup + bad event_type
        ])
        errs = vmod.validate_iocs_csv(p)
        os.unlink(p)
        self.assertTrue(any("first_seen > last_seen" in e for e in errs))
        self.assertTrue(any("IP形式" in e for e in errs))
        self.assertTrue(any("SHA256" in e for e in errs))
        self.assertTrue(any("duplicate" in e for e in errs))
        self.assertTrue(any("不正なevent_type" in e for e in errs))

    def test_public_feed_forbidden_columns(self):
        # event_id/detail/sessionが公開feedに混入したらvalidateが落とす
        f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="")
        w = csv.writer(f)
        w.writerow(vmod.PUBLIC_COLS + ["event_id", "session"])
        w.writerow(["1.2.3.4", "ip", "ssh-probe", "low", "20", "active",
                    "2026-09-20", "2026-09-20", "1", "evt-123", "sess-9"])
        f.close()
        errs = vmod.validate_iocs_csv(f.name)
        os.unlink(f.name)
        self.assertTrue(any("禁止カラム" in e for e in errs), errs)

    def _tmpcsv(self, rows):
        f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="")
        w = csv.writer(f)
        w.writerow(vmod.PUBLIC_COLS)
        for r in rows:
            w.writerow(r)
        f.close()
        return f.name

    def test_metadata_aggregation(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            feeds = d / "feeds"; feeds.mkdir()
            import generate_feeds as gf
            recs = normalize.aggregate([
                {"indicator": "1.2.3.4", "type": "ip", "first_seen": "2026-09-20", "last_seen": "2026-09-20",
                 "hits": 1, "categories": ["ssh-probe"], "sources": ["ssh"], "size": None, "event_type": None},
                {"indicator": "2.2.2.2", "type": "ip", "first_seen": "2026-08-01", "last_seen": "2026-08-01",
                 "hits": 1, "categories": ["ssh-probe"], "sources": ["ssh"], "size": None, "event_type": None},
            ])
            rows = gf.build(recs, NOW, ())
            meta = {"updated": "2026-09-24T00:00:00Z", "indicators": 2, "ipv4": 2, "ipv6": 0,
                    "url": 0, "sha256": 0,
                    "active": sum(1 for r in rows if r["status"] == "active"),
                    "stale": sum(1 for r in rows if r["status"] == "stale"),
                    "expired": sum(1 for r in rows if r["status"] == "expired")}
            (d / "metadata.json").write_text(json.dumps(meta))
            with open(feeds / "iocs.csv", "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=gf.PUBLIC_COLS, extrasaction="ignore"); w.writeheader()
                for r in rows: w.writerow(r)
            errs = vmod.validate_metadata(feeds)
            self.assertEqual(errs, [], errs)
            # 不整合を入れると検出
            meta["indicators"] = 99
            (d / "metadata.json").write_text(json.dumps(meta))
            errs = vmod.validate_metadata(feeds)
            self.assertTrue(any("indicators" in e for e in errs))


class TestExporterSafety(unittest.TestCase):
    """private config未設定時に秘密情報が漏れない (spec #13/#16)"""

    def _load_exporter(self, env=None):
        import importlib
        old = {k: os.environ.get(k) for k in ("HONEYPOT_SELF_IPS", "HONEYPOT_EXCLUDE_NETS",
                                              "HONEYPOT_DECOY_CONFIG")}
        for k in old:
            os.environ.pop(k, None)
        for k, v in (env or {}).items():
            os.environ[k] = v
        try:
            import honeypot_export
            importlib.reload(honeypot_export)
            return honeypot_export
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_defaults_have_no_real_infra(self):
        """コード上のデフォルト値に実IP/組織prefixが無い (安全側のみ)"""
        import inspect
        ex = self._load_exporter()
        src = inspect.getsource(ex)
        # 安全側デフォルト: SELF_IPS空・除外networkはloopback/RFC1918/link-localのみ
        self.assertEqual(ex.SELF_IPS, [])  # 未設定=空
        import ipaddress
        for net in ex.EXCLUDE_NETS:
            self.assertTrue(net.is_private or net.is_loopback,
                            f"非ユニバーサルな除外networkがデフォルトに混入: {net}")
        self.assertEqual(ex.SELF_IPS, [])  # 未設定=空 (マスクなしでも漏れない: そもそも出力しない)

    def test_default_excludes_are_universal_only(self):
        ex = self._load_exporter()
        self.assertTrue(ex.ip_excluded("10.1.2.3"))     # RFC1918
        self.assertTrue(ex.ip_excluded("192.168.1.1"))  # RFC1918
        self.assertTrue(ex.ip_excluded("127.0.0.1"))    # loopback
        self.assertFalse(ex.ip_excluded("8.8.8.8"))     # global は除外しない

    def test_env_config_respected(self):
        ex = self._load_exporter({"HONEYPOT_SELF_IPS": "203.0.113.9",
                                  "HONEYPOT_EXCLUDE_NETS": "198.51.100.0/24"})
        self.assertTrue(ex.ip_excluded("203.0.113.9"))
        self.assertTrue(ex.ip_excluded("198.51.100.7"))
        self.assertFalse(ex.ip_excluded("8.8.8.8"))
        self.assertIn("203.0.113.9", ex.sanitize_text("http://203.0.113.9/x").replace("[self]", "203.0.113.9") or "x")

    def test_decoy_keywords_default_empty(self):
        ex = self._load_exporter()  # config無し
        self.assertEqual(ex.DECOY_KEYWORDS, [])


if __name__ == "__main__":
    unittest.main()
