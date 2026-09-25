#!/usr/bin/env python3
"""test_enrich.py - enrichment系のmockテスト (外部APIは叩かない)"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import enrich


def ok_cymru(ips):
    return {ip: {"asn": "197170", "as_name": "DIICOT-TEST", "country": "RO"} for ip in ips}


class TestCymru(unittest.TestCase):
    def test_success(self):
        got = enrich.cymru_bulk(["1.2.3.4"], fetch=ok_cymru)
        self.assertEqual(got["1.2.3.4"]["asn"], "197170")
        self.assertEqual(got["1.2.3.4"]["country"], "RO")

    def test_timeout_returns_empty_and_keeps_going(self):
        def boom(ips):
            raise OSError("simulated timeout")
        got = enrich.cymru_bulk(["1.2.3.4"], fetch=boom)
        self.assertEqual(got, {})   # fail-open: 空を返し、呼び出し側はcacheを保持

    def test_rate_limit_returns_empty(self):
        def limited(ips):
            raise OSError("rate limited")
        self.assertEqual(enrich.cymru_bulk(["1.1.1.1"], fetch=limited), {})


class TestTI(unittest.TestCase):
    def test_no_api_key_skips(self):
        # VIRUSTOTAL_API_KEY等が無い環境ではNoneを返し、sourcesに入らない
        self.assertIsNone(enrich.ti_check_virustotal("1.2.3.4", "ip"))
        self.assertIsNone(enrich.ti_check_greynoise("1.2.3.4"))
        self.assertIsNone(enrich.ti_check_abuseipdb("1.2.3.4"))

    def test_urlhaus_malicious_and_error(self):
        orig = enrich._http_json
        try:
            enrich._http_json = lambda u, data=None, headers=None: {"query_status": "found"}
            self.assertIs(enrich.ti_check_urlhaus("http://x/", ), True)
            enrich._http_json = lambda u, data=None, headers=None: {"query_status": "no_result"}
            self.assertIs(enrich.ti_check_urlhaus("http://x/"), False)
            def err(u, data=None, headers=None):
                raise OSError("timeout")
            enrich._http_json = err
            self.assertIsNone(enrich.ti_check_urlhaus("http://x/"))
        finally:
            enrich._http_json = orig

    def test_malwarebazaar_family(self):
        orig = enrich._http_json
        try:
            enrich._http_json = lambda u, data=None, headers=None: {
                "query_status": "ok", "data": [{"signature": "XMRig"}]}
            self.assertEqual(enrich.ti_check_malwarebazaar("a" * 64), "XMRig")
        finally:
            enrich._http_json = orig

    def test_run_ti_cache_hit(self):
        cache = {"9.9.9.9": {"sources": ["abuseipdb"], "malicious": 1, "family": None,
                             "expires": "2999-01-01T00:00:00Z", "checked": "2026-01-01T00:00:00Z"}}
        res = enrich.run_ti("9.9.9.9", "ip", cache)   # fetch不要 (cache hit)
        self.assertEqual(res["sources"], ["abuseipdb"])
        self.assertEqual(res["malicious"], 1)


class TestEnrichPreserves(unittest.TestCase):
    def test_failure_keeps_existing_fields(self):
        """ASN全滅時でも既存cache値を保持する (in-process, 通信無し)"""
        rows = [{"indicator": "5.5.5.5", "type": "ip"}]
        cache = {"5.5.5.5": {"asn": "12345", "as_name": "OLD", "country": "DE",
                            "checked": "2000-01-01T00:00:00Z"}}   # TTL切れ
        fail = enrich.apply_asn(rows, cache, got={}, now_iso="2026-09-24T00:00:00Z")
        self.assertEqual(rows[0]["asn"], "12345")   # 旧値保持!
        self.assertEqual(rows[0]["country"], "DE")
        self.assertEqual(rows[0]["as_name"], "OLD")
        # 新規取得は上書きされる
        ok = enrich.apply_asn(rows, cache, got={"5.5.5.5": {"asn": "42", "as_name": "NEW", "country": "XX"}},
                              now_iso="2026-09-24T00:00:00Z")
        self.assertEqual(rows[0]["asn"], "42")
        self.assertEqual(rows[0]["country"], "XX")
        # cache未搭載のIPは空欄のまま壊れない
        rows2 = [{"indicator": "6.6.6.6", "type": "ip"}]
        enrich.apply_asn(rows2, cache, got={}, now_iso="x")
        self.assertEqual(rows2[0]["asn"], "")


if __name__ == "__main__":
    unittest.main()
