import os
import sys
import struct
import sqlite3
import zlib
import tempfile
import unittest
from pathlib import Path

# Importer le module principal
sys.path.insert(0, str(Path(__file__).resolve().parent))
import legacy2json


class TestLegacy2Json(unittest.TestCase):

    def setUp(self):
        # Création d'une table DBF synthétique valide
        nrec = 2
        hlen = 32 + 32 * 2 + 1
        rlen = 1 + 10 + 5
        header = struct.pack("<BBBBIHH20x", 0x03, 24, 10, 15, nrec, hlen, rlen)
        f1 = b"NAME\x00\x00\x00\x00\x00\x00\x00" + b"C" + struct.pack("<4xBB14x", 10, 0)
        f2 = b"AGE\x00\x00\x00\x00\x00\x00\x00\x00" + b"N" + struct.pack("<4xBB14x", 5, 0)
        terminator = b"\x0D"
        rec1 = b" " + b"Alice     " + b"   25"
        rec2 = b"*" + b"Bob       " + b"   30"
        eof = b"\x1A"
        self.mini_dbf = header + f1 + f2 + terminator + rec1 + rec2 + eof

        # Création d'un SQLite valide
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            self.sqlite_tmp = tf.name
        con = sqlite3.connect(self.sqlite_tmp)
        cur = con.cursor()
        cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);")
        cur.execute("INSERT INTO users VALUES (1, 'alice');")
        con.commit()
        con.close()
        self.mini_sqlite = Path(self.sqlite_tmp).read_bytes()

    def tearDown(self):
        if hasattr(self, "sqlite_tmp") and os.path.exists(self.sqlite_tmp):
            os.unlink(self.sqlite_tmp)

    # --- Tests de Détection ---

    def test_detect_dbf(self):
        self.assertEqual(legacy2json.detect(self.mini_dbf), "dbf")

    def test_detect_sqlite(self):
        self.assertEqual(legacy2json.detect(self.mini_sqlite), "sqlite3")

    def test_detect_zip(self):
        self.assertEqual(legacy2json.detect(b"PK\x03\x04\x00\x00fakezip"), "zip")

    def test_detect_gzip(self):
        self.assertEqual(legacy2json.detect(b"\x1f\x8b\x08dummygzip"), "gzip")

    def test_detect_ole2(self):
        self.assertEqual(legacy2json.detect(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1dummy"), "ole2")

    def test_detect_text(self):
        self.assertEqual(legacy2json.detect(b"Ceci est du texte clair lisible sans signature."), "text")

    def test_detect_empty(self):
        self.assertEqual(legacy2json.detect(b""), "empty")

    def test_detect_unknown(self):
        self.assertEqual(legacy2json.detect(b"\x00\x01\x02\x03\xfe\xff\x80\x90\xaa\xbb"), "unknown")

    # --- Tests Utilitaires ---

    def test_entropy(self):
        self.assertEqual(legacy2json.entropy(b"A" * 500), 0.0)
        varied = bytes(range(256)) * 4
        self.assertGreater(legacy2json.entropy(varied), 7.0)

    def test_clean_utility(self):
        b_res = legacy2json.clean(b"binary data")
        self.assertTrue(b_res.get("_bytes"))
        self.assertEqual(legacy2json.clean({"k": "v"}), {"k": "v"})

    # --- Tests Parseurs ---

    def test_parse_dbf(self):
        res = legacy2json.parse_dbf(self.mini_dbf, depth=0)
        self.assertEqual(res["declared_records"], 2)
        self.assertEqual(res["deleted_records"], 1)
        self.assertEqual(res["rows"][0]["NAME"], "Alice")
        self.assertEqual(res["rows"][0]["AGE"], 25)
        self.assertTrue(res["rows"][1].get("_deleted"))

    def test_parse_text_json(self):
        res = legacy2json.parse_text('{"status": "ok", "count": 42}', "utf-8")
        self.assertEqual(res["format"], "json")
        self.assertEqual(res["data"]["count"], 42)

    def test_parse_text_csv(self):
        raw = "nom,salaire\nBob,3000\nAlice,3500"
        res = legacy2json.parse_text(raw, "utf-8")
        self.assertEqual(res["format"], "csv")
        self.assertEqual(len(res["data"]), 2)
        self.assertEqual(res["data"][0]["nom"], "Bob")

    def test_parse_text_ini(self):
        raw = "[server]\nhost=127.0.0.1\nport=8080"
        res = legacy2json.parse_text(raw, "utf-8")
        self.assertEqual(res["format"], "ini")
        self.assertEqual(res["data"]["server"]["port"], "8080")

    # --- Tests Heuristiques ---

    def test_xor_scan(self):
        clear = b"Confidence is key when decrypting legacy files and restoring vintage databases." * 4
        key = 0x88
        encrypted = bytes(b ^ key for b in clear)
        guesses = legacy2json.xor_scan(encrypted)
        self.assertGreater(len(guesses), 0)
        self.assertTrue(any(g["key"] == key and g["mode"] == "xor" for g in guesses))

    def test_try_decompress_hidden_zlib(self):
        data = b"Internal hidden compressed log file content." * 8
        compressed = zlib.compress(data)
        container = b"CUSTOM_PREAMBLE_1234" + compressed + b"TAIL"
        decompressed = legacy2json.try_decompress(container, depth=0)
        self.assertGreater(len(decompressed), 0)
        self.assertTrue(any(item["method"] == "zlib" for item in decompressed))

    # --- Test Intégration globale ---

    def test_analyze_pipeline(self):
        out = legacy2json.analyze(self.mini_dbf)
        self.assertEqual(out["detected"], "dbf")
        self.assertIn("data", out)
        self.assertEqual(len(out["data"]["rows"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
