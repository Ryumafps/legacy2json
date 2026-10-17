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


# ───────────────────────── helpers de fabrication de fichiers ─────────────────────────
def make_dbf(version, memo_len, blocks, codepage=0x01):
    """DBF à 2 champs : NOM (C,10) et MEMO (M). blocks = [(nom, n° de bloc mémo)]"""
    fields = [("NOM", "C", 10), ("MEMO", "M", memo_len)]
    rlen = 1 + sum(f[2] for f in fields)
    hlen = 32 + 32 * len(fields) + 1
    h = bytearray(32)
    h[0] = version
    h[1:4] = bytes([99, 5, 7])
    struct.pack_into("<IHH", h, 4, len(blocks), hlen, rlen)
    h[29] = codepage
    for n, t, l in fields:
        fd = bytearray(32)
        fd[:len(n)] = n.encode()
        fd[11] = ord(t)
        fd[16] = l
        h += fd
    h += b"\r"
    body = b"".join(b" " + nom.ljust(10).encode() +
                    (str(b).rjust(10).encode() if memo_len == 10 else struct.pack("<I", b)) for nom, b in blocks)
    return bytes(h) + body + b"\x1a"


def make_cfb():
    """OLE2 minimal : un flux normal (4096 o) + un mini-flux (50 o)."""
    ss, E, NO = 512, 0xFFFFFFFE, 0xFFFFFFFF
    pad = lambda b: b + b"\0" * (-len(b) % ss)
    fat = [0xFFFFFFFD, E, 3, 4, 5, 6, 7, 8, 9, E, E, E]
    fatb = struct.pack("<%dI" % (ss // 4), *(fat + [NO] * (ss // 4 - len(fat))))

    def ent(name, t, l, r, c, start, size):
        e = bytearray(128)
        nb = name.encode("utf-16-le")
        e[:len(nb)] = nb
        struct.pack_into("<H", e, 64, len(nb) + 2)
        e[66] = t
        struct.pack_into("<III", e, 68, l, r, c)
        struct.pack_into("<I", e, 116, start)
        struct.pack_into("<Q", e, 120, size)
        return bytes(e)

    dirb = pad(ent("Root Entry", 5, NO, NO, 1, 11, 64) + ent("Data", 2, NO, 2, NO, 2, 4096) +
               ent("Small", 2, NO, NO, NO, 0, 50))
    mf = struct.pack("<%dI" % (ss // 4), *([E] + [NO] * (ss // 4 - 1)))
    hdr = bytearray(512)
    hdr[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HH", hdr, 24, 0x3e, 3)
    struct.pack_into("<H", hdr, 28, 0xFFFE)
    struct.pack_into("<HH", hdr, 30, 9, 6)
    struct.pack_into("<8I", hdr, 44, 1, 1, 0, 4096, 10, 1, E, 0)
    struct.pack_into("<109I", hdr, 76, 0, *([NO] * 108))
    return bytes(hdr) + fatb + dirb + bytes(range(256)) * 16 + mf + pad(b"Hello mini stream " * 3)


CAFE = "Café crème".encode("cp437")  # é = 0x82 en cp437 : casse l'ancien décodage latin-1


class TestMemo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_dbf(self, name):
        return legacy2json.analyze((self.dir / name).read_bytes(), source_path=self.dir / name)["data"]

    def test_dbt3_texte_decode_avec_codepage(self):
        dbt = bytearray(512 * 3)
        dbt[512:512 + len(CAFE)] = CAFE
        dbt[512 + len(CAFE)] = 0x1A
        (self.dir / "a.dbf").write_bytes(make_dbf(0x83, 10, [("X", 1)]))
        (self.dir / "a.dbt").write_bytes(bytes(dbt))
        d = self.run_dbf("a.dbf")
        self.assertEqual(d["rows"][0]["MEMO"], "Café crème")
        self.assertIn("succès", d["memo_note"])

    def test_dbt4_en_tete_de_bloc_retire(self):
        dbt = bytearray(512 * 3)
        struct.pack_into("<H", dbt, 20, 512)
        dbt[512:520] = b"\xff\xff\x08\x00" + struct.pack("<I", len(CAFE) + 8)
        dbt[520:520 + len(CAFE)] = CAFE
        (self.dir / "b.dbf").write_bytes(make_dbf(0x8B, 10, [("X", 1)]))
        (self.dir / "b.dbt").write_bytes(bytes(dbt))
        self.assertEqual(self.run_dbf("b.dbf")["rows"][0]["MEMO"], "Café crème")

    def test_fpt_foxpro(self):
        fpt = bytearray(64 * 4)
        struct.pack_into(">H", fpt, 6, 64)
        struct.pack_into(">II", fpt, 128, 1, len(CAFE))
        fpt[136:136 + len(CAFE)] = CAFE
        (self.dir / "c.dbf").write_bytes(make_dbf(0xF5, 4, [("X", 2)]))
        (self.dir / "c.fpt").write_bytes(bytes(fpt))
        self.assertEqual(self.run_dbf("c.dbf")["rows"][0]["MEMO"], "Café crème")

    def test_compagnon_casse_differente(self):
        dbt = bytearray(512 * 2)
        dbt[512:512 + len(CAFE)] = CAFE
        dbt[512 + len(CAFE)] = 0x1A
        (self.dir / "dos.dbf").write_bytes(make_dbf(0x83, 10, [("X", 1)]))
        (self.dir / "DOS.DBT").write_bytes(bytes(dbt))
        self.assertEqual(self.run_dbf("dos.dbf")["rows"][0]["MEMO"], "Café crème")

    def test_memo_absent_garde_le_numero_de_bloc(self):
        (self.dir / "d.dbf").write_bytes(make_dbf(0x83, 10, [("X", 1)]))
        d = self.run_dbf("d.dbf")
        self.assertEqual(d["rows"][0]["MEMO"], {"memo_block": 1})
        self.assertIn("numéro de bloc", d["memo_note"])

    def test_fichier_mémo_tronque_ne_plante_pas(self):
        (self.dir / "e.dbf").write_bytes(make_dbf(0x83, 10, [("X", 99)]))
        (self.dir / "e.dbt").write_bytes(b"\x00" * 100)
        self.assertEqual(self.run_dbf("e.dbf")["rows"][0]["MEMO"], {"memo_block": 99})


class TestParseurs(unittest.TestCase):
    def test_cfb_flux_normal_et_mini_flux(self):
        out = legacy2json.analyze(make_cfb())
        self.assertEqual(out["detected"], "ole2")
        streams = {s["path"]: s for s in out["data"]["streams"]}
        self.assertEqual(streams["Data"]["size"], 4096)
        self.assertTrue(streams["Small"]["content"]["text"].startswith("Hello mini stream"))

    def test_sqlite_lignes_et_blob(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            p = tf.name
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE t(id INT, nom TEXT, b BLOB)")
        con.execute("INSERT INTO t VALUES (1, 'héllo', x'0102')")
        con.commit()
        con.close()
        data = Path(p).read_bytes()
        os.unlink(p)
        row = legacy2json.analyze(data)["data"]["tables"]["t"]["rows"][0]
        self.assertEqual((row["id"], row["nom"]), (1, "héllo"))
        self.assertTrue(row["b"]["_bytes"] if isinstance(row["b"], dict) else isinstance(row["b"], bytes))

    def test_zip_recursif(self):
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.json", '{"x": 1}')
        out = legacy2json.analyze(buf.getvalue())["data"]
        self.assertEqual(out["entries"][0]["content"]["data"]["data"], {"x": 1})

    def test_gzip_recursif(self):
        import gzip
        out = legacy2json.analyze(gzip.compress(b"[1, 2, 3]"))["data"]
        self.assertEqual(out["content"]["data"]["data"], [1, 2, 3])

    def test_enregistrements_fixes_inconnus(self):
        rows = b"".join(b"REC" + struct.pack("<HI", i, i * 1000) + (b"name%03d" % i) + b"\0\0" for i in range(100))
        g = legacy2json.record_guess(b"HDR!" + b"\0" * 12 + rows)
        self.assertEqual(g["best_record_size"], 18)


class TestRobustesse(unittest.TestCase):
    """Promesse du README : ne jamais planter, quelle que soit l'entrée."""

    def test_fichiers_tronques_ou_corrompus(self):
        import json, random
        rnd = random.Random(42)
        seeds = [make_cfb(), make_dbf(0x83, 10, [("X", 1)]), zlib.compress(b"x" * 500), b"PK\x03\x04" + b"\0" * 60,
                 b"SQLite format 3\x00" + b"\xff" * 300]
        for seed in seeds:
            for _ in range(60):
                b = bytearray(seed[:rnd.randrange(len(seed) + 1)])
                for _ in range(rnd.randint(0, 10)):
                    if b:
                        b[rnd.randrange(len(b))] ^= rnd.randrange(1, 256)
                r = legacy2json.analyze(bytes(b))
                self.assertIsInstance(r, dict)
                json.dumps(legacy2json.clean(r))  # doit rester sérialisable


if __name__ == "__main__":
    unittest.main(verbosity=2)
