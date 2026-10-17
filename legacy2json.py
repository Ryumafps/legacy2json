#!/usr/bin/env python3
"""
legacy2json - récupère les données de fichiers de formats anciens/fermés et les écrit en JSON.

Principe : 1) identifier le format (signatures + validation structurelle, pas l'extension)
          2) parser les formats connus (DBF, SQLite, OLE2/CFB, ZIP, gzip/bz2/xz, plist,
             JSON/XML/INI/CSV/clé=valeur, Access via mdbtools si installé)
          3) sinon : analyse heuristique (chaînes ASCII/UTF-16, flux zlib/deflate cachés,
             XOR/ADD mono-octet, taille d'enregistrement fixe, signatures embarquées)
Garanties : ne plante jamais, lecture seule, aucune donnée perdue (--embed-raw ajoute le fichier brut
en base64 dans le JSON). Impossible de garantir le décodage de TOUT format inconnu : dans ce cas
la sortie contient tout ce qui est récupérable + les indices pour écrire un parseur dédié.

Usage :
  python legacy2json.py fichier.xyz                 # JSON sur stdout
  python legacy2json.py fichier.xyz -o sortie.json
  python legacy2json.py dossier/ -o sortie_dir/     # récursif
  Options : --full (aucune limite de lignes/blobs)  --embed-raw (fichier brut en base64)
"""
import argparse, base64, bz2, collections, configparser, csv, datetime as dt, hashlib, io
import json, logging, lzma, math, os, plistlib, re, shutil, sqlite3, struct, subprocess, sys
import tempfile, traceback, zipfile, zlib
import xml.etree.ElementTree as ET
from pathlib import Path

log = logging.getLogger("legacy2json")

LIM = dict(rows=1000, blob=256, strings=300, depth=3, preview=4000,
           maxout=256 * 2**20, scan=64 * 2**20, member=25 * 2**20)
PRINT = bytes(range(32, 127)) + b"\t\n\r"


# ───────────────────────── utilitaires ─────────────────────────
def b64(b):
    b = bytes(b)
    return {"_bytes": True, "size": len(b), "base64": base64.b64encode(b[:LIM["blob"]]).decode(),
            "truncated": len(b) > LIM["blob"]}


def clean(o):
    if isinstance(o, (bytes, bytearray)):
        return b64(o)
    if isinstance(o, (dt.datetime, dt.date, dt.time)):
        return o.isoformat()
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [clean(v) for v in o]
    if isinstance(o, float) and (math.isnan(o) or math.isinf(o)):
        return str(o)
    return o


def pr(s):
    """part d'octets imprimables"""
    return 0.0 if not s else 1 - len(s.translate(None, PRINT)) / len(s)


def entropy(d):
    if not d:
        return 0.0
    c, n = collections.Counter(d), len(d)
    return round(-sum(v / n * math.log2(v / n) for v in c.values()), 3)


def text_ok(t):
    if not t:
        return False
    s = t[:20000]
    return sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t") / len(s) >= 0.97


def decode_text(d):
    if not d:
        return None
    if d.startswith(b"\xef\xbb\xbf"):
        cands = ["utf-8-sig"]
    elif d.startswith((b"\xff\xfe", b"\xfe\xff")):
        cands = ["utf-16"]
    else:
        cands = ["utf-8"]
    for e in cands:
        try:
            t = d.decode(e)
        except Exception:
            continue
        if text_ok(t):
            return t, e
    if b"\x00" not in d[:4096] and pr(d[:20000]) >= 0.85:
        t = d.decode("cp1252", "replace")
        if text_ok(t):
            return t, "cp1252"
    return None


def describe(b):
    """résumé sûr d'un blob quelconque"""
    out = {"size": len(b)}
    t = decode_text(b) if len(b) <= 2 * 2**20 else None
    if t:
        out.update(text=t[0][:LIM["preview"]], encoding=t[1], truncated=len(t[0]) > LIM["preview"])
    else:
        out.update(b64(b))
        st = find_strings(b[:2**20], quick=True)
        if st:
            out["strings"] = st
    return out


def find_strings(d, quick=False):
    if quick:
        return [m.group().decode("ascii")[:120] for _, m in zip(range(10), re.finditer(rb"[\x20-\x7e]{6,}", d))]
    d = d[:LIM["scan"]]
    res = {}
    for key, rx, dec in (("ascii", rb"[\x20-\x7e]{4,}", "ascii"),
                         ("utf16le", rb"(?:[\x20-\x7e]\x00){4,}", "utf-16-le")):
        items, total = [], 0
        for m in re.finditer(rx, d):
            total += 1
            if len(items) < LIM["strings"]:
                items.append({"offset": m.start(), "text": m.group().decode(dec)[:200]})
        res[key] = {"total": total, "shown": items}
    return res


SIGS = {b"SQLite format 3\x00": "sqlite3", b"PK\x03\x04": "zip", b"\x89PNG\r\n\x1a\n": "png",
        b"\xff\xd8\xff": "jpeg", b"GIF89a": "gif", b"GIF87a": "gif", b"%PDF-": "pdf",
        b"\x1f\x8b\x08": "gzip", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "ole2", b"{\\rtf": "rtf",
        b"<?xml": "xml", b"bplist00": "bplist", b"7z\xbc\xaf\x27\x1c": "7z", b"Rar!": "rar",
        b"\xfd7zXZ\x00": "xz"}


def find_sigs(d):
    out = []
    for sig, name in SIGS.items():
        pos, n = d.find(sig, 1), 0
        while pos != -1 and n < 20:
            out.append({"offset": pos, "type": name})
            n += 1
            pos = d.find(sig, pos + 1)
    return sorted(out, key=lambda x: x["offset"])[:100]


# ───────────────────────── détection ─────────────────────────
MAGIC = [(b"SQLite format 3\x00", "sqlite3"), (b"** This file contains an SQLite", "sqlite2"),
         (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
         (b"\xfd7zXZ\x00", "xz"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
         (b"bplist00", "bplist"), (b"%PDF-", "pdf"), (b"{\\rtf", "rtf"), (b"\x89PNG\r\n\x1a\n", "png"),
         (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!", "rar")]


def is_dbf(d):
    if len(d) < 33 or d[0] not in (0x02, 0x03, 0x04, 0x05, 0x30, 0x31, 0x32, 0x43, 0x63, 0x83, 0x8B, 0xCB, 0xF5, 0xFB):
        return False
    nrec, hlen, rlen = struct.unpack_from("<IHH", d, 4)
    if hlen < 33 or rlen < 2 or hlen > len(d):
        return False
    pos, total, n = 32, 1, 0
    while pos < hlen and pos + 32 <= len(d) and d[pos] != 0x0D:
        total += d[pos + 16]
        pos += 32
        n += 1
    return n > 0 and pos < hlen and d[pos] == 0x0D and total == rlen


def detect(d):
    if not d:
        return "empty"
    for m, k in MAGIC:
        if d.startswith(m):
            return k
    if d[:4] == b"\x00\x01\x00\x00" and d[4:16] in (b"Standard Jet", b"Standard ACE"):
        return "access"
    if is_dbf(d):
        return "dbf"
    return "text" if decode_text(d) else "unknown"


# ───────────────────────── support mémo DBF (.dbt / .fpt) ─────────────────────────
def _find_companion(dbf_path):
    """Cherche <nom>.dbt / <nom>.fpt sans tenir compte de la casse (DOS : CLIENTS.DBT à côté de clients.dbf)."""
    p = Path(dbf_path)
    try:
        siblings = list(p.parent.iterdir())
    except OSError:
        return None
    for ext in (".dbt", ".fpt"):
        for f in siblings:
            if f.suffix.lower() == ext and f.stem.lower() == p.stem.lower() and f.is_file():
                return f
    return None


def _load_memo(dbf_path, enc="cp1252"):
    """Renvoie get_memo(block) -> str | bytes | None, ou None si aucun fichier mémo compagnon.
    Le texte est décodé avec la page de code du DBF (enc), pas en latin-1."""
    if dbf_path is None:
        return None
    mp = _find_companion(dbf_path)
    if mp is None:
        return None
    try:
        md = mp.read_bytes()
    except Exception as e:
        log.warning("fichier mémo illisible %s : %s", mp, e)
        return None
    if mp.suffix.lower() == ".fpt":
        # FoxPro : taille de bloc à l'offset 6 (big-endian), chaque mémo = type(4) + longueur(4) + données
        bs = struct.unpack_from(">H", md, 6)[0] if len(md) >= 8 else 64
        bs = bs or 64

        def get_memo(block):
            off = block * bs
            if block <= 0 or off + 8 > len(md):
                return None
            mtype, mlen = struct.unpack_from(">II", md, off)
            data = md[off + 8: off + 8 + mlen]
            return data.decode(enc, "replace") if mtype == 1 else data  # 1 = texte, sinon binaire
        log.debug("mémo FoxPro chargé : %s (bloc=%d octets)", mp, bs)
        return get_memo
    # dBase .dbt : taille de bloc en en-tête (offset 20) pour dBase IV, 512 pour dBase III
    bs = struct.unpack_from("<H", md, 20)[0] if len(md) >= 22 else 0
    bs = bs if 0 < bs <= 32768 else 512

    def get_memo(block):
        off = block * bs
        if block <= 0 or off >= len(md):
            return None
        if md[off:off + 4] == b"\xff\xff\x08\x00" and off + 8 <= len(md):  # dBase IV : en-tête de 8 octets
            mlen = struct.unpack_from("<I", md, off + 4)[0]
            data = md[off + 8: off + max(mlen, 8)].rstrip(b"\x00\x1a")
        else:  # dBase III : texte terminé par 0x1A
            end = md.find(b"\x1a", off)
            data = md[off: len(md) if end == -1 else end]
        return data.decode(enc, "replace")
    log.debug("mémo dBase chargé : %s (bloc=%d octets)", mp, bs)
    return get_memo


# ───────────────────────── parseurs ─────────────────────────
def parse_dbf(d, depth, source_path=None):
    nrec, hlen, rlen = struct.unpack_from("<IHH", d, 4)
    enc = {0x01: "cp437", 0x02: "cp850", 0x03: "cp1252", 0x57: "cp1252", 0x58: "cp1252", 0x59: "cp1252",
           0x64: "cp852", 0x65: "cp866", 0xC8: "cp1250", 0xC9: "cp1251", 0xCA: "cp1254", 0xCB: "cp1253"}.get(d[29], "cp1252")
    get_memo = _load_memo(source_path, enc)
    fields, pos = [], 32
    while pos + 32 <= len(d) and d[pos] != 0x0D:
        fields.append((d[pos:pos + 11].split(b"\0")[0].decode("ascii", "replace"),
                       chr(d[pos + 11]), d[pos + 16], d[pos + 17]))
        pos += 32
    avail = (len(d) - hlen) // rlen
    n = avail if (nrec == 0 or nrec > avail) else nrec
    rows, deleted = [], 0
    for i in range(n):
        rec = d[hlen + i * rlen: hlen + (i + 1) * rlen]
        if rec[:1] == b"*":
            deleted += 1
        if len(rows) >= LIM["rows"]:
            continue
        row, off = {}, 1
        for name, t, ln, dec in fields:
            if name != "_NullFlags":
                row[name] = dbf_val(t, rec[off:off + ln], enc, get_memo)
            off += ln
        if rec[:1] == b"*":
            row["_deleted"] = True
        rows.append(row)
    y = d[1] + (2000 if d[1] < 80 else 1900)
    has_memo_fields = any(f[1] in "MGP" for f in fields)
    memo_note = None
    if has_memo_fields and not get_memo:
        memo_note = "champs mémo : numéro de bloc seulement (fichier .dbt/.fpt séparé)"
    elif has_memo_fields and get_memo:
        memo_note = "fichier mémo chargé avec succès"
    return {"version_byte": hex(d[0]), "last_update": f"{y}-{d[2]:02d}-{d[3]:02d}", "encoding": enc,
            "declared_records": nrec, "records_found": n, "deleted_records": deleted,
            "memo_note": memo_note,
            "fields": [{"name": a, "type": b, "length": c, "decimals": e} for a, b, c, e in fields],
            "rows": rows, "rows_truncated": n > len(rows)}


def dbf_val(t, raw, enc, get_memo=None):
    if t == "C":
        return raw.decode(enc, "replace").rstrip(" \x00")
    if t in "NF":
        s = raw.decode("ascii", "replace").strip().rstrip("\x00").strip()
        if not s or set(s) <= set("*?"):
            return None
        try:
            return float(s) if ("." in s or "e" in s.lower()) else int(s)
        except ValueError:
            return s
    if t == "D":
        s = raw.decode("ascii", "replace").strip()
        return f"{s[:4]}-{s[4:6]}-{s[6:8]}" if len(s) == 8 and s.isdigit() else (s or None)
    if t == "L":
        c = raw[:1].decode("ascii", "replace").upper()
        return True if c and c in "YT" else False if c and c in "NF" else None
    if t == "I" and len(raw) == 4:
        return struct.unpack("<i", raw)[0]
    if t in "BO" and len(raw) == 8:
        return struct.unpack("<d", raw)[0]
    if t == "Y" and len(raw) == 8:
        return struct.unpack("<q", raw)[0] / 10000
    if t == "T" and len(raw) == 8:
        day, ms = struct.unpack("<ii", raw)
        if day == 0:
            return None
        try:
            return (dt.datetime.fromordinal(day - 1721425) + dt.timedelta(milliseconds=ms)).isoformat()
        except Exception:
            return {"julian_day": day, "ms": ms}
    if t in "MGP":
        if len(raw) == 4:
            block = struct.unpack("<I", raw)[0]
        else:
            s = raw.decode("ascii", "replace").strip()
            block = int(s) if s.isdigit() else 0
        if block and get_memo:
            content = get_memo(block)
            if content is not None:
                return content if isinstance(content, str) else b64(content)
        return {"memo_block": block} if block else None
    return raw


def parse_sqlite(d, depth):
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        f.write(d)
        p = f.name
    try:
        con = sqlite3.connect(Path(p).as_uri() + "?mode=ro", uri=True)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        tables, others = {}, []
        for typ, name, sql in con.execute("select type,name,sql from sqlite_master").fetchall():
            if typ != "table":
                others.append({"type": typ, "name": name, "sql": sql})
                continue
            q = '"' + name.replace('"', '""') + '"'
            try:
                cols = [r[1] for r in con.execute(f"pragma table_info({q})")]
                total = con.execute(f"select count(*) from {q}").fetchone()[0]
                cur = con.execute(f"select * from {q} limit {LIM['rows']}")
                tables[name] = {"sql": sql, "columns": cols, "row_count": total,
                                "rows": [dict(zip(cols, r)) for r in cur], "rows_truncated": total > LIM["rows"]}
            except Exception as e:
                tables[name] = {"sql": sql, "error": f"{type(e).__name__}: {e}"}
        con.close()
        return {"tables": tables, "other_objects": others}
    finally:
        os.unlink(p)


def parse_cfb(d, depth):
    """Conteneur OLE2 : .doc .xls .ppt .msg .wps .db anciens, installeurs, etc."""
    if len(d) < 512:
        raise ValueError("trop court")
    ss, mss = 1 << struct.unpack_from("<H", d, 30)[0], 1 << struct.unpack_from("<H", d, 32)[0]
    if not (128 <= ss <= 65536 and 16 <= mss <= ss):
        raise ValueError("tailles de secteur invalides")
    nfat, dir0, _, cutoff, mf0, nmf, dif0, ndif = struct.unpack_from("<8I", d, 44)
    END = 0xFFFFFFFA

    def sec(i):
        o = (i + 1) * ss
        c = d[o:o + ss] if o < len(d) else b""
        return c + b"\x00" * (ss - len(c))

    difat = list(struct.unpack_from("<109I", d, 76))
    s, seen = dif0, set()
    for _ in range(ndif):
        if s >= END or s in seen:
            break
        seen.add(s)
        vals = struct.unpack("<%dI" % (ss // 4), sec(s))
        difat += vals[:-1]
        s = vals[-1]
    fat = []
    for s in [x for x in difat if x < END][:nfat]:
        fat += struct.unpack("<%dI" % (ss // 4), sec(s))

    def chain(start, table):
        out, seen, s = [], set(), start
        while s < END and s not in seen and s < len(table):
            seen.add(s)
            out.append(s)
            s = table[s]
        return out

    def read(start, size=None):
        b = b"".join(sec(s) for s in chain(start, fat))
        return b if size is None else b[:size]

    dirb = read(dir0)
    ents = []
    for i in range(len(dirb) // 128):
        e = dirb[i * 128:(i + 1) * 128]
        nl = struct.unpack_from("<H", e, 64)[0]
        left, right, child = struct.unpack_from("<III", e, 68)
        size = struct.unpack_from("<Q", e, 120)[0]
        if ss == 512:
            size &= 0xFFFFFFFF
        ents.append(dict(name=e[:max(0, min(nl, 64) - 2)].decode("utf-16-le", "replace"), type=e[66],
                         left=left, right=right, child=child, start=struct.unpack_from("<I", e, 116)[0], size=size))
    if not ents:
        raise ValueError("répertoire vide")
    mini = read(ents[0]["start"], ents[0]["size"])
    minifat = []
    for s in chain(mf0, fat):
        minifat += struct.unpack("<%dI" % (ss // 4), sec(s))

    def read_mini(start, size):
        return b"".join(mini[s * mss:(s + 1) * mss] for s in chain(start, minifat))[:size]

    found, seen = [], set()

    def walk(idx, prefix):
        stack = [idx]
        while stack:
            i = stack.pop()
            if i >= len(ents) or i in seen:
                continue
            seen.add(i)
            e = ents[i]
            stack += [e["left"], e["right"]]
            path = prefix + e["name"]
            found.append((path, e))
            if e["type"] == 1:
                walk(e["child"], path + "/")

    walk(ents[0]["child"], "")
    vis = lambda p: re.sub(r"[\x00-\x1f]", lambda m: "\\x%02x" % ord(m.group()), p)
    streams = []
    for path, e in found:
        if e["type"] != 2:
            continue
        data = read_mini(e["start"], e["size"]) if e["size"] < cutoff else read(e["start"], e["size"])
        streams.append({"path": vis(path), "size": e["size"], "content": describe(data)})
    names = {s["path"] for s in streams}
    likely = ("Word 97-2003 (.doc)" if "WordDocument" in names else
              "Excel 97-2003 (.xls)" if names & {"Workbook", "Book"} else
              "PowerPoint 97-2003 (.ppt)" if "PowerPoint Document" in names else
              "Outlook .msg" if any(n.startswith("__substg1.0_") for n in names) else None)
    return {"likely_application": likely, "storages": [vis(p) for p, e in found if e["type"] == 1],
            "streams": streams}


def decompress(kind, d):
    lim = LIM["maxout"]
    if kind == "gzip":
        o = zlib.decompressobj(31)
        return o.decompress(d, lim)
    if kind == "bzip2":
        return bz2.BZ2Decompressor().decompress(d, lim)
    return lzma.LZMADecompressor().decompress(d, max_length=lim)


def parse_compressed(d, depth, kind):
    data = decompress(kind, d)
    return {"method": kind, "decompressed_size": len(data), "content": nested(data, depth)}


def nested(data, depth):
    if depth >= LIM["depth"]:
        return describe(data)
    return analyze(data, depth + 1)


def parse_zip(d, depth):
    z = zipfile.ZipFile(io.BytesIO(d))
    names = z.namelist()
    kind = ("docx" if "word/document.xml" in names else "xlsx" if "xl/workbook.xml" in names else
            "pptx" if "ppt/presentation.xml" in names else "odf" if "mimetype" in names else
            "jar/apk" if "META-INF/MANIFEST.MF" in names else "epub" if "META-INF/container.xml" in names else "zip")
    entries = []
    for i in z.infolist()[:2000]:
        e = {"name": i.filename, "size": i.file_size, "compressed": i.compress_size,
             "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % i.date_time, "encrypted": bool(i.flag_bits & 1)}
        if not i.is_dir() and not e["encrypted"] and i.file_size <= LIM["member"]:
            try:
                e["content"] = nested(z.read(i), depth)
            except Exception as ex:
                e["error"] = f"{type(ex).__name__}: {ex}"
        entries.append(e)
    return {"zip_kind": kind, "entries": entries}


def parse_plist(d, depth):
    return plistlib.loads(d)


def parse_access(d, depth):
    ver = {0: "Jet3 (Access 97)", 1: "Jet4 (Access 2000-2003)", 2: "ACE12 (Access 2007)", 3: "ACE14 (Access 2010+)"}
    if not shutil.which("mdb-tables"):
        raise RuntimeError("Access détecté (%s) mais mdbtools absent : installe-le (apt install mdbtools / brew install mdbtools) "
                           "puis relance, le script l'utilisera automatiquement" % ver.get(d[0x14], "?"))
    with tempfile.NamedTemporaryFile(suffix=".mdb", delete=False) as f:
        f.write(d)
        p = f.name
    try:
        names = subprocess.run(["mdb-tables", "-1", p], capture_output=True, text=True, timeout=120).stdout.splitlines()
        tables = {}
        for n in names:
            if not n.strip():
                continue
            out = subprocess.run(["mdb-export", p, n], capture_output=True, text=True, timeout=300).stdout
            rows = list(csv.DictReader(io.StringIO(out)))
            tables[n] = {"row_count": len(rows), "rows": rows[:LIM["rows"]], "rows_truncated": len(rows) > LIM["rows"]}
        return {"engine": ver.get(d[0x14], "?"), "tables": tables}
    finally:
        os.unlink(p)


def xml2d(e):
    d = {}
    if e.attrib:
        d["@attrs"] = dict(e.attrib)
    for k in e:
        d.setdefault(k.tag, []).append(xml2d(k))
    txt = (e.text or "").strip()
    if txt:
        if not d:
            return txt
        d["#text"] = txt
    return d if d else ""


def parse_text(t, enc):
    s = t.strip()
    if s[:1] in ("{", "["):
        try:
            return {"format": "json", "encoding": enc, "data": json.loads(s)}
        except Exception:
            pass
    if s.startswith("<"):
        try:
            root = ET.fromstring(s.encode("utf-8"))
            return {"format": "xml", "encoding": enc, "data": {root.tag: xml2d(root)}}
        except Exception:
            pass
    if re.search(r"^\s*\[[^\]\r\n]+\]\s*$", t, re.M):
        try:
            cp = configparser.ConfigParser(strict=False, interpolation=None)
            cp.optionxform = str
            cp.read_string(t if re.match(r"\s*\[", t) else "[DEFAULT_TOP]\n" + t)
            return {"format": "ini", "encoding": enc, "data": {k: dict(cp[k]) for k in cp.sections()}}
        except Exception:
            pass
    lines = [l for l in t.splitlines() if l.strip()]
    if len(lines) >= 2:
        try:
            dia = csv.Sniffer().sniff("\n".join(lines[:50]), delimiters=",;\t|")
            rows = list(csv.reader(lines, dia))
            wid = collections.Counter(len(r) for r in rows)
            w, c = wid.most_common(1)[0]
            if w >= 2 and c / len(rows) >= 0.9:
                hdr = csv.Sniffer().has_header("\n".join(lines[:50]))
                data = [dict(zip(rows[0], r)) for r in rows[1:]] if hdr else rows
                return {"format": "csv", "encoding": enc, "delimiter": dia.delimiter, "header": hdr,
                        "data": data[:LIM["rows"]], "truncated": len(data) > LIM["rows"]}
        except Exception:
            pass
    kv = [re.match(r"^\s*([\w.\-\[\] ]+?)\s*[=:]\s*(.*)$", l) for l in lines if not l.lstrip().startswith(("#", ";", "//"))]
    if kv and all(kv) and len(kv) >= 2:
        return {"format": "key-value", "encoding": enc, "data": [{"key": m.group(1), "value": m.group(2)} for m in kv]}
    return {"format": "plain-text", "encoding": enc, "lines": len(lines), "data": t[:LIM["preview"] * 10],
            "truncated": len(t) > LIM["preview"] * 10}


PARSERS = {"dbf": parse_dbf, "sqlite3": parse_sqlite, "ole2": parse_cfb, "zip": parse_zip,
           "bplist": parse_plist, "access": parse_access,
           "gzip": lambda d, n: parse_compressed(d, n, "gzip"),
           "bzip2": lambda d, n: parse_compressed(d, n, "bzip2"),
           "xz": lambda d, n: parse_compressed(d, n, "xz")}
# Pour ajouter un format : écrire parse_xxx(d, depth) -> dict, l'ajouter ici + une signature dans MAGIC/detect().


# ───────────────────────── analyse heuristique (formats inconnus) ─────────────────────────
def try_decompress(d, depth):
    out, lim = [], LIM["maxout"]

    def add(off, method, data):
        item = {"offset": off, "method": method, "size": len(data)}
        item["result" if depth < LIM["depth"] else "preview"] = nested(data, depth) if depth < LIM["depth"] else describe(data)
        out.append(item)

    def good(o, data):
        return len(data) >= 4 and (o.eof or len(data) >= 64)

    for name, w in (("zlib", 15), ("deflate-raw", -15), ("gzip", 31)):
        try:
            o = zlib.decompressobj(w)
            data = o.decompress(d, lim)
            if good(o, data) and (w != -15 or o.eof):
                add(0, name, data)
        except Exception:
            pass
    for name, mk in (("bzip2", bz2.BZ2Decompressor), ("lzma", lzma.LZMADecompressor)):
        try:
            o = mk()
            data = o.decompress(d, lim) if name == "bzip2" else o.decompress(d, max_length=lim)
            if o.eof and data:
                add(0, name, data)
        except Exception:
            pass
    mv, covered, tries = memoryview(d[:LIM["scan"]]), 0, 0
    for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", mv):
        if m.start() < max(covered, 1) or tries > 300 or len(out) > 50:
            continue
        tries += 1
        try:
            o = zlib.decompressobj(15)
            data = o.decompress(mv[m.start():], lim)
            if good(o, data):
                add(m.start(), "zlib", data)
                if o.eof:
                    covered = len(mv) - len(o.unused_data)
        except Exception:
            pass
    return out


def textiness(s):
    """part d'octets lettres/chiffres/espace/retour ligne : départage les clés voisines"""
    return 1 - len(s.translate(None, b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n\r\t.,;:'-_/()")) / len(s)


def xor_scan(d):
    s = d[:65536]
    if len(s) < 32 or len(set(s)) < 8:
        return []
    base, res = textiness(s), []
    for k in range(1, 256):
        for mode, tbl in (("xor", bytes(i ^ k for i in range(256))), ("add", bytes((i + k) & 255 for i in range(256)))):
            t = s.translate(tbl)
            r = textiness(t)
            if pr(t) > 0.9 and r > 0.7 and r > base + 0.3:
                res.append((r, mode, k, tbl))
    res.sort(key=lambda x: -x[0])
    return [{"mode": m, "key": k, "text_ratio": round(r, 3),
             "sample": d[:300].translate(t).decode("latin-1")} for r, m, k, t in res[:3]]


def record_guess(d):
    s = d[:20000]
    n = len(s)
    if n < 64:
        return None
    cnt = collections.Counter(s)
    base = sum((v / n) ** 2 for b, v in cnt.items() if b)
    scores = []
    for sz in range(2, min(1024, n // 4)):
        a, b = s[:-sz], s[sz:]
        A, B = int.from_bytes(a, "big"), int.from_bytes(b, "big")
        eq = (A ^ B).to_bytes(len(a), "big").count(0) - (A | B).to_bytes(len(a), "big").count(0)
        scores.append((eq / len(a), sz))
    mx = max(scores)[0]
    if mx < base + 0.1:
        return None
    best = min(sz for sc, sz in scores if sc >= 0.97 * mx)
    recs = [s[i:i + best] for i in range(0, n - best + 1, best)][:200]
    cols, run = [], None
    for c in range(best):
        kind = "constant" if len({r[c] for r in recs}) == 1 else "variable"
        if run and run["kind"] == kind:
            run["to"] = c
        else:
            run = {"from": c, "to": c, "kind": kind}
            cols.append(run)
    return {"note": "heuristique : taille d'enregistrement fixe probable (décalage d'en-tête inconnu)",
            "candidates": [{"size": sz, "score": round(sc, 3)} for sc, sz in sorted(scores, reverse=True)[:5]],
            "best_record_size": best, "column_layout": cols[:80],
            "first_records_hex": [r.hex() for r in recs[:10]]}


def generic(d, depth):
    g = {"header_hex": d[:64].hex(" "), "printable_ratio": round(pr(d[:65536]), 3),
         "first_u32_le": list(struct.unpack_from("<%dI" % min(8, len(d) // 4), d, 0)) if len(d) >= 4 else [],
         "strings": find_strings(d), "embedded_signatures": find_sigs(d[:LIM["scan"]])}
    for key, fn in (("hidden_compressed_streams", lambda: try_decompress(d, depth)),
                    ("single_byte_obfuscation", lambda: xor_scan(d)),
                    ("fixed_record_structure", lambda: record_guess(d))):
        try:
            v = fn()
            if v:
                g[key] = v
        except Exception as e:
            g[key + "_error"] = f"{type(e).__name__}: {e}"
    return g


# ───────────────────────── orchestration ─────────────────────────
def analyze(d, depth=0, source_path=None):
    res = {"size": len(d), "sha256": hashlib.sha256(d).hexdigest(), "entropy": entropy(d[:2**20])}
    kind = detect(d)
    res["detected"] = kind
    log.debug("format détecté : %s (taille=%d)", kind, len(d))
    warn, parsed = [], None
    if kind in PARSERS:
        try:
            if kind == "dbf" and source_path:
                parsed = parse_dbf(d, depth, source_path=source_path)
            else:
                parsed = PARSERS[kind](d, depth)
        except Exception as e:
            warn.append(f"{kind}: {type(e).__name__}: {e}")
            log.warning("erreur parseur %s : %s", kind, e)
    elif kind == "text":
        t = decode_text(d)
        try:
            parsed = parse_text(*t)
        except Exception as e:
            warn.append(f"text: {type(e).__name__}: {e}")
    elif kind in ("sqlite2", "pdf", "rtf", "png", "jpeg", "gif", "7z", "rar"):
        warn.append(f"{kind}: format reconnu mais sans parseur intégré (voir 'analysis' pour ce qui est récupérable)")
    if parsed is not None:
        res["data"] = parsed
    elif kind != "empty":
        try:
            res["analysis"] = generic(d, depth)
        except Exception as e:
            warn.append(f"analysis: {type(e).__name__}: {e}")
    if warn:
        res["warnings"] = warn
    return res


def process_file(path, embed_raw=False):
    p = Path(path)
    try:
        d = p.read_bytes()
        r = {"file": str(path), **analyze(d, source_path=p)}
        if embed_raw:
            r["raw_base64"] = base64.b64encode(d).decode()
    except Exception as e:
        r = {"file": str(path), "error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc(limit=3)}
    return r


def main():
    ap = argparse.ArgumentParser(description="Convertit des fichiers de formats legacy en JSON.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-o", "--out", help="fichier .json (1 entrée) ou dossier de sortie")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="niveau de verbosité (-v ou -vv)")
    ap.add_argument("--full", action="store_true", help="aucune limite de lignes/blobs/chaînes")
    ap.add_argument("--embed-raw", action="store_true", help="inclut le fichier brut en base64 (sauvegarde sans perte)")
    a = ap.parse_args()

    log_level = logging.WARNING
    if a.verbose == 1:
        log_level = logging.INFO
    elif a.verbose >= 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    if a.full:
        LIM.update(rows=10**12, blob=10**12, strings=10**9, preview=10**12)
    files = []
    for p in a.paths:
        P = Path(p)
        files += [f for f in sorted(P.rglob("*")) if f.is_file()] if P.is_dir() else [P]
    single = len(files) == 1 and not Path(a.paths[0]).is_dir()
    for f in files:
        log.info("Traitement de %s...", f)
        r = clean(process_file(f, a.embed_raw))
        txt = json.dumps(r, ensure_ascii=False, indent=2)
        if a.out and single and a.out.lower().endswith(".json"):
            Path(a.out).write_text(txt, encoding="utf-8")
        elif a.out:
            od = Path(a.out)
            od.mkdir(parents=True, exist_ok=True)
            (od / (f.name + ".json")).write_text(txt, encoding="utf-8")
        elif single:
            print(txt)
        else:
            Path(str(f) + ".json").write_text(txt, encoding="utf-8")
        if a.out or not single:
            print(f"[{'ERR' if 'error' in r else 'ok'}] {f} -> {r.get('detected', '?')}", file=sys.stderr)


if __name__ == "__main__":
    main()
