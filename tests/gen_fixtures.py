#!/usr/bin/env python3
"""Generates tests/fixtures/* and the golden outputs in tests/golden/ by running the
ORIGINAL pdfid.py. Only needed when fixtures change; the Rust tests use the results.

Usage: python3 -I tests/gen_fixtures.py /path/to/pdfid.py
"""
import os, random, shutil, subprocess, sys, tempfile, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
GOLD = os.path.join(HERE, "golden")

# flag-set name -> pdfid flags (keep in sync with tests/golden.rs)
FLAGSETS = {
    "default": [],
    "n": ["-n"],
    "e": ["-e"],
    "a": ["-a"],
    "a_e_n": ["-a", "-e", "-n"],
    "f_e_a": ["-f", "-e", "-a"],
}


def fixtures():
    rnd = random.Random(42)
    blob = bytes(rnd.getrandbits(8) for _ in range(4000))
    flate = zlib.compress(b"BT /F1 12 Tf 72 712 Td (Hello) Tj ET\n" * 20)
    return {
        # typical malicious structure: every keyword, hex obfuscation, dates, binary stream
        "evil.pdf": b"%PDF-1.7\n1 0 obj\n<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R/AA<<>>/AcroForm<</XFA 9 0 R>>>>\nendobj\n"
            b"2 0 obj\n<</Type/Pages/Kids[4 0 R]/Count 1>>\nendobj\n"
            b"3 0 obj\n<</S/J#61vaScript/J#53 (app.alert\\(1\\))>>\nendobj\n"
            b"4 0 obj\n<</Type/Page/Parent 2 0 R/AA<</O<</S/Launch/F(cmd.exe)>>>>/CreationDate(D:20260101120000+01'00')/ModDate (D:20250102030405Z)/X(D:20240101000000)>>\nendobj\n"
            b"5 0 obj\n<</Length 4000/Filter/JBIG2Decode/DecodeParms<</Colors 16777217>>>>\nstream\n" + blob + b"\nendstream\nendobj\n"
            b"6 0 obj\n<</Type/ObjStm/N 1>>stream\nendstream endobj 7 0 obj<</Type/EmbeddedFile/RichMedia 1/Encrypt 2>>endobj\n"
            b"xref\ntrailer\n<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n%%EOF\r\nTRAILINGJUNK\n",
        # benign, well-formed document with a Flate stream and proper xref
        "benign.pdf": (lambda body: body + b"xref\n0 5\n0000000000 65535 f \ntrailer\n<</Size 5/Root 1 0 R/Info 4 0 R>>\nstartxref\n%d\n%%%%EOF\n" % len(body))(
            b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
            b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
            b"2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n"
            b"3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 5 0 R>>\nendobj\n"
            b"4 0 obj\n<</Producer(test)/CreationDate(D:20231231235959-05'30')/ModDate(D:20240101000000+00'00')>>\nendobj\n"
            + (b"5 0 obj\n<</Length %d/Filter/FlateDecode>>\nstream\n" % len(flate)) + flate + b"\nendstream\nendobj\n"),
        # hex obfuscation incl. full-hex names, invalid escapes, /Colors variants
        "obf.pdf": b"%PDF-1.4\n/#4A#53 /#4a#61#76#61#53#63#72#69#70#74 /Open#41ction /J#5 /JS# /Pag#65 /Page#73 "
            b"/Colors 00016777217 /Colors 16777216 /Colors/99999999 /Colors 000000000000000000000000000016777217 "
            b"/Colors 123456789012345678901234567890\n%%EOF",
        # escapes at the very end of the file
        "escape_eof1.pdf": b"%PDF-1.4\n/JS#",
        "escape_eof2.pdf": b"%PDF-1.4\n/JS#4",
        # %%EOF state machine corner cases
        "eofs.pdf": b"%PDF-1.5\r%%EOF %%EOF\t x %%%EOF\n%%EOF\rZ%%EOF",
        "eof_crlf.pdf": b"%PDF-1.5\n%%EOF\r\n",
        "eof_noeol.pdf": b"%PDF-1.5\n/JS\n%%EOF",
        # date state machine corner cases
        "dates.pdf": b"%PDF-1.6\n"
            b"/A(D:20200101000000)"           # no TZ, terminated by ')'
            b"/B\"D:20200102000000\""          # terminated by '"'
            b"/C(D:20200103000000Z)"           # Z with no offset -> dropped
            b"/D(D:2020010400000)"             # 13 digits -> dropped
            b"/E(D:202001050000001)"           # 15 digits -> dropped
            b"/F(D:20200106000000+0100)"       # missing quote -> dropped
            b"/G(D:20200107000000-0x'00)"      # bad TZ digit -> dropped
            b"/H(D:20200108000000+01'0x)"      # bad minutes -> dropped
            b"/I(DD:20200109000000+01'00')"    # D restarts the machine
            b"/J(D;20200110000000)"            # no colon
            b"/K(D:20200111000000+01'00')\n",
        # header variants
        "noheader.bin": b"MZ\x90\x00 junk /JavaScript obj\n",
        "lateheader.pdf": b"X" * 900 + b"%PDF-1.3\n/JS\n%%EOF",
        "longheader.pdf": b"%PDF-1.4 /JS /JavaScript /AA\n%%EOF",
        "binhdr.pdf": b"%PDF\x00\x01\xff-1.6\n/Launch",
        "quotehdr.pdf": b"%PDF'1.6\n/JS",
        "crhdr.pdf": b"%PDF-2.0\r/OpenAction\r%%EOF",
        "shorthdr.pdf": b"%PDF-1",
        # stream handling
        "nostreamend.pdf": b"%PDF-1.2\nstream\nabc /JS\n",
        "endstream_only.pdf": b"%PDF-1.2\nendstream\nstream\nendstream\nendstream\n",
        # names with high bytes and digits (sorting, latin-1 mapping)
        "names.pdf": b"%PDF-1.4\n/Zeta /alpha /#e9t#e9 /#ff /Beta2 /2nd /alpha /#00x\n",
        "empty.pdf": b"",
    }


def run(cmd):
    p = subprocess.run(cmd, capture_output=True)
    return p.returncode, p.stdout.decode("latin1")


def body(out):
    # drop the "PDFiD <version> <file>" line; keep everything else verbatim
    return out.split("\n", 1)[1] if "\n" in out else ""


def main():
    orig = sys.argv[1]
    shutil.rmtree(FIX, ignore_errors=True)
    shutil.rmtree(GOLD, ignore_errors=True)
    os.makedirs(FIX)
    os.makedirs(GOLD)
    for name, data in fixtures().items():
        with open(os.path.join(FIX, name), "wb") as f:
            f.write(data)
    for name in sorted(os.listdir(FIX)):
        path = os.path.join(FIX, name)
        for fs, flags in FLAGSETS.items():
            rc, out = run([sys.executable, "-I", orig] + flags + [path])
            if rc != 0 or "***Error occured***" in out:
                print(f"skip {name} [{fs}]: original fails")
                continue
            with open(os.path.join(GOLD, f"{name}.{fs}.txt"), "w", encoding="latin1", newline="") as f:
                f.write(body(out))
        # disarm: original disarms a copy, then scans its own result with -a -f
        with tempfile.TemporaryDirectory() as td:
            cp = os.path.join(td, name)
            shutil.copy(path, cp)
            run([sys.executable, "-I", orig, "-d", cp])
            root, ext = os.path.splitext(cp)
            dp = root + ".disarmed" + ext
            if os.path.exists(dp) and os.path.getsize(dp) == len(open(path, "rb").read()) > 0:
                _, out = run([sys.executable, "-I", orig, "-a", "-f", dp])
                with open(os.path.join(GOLD, f"{name}.disarmed_rescan.txt"), "w", encoding="latin1", newline="") as f:
                    f.write(body(out))
    print(f"{len(os.listdir(FIX))} fixtures, {len(os.listdir(GOLD))} golden files")


if __name__ == "__main__":
    main()
