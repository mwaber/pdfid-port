#!/usr/bin/env python3
"""Differential test: compares the Rust port with the original pdfid.py on any set of files.

Output must be byte-identical (except the first "PDFiD <version> <file>" line) for
several flag combinations, and disarmed files of both tools must rescan identically.

Usage:
  python3 -I tests/parity.py --orig /path/to/pdfid.py [--bin target/release/pdfid] PATH...

PATH can be files or directories (scanned recursively). Exit code 1 on any mismatch.
"""
import argparse, os, shutil, subprocess, sys, tempfile

FLAGSETS = [[], ["-n"], ["-e"], ["-a"], ["-a", "-e", "-n"], ["-f", "-e", "-a"]]


def run(cmd):
    return subprocess.run(cmd, capture_output=True).stdout


def body(out):
    # drop everything up to and including the "PDFiD..." line (disarm logs precede it)
    lines = out.split(b"\n")
    i = next((k for k, l in enumerate(lines) if l.startswith(b"PDFiD")), None)
    return None if i is None else b"\n".join(lines[i + 1:])


def collect(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    f = os.path.join(root, n)
                    if os.path.isfile(f) and not os.path.islink(f):
                        yield f
        elif os.path.isfile(p):
            yield p


def first_diff(a, b):
    la, lb = a.split(b"\n"), b.split(b"\n")
    for k, (x, y) in enumerate(zip(la, lb)):
        if x != y:
            return f"line {k + 2}: original {x!r} / port {y!r}"
    return f"line count: original {len(la)} / port {len(lb)}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--orig", required=True, help="path to the original pdfid.py")
    ap.add_argument("--bin", default=os.path.join(os.path.dirname(__file__), "..", "target", "release", "pdfid"))
    ap.add_argument("--no-disarm", action="store_true", help="skip the disarm comparison")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    orig = [sys.executable, "-I", a.orig]

    files = list(collect(a.paths))
    compared = skipped = fails = 0
    for f in files:
        for flags in FLAGSETS:
            o = run(orig + flags + [f])
            if b"***Error occured***" in o or body(o) is None:
                skipped += 1  # original crashed; the port handles these cases on its own
                continue
            r = run([a.bin] + flags + [f])
            compared += 1
            if body(o) != body(r):
                fails += 1
                print(f"DIFF {f} {' '.join(flags) or '(no flags)'}: {first_diff(body(o), body(r))}")

    dcompared = dfails = 0
    if not a.no_disarm:
        with tempfile.TemporaryDirectory() as td:
            for k, f in enumerate(files):
                base = os.path.basename(f)
                root, ext = os.path.splitext(base)
                outs = []
                for tag, cmd in (("o", orig), ("r", [a.bin])):
                    d = os.path.join(td, f"{k}{tag}")
                    os.makedirs(d)
                    shutil.copy(f, os.path.join(d, base))
                    run(cmd + ["-d", os.path.join(d, base)])
                    outs.append(os.path.join(d, root + ".disarmed" + ext))
                # the original writes an empty file for non-PDFs; the port writes none
                if not all(os.path.exists(p) and os.path.getsize(p) for p in outs):
                    continue
                dcompared += 1
                x, y = (body(run(orig + ["-a", "-f", p])) for p in outs)
                if x != y or os.path.getsize(outs[0]) != os.path.getsize(outs[1]):
                    dfails += 1
                    print(f"DISARM DIFF {f}")

    print(f"{len(files)} files: {compared} outputs compared, {fails} mismatches, "
          f"{skipped} skipped (original crashed); disarm: {dcompared} compared, {dfails} mismatches")
    sys.exit(1 if fails or dfails else 0)


if __name__ == "__main__":
    main()
