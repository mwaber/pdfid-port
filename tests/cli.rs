//! CLI behaviour: argument parsing, input handling, JSON, triage exit codes, disarm files, errors.

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Fresh per-test scratch directory.
fn tmpdir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("cli")
        .join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn pdfid<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_pdfid"))
        .args(args)
        .output()
        .unwrap()
}

fn pdfid_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pdfid"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

/// A keyword line in pdfid's text format (` %-16s %7d`).
fn kw_line(k: &str, n: u64) -> String {
    format!(" {k:<16} {n:>7}\n")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn json(o: &Output) -> Vec<Value> {
    serde_json::from_slice::<Value>(&o.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON ({e}): {}", stdout(o)))
        .as_array()
        .unwrap()
        .clone()
}

// ---------------------------------------------------------------- arguments

#[test]
fn no_arguments_prints_usage() {
    let o = pdfid::<_, &str>([]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("Usage: pdfid"));
    assert!(!stderr(&o).contains("error:"));
}

#[test]
fn help_flags() {
    for f in ["-h", "--help"] {
        let o = pdfid([f]);
        assert_eq!(o.status.code(), Some(1), "{f}");
        assert!(stderr(&o).contains("Usage: pdfid"), "{f}");
    }
}

#[test]
fn version_flags() {
    for f in ["-V", "--version"] {
        let o = pdfid([f]);
        assert!(o.status.success(), "{f}");
        assert_eq!(
            stdout(&o).trim(),
            format!("pdfid {}", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn unknown_options_are_rejected() {
    for f in ["-x", "--bogus", "-nx"] {
        let o = pdfid([f, "file.pdf"]);
        assert_eq!(o.status.code(), Some(1), "{f}");
        assert!(stderr(&o).contains("error: unknown option"), "{f}");
        assert!(stdout(&o).is_empty());
    }
}

#[test]
fn options_without_input_print_usage() {
    let o = pdfid(["-n", "-e"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("Usage: pdfid"));
}

#[test]
fn combined_short_flags_equal_separate_flags() {
    let f = fixture("evil.pdf");
    let a = pdfid([Path::new("-nae"), &f]);
    let b = pdfid([Path::new("-n"), Path::new("-a"), Path::new("-e"), &f]);
    assert!(a.status.success());
    assert_eq!(a.stdout, b.stdout);
    assert!(stdout(&a).contains("Total entropy:"));
    assert!(!stdout(&a).contains(" 0\n"), "-n must hide zero counts");
}

#[test]
fn long_options() {
    let f = fixture("evil.pdf");
    let a = pdfid([
        Path::new("--nozero"),
        Path::new("--all"),
        Path::new("--extra"),
        &f,
    ]);
    let b = pdfid([Path::new("-nae"), &f]);
    assert_eq!(a.stdout, b.stdout);
}

#[test]
fn double_dash_ends_options() {
    let d = tmpdir("double_dash");
    let f = d.join("-n");
    fs::copy(fixture("evil.pdf"), &f).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_pdfid"))
        .current_dir(&d)
        .args(["--", "-n"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("PDFiD-rs ") && stdout(&o).contains(" -n\n"));
    assert!(stdout(&o).contains(&kw_line("/OpenAction", 1)));
}

// ---------------------------------------------------------------- inputs

#[test]
fn reads_from_stdin() {
    let data = fs::read(fixture("obf.pdf")).unwrap();
    let a = pdfid_stdin(&["-e", "-"], &data);
    let b = pdfid([Path::new("-e"), &fixture("obf.pdf")]);
    assert!(a.status.success());
    let tail = |s: String| s.split_once('\n').unwrap().1.to_string();
    assert!(stdout(&a).starts_with(&format!("PDFiD-rs {} <stdin>\n", env!("CARGO_PKG_VERSION"))));
    assert_eq!(tail(stdout(&a)), tail(stdout(&b)));
}

#[test]
#[cfg(unix)] // a directory cannot be opened as a file handle on Windows
fn stdin_read_error() {
    // a directory as stdin makes read() fail with EISDIR
    let o = Command::new(env!("CARGO_BIN_EXE_pdfid"))
        .arg("-")
        .stdin(fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("error: <stdin>:"), "{}", stderr(&o));
    assert!(stdout(&o).is_empty());
}

#[test]
fn disarm_is_ignored_for_stdin() {
    let data = fs::read(fixture("evil.pdf")).unwrap();
    let o = pdfid_stdin(&["-d", "-"], &data);
    assert!(o.status.success());
    assert!(stderr(&o).contains("warning: --disarm ignored for stdin"));
    assert!(!stdout(&o).contains("Disarmed ->"));
}

#[test]
fn directory_requires_scan_flag() {
    let d = tmpdir("dir_noscan");
    let o = pdfid([&d]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("is a directory (use -s)"));
}

#[test]
fn scan_recurses_sorted_and_skips_symlinks() {
    let d = tmpdir("scan");
    fs::create_dir_all(d.join("b/nested")).unwrap();
    fs::copy(fixture("benign.pdf"), d.join("b/nested/z.pdf")).unwrap();
    fs::copy(fixture("evil.pdf"), d.join("a.pdf")).unwrap();
    fs::write(d.join("c.txt"), b"not a pdf").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(fixture("evil.pdf"), d.join("link.pdf")).unwrap();
        std::os::unix::fs::symlink(&d, d.join("b/loop")).unwrap();
    }
    for flag in ["-s", "--scan"] {
        let o = pdfid([Path::new(flag), &d]);
        assert!(o.status.success(), "{}", stderr(&o));
        let files: Vec<_> = stdout(&o)
            .lines()
            .filter_map(|l| l.strip_prefix("PDFiD-rs "))
            .map(|l| l.split_once(' ').unwrap().1.to_string())
            .collect();
        let rel: Vec<_> = files
            .iter()
            .map(|f| {
                Path::new(f)
                    .strip_prefix(&d)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(rel, ["a.pdf", "b/nested/z.pdf", "c.txt"]);
        assert!(stdout(&o).contains(" Not a PDF document"));
    }
}

#[test]
fn missing_file_is_an_error_but_others_continue() {
    let o = pdfid([Path::new("/nonexistent/x.pdf"), &fixture("benign.pdf")]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("error: /nonexistent/x.pdf"));
    assert!(stdout(&o).contains("benign.pdf"));
}

#[test]
fn multiple_files_in_order() {
    let o = pdfid([fixture("evil.pdf"), fixture("benign.pdf")]);
    let s = stdout(&o);
    assert!(s.find("evil.pdf").unwrap() < s.find("benign.pdf").unwrap());
    assert_eq!(s.matches("PDFiD-rs ").count(), 2);
}

// ---------------------------------------------------------------- text output specifics

#[test]
fn non_pdf_text_output() {
    let o = pdfid([fixture("noheader.bin")]);
    assert!(o.status.success());
    assert!(stdout(&o).ends_with(" Not a PDF document\n\n"));
    assert!(!stdout(&o).contains("obj"));
}

#[test]
fn originals_crash_cases_are_handled() {
    // pdfid.py raises on these (ZeroDivisionError / IndexError); the port must not.
    let e = pdfid([
        Path::new("-f"),
        Path::new("-e"),
        Path::new("-a"),
        &fixture("empty.pdf"),
    ]);
    assert!(e.status.success());
    assert!(stdout(&e).contains(" PDF Header: \n"));
    assert!(stdout(&e).contains(" Total entropy:           0.000000 (         0 bytes)"));
    assert!(stdout(&e).contains(" Entropy inside streams:  N/A      (         0 bytes)"));

    let s = pdfid([Path::new("-e"), &fixture("shorthdr.pdf")]);
    assert!(s.status.success());
    assert!(stdout(&s).contains(" PDF Header: %PDF-1\n"));
}

// ---------------------------------------------------------------- triage

#[test]
fn triage_exit_codes() {
    let evil = pdfid([Path::new("--triage"), &fixture("evil.pdf")]);
    assert_eq!(evil.status.code(), Some(2));
    assert!(stdout(&evil).contains(" Suspicious: /JS, /JavaScript, /AA, /OpenAction, /JBIG2Decode, /RichMedia, /Launch, /EmbeddedFile, /XFA, /Colors > 2^24\n"));

    let benign = pdfid([Path::new("--triage"), &fixture("benign.pdf")]);
    assert_eq!(benign.status.code(), Some(0));
    assert!(!stdout(&benign).contains("Suspicious"));

    // without --triage, suspicious content does not change the exit code
    assert_eq!(pdfid([fixture("evil.pdf")]).status.code(), Some(0));

    // error takes precedence over suspicious
    let both = pdfid([
        Path::new("--triage"),
        &fixture("evil.pdf"),
        Path::new("/nonexistent.pdf"),
    ]);
    assert_eq!(both.status.code(), Some(1));

    // non-PDF without -f is never suspicious, even if it contains /JavaScript
    let np = pdfid([Path::new("--triage"), &fixture("noheader.bin")]);
    assert_eq!(np.status.code(), Some(0));
    let npf = pdfid([
        Path::new("--triage"),
        Path::new("-f"),
        &fixture("noheader.bin"),
    ]);
    assert_eq!(npf.status.code(), Some(2));
}

#[test]
fn colors_alone_is_suspicious() {
    let d = tmpdir("colors");
    let f = d.join("c.pdf");
    fs::write(&f, b"%PDF-1.4\n<</Colors 33554432>>\n").unwrap();
    let o = pdfid([Path::new("--triage"), &f]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stdout(&o).contains(" Suspicious: /Colors > 2^24\n"));
}

// ---------------------------------------------------------------- JSON

#[test]
fn json_full_report() {
    let o = pdfid([
        Path::new("--json"),
        Path::new("-a"),
        Path::new("-e"),
        &fixture("evil.pdf"),
    ]);
    assert!(o.status.success());
    let v = json(&o);
    assert_eq!(v.len(), 1);
    let r = &v[0];
    assert!(r["file"].as_str().unwrap().ends_with("evil.pdf"));
    assert_eq!(r["isPdf"], true);
    assert_eq!(r["header"], "%PDF-1.7");
    let kw = r["keywords"].as_object().unwrap();
    assert_eq!(kw.len(), 21);
    assert_eq!(kw["obj"]["count"], 7);
    assert_eq!(kw["/JavaScript"]["count"], 1);
    assert_eq!(kw["/JavaScript"]["hexcodes"], 1);
    assert_eq!(kw["/Colors > 2^24"]["count"], 1);
    // JSON keeps keyword order of pdfid.py
    let order: Vec<_> = kw.keys().map(String::as_str).collect();
    assert_eq!(order[0], "obj");
    assert_eq!(*order.last().unwrap(), "/Colors > 2^24");
    assert_eq!(r["names"]["/Type"]["count"], 5);
    assert!(
        r["names"].get("/JS").is_none(),
        "keywords are not repeated in names"
    );
    let e = &r["extra"];
    assert_eq!(e["eofCount"], 2);
    assert_eq!(e["afterLastEof"], 13);
    assert_eq!(e["dates"].as_array().unwrap().len(), 2);
    assert_eq!(e["dates"][0]["date"], "D:20240101000000");
    assert_eq!(e["dates"][0]["name"], "/X");
    assert!(e["entropy"]["insideStreams"]["value"].as_f64().unwrap() > 7.0);
    let total = e["entropy"]["total"]["bytes"].as_u64().unwrap();
    let ins = e["entropy"]["insideStreams"]["bytes"].as_u64().unwrap();
    let out = e["entropy"]["outsideStreams"]["bytes"].as_u64().unwrap();
    assert_eq!(total, fs::metadata(fixture("evil.pdf")).unwrap().len());
    assert_eq!(ins + out, total);
    assert_eq!(r["suspicious"].as_array().unwrap().len(), 10);
    assert!(r.get("disarmed").is_none());
}

#[test]
fn json_minimal_and_nulls() {
    let o = pdfid([Path::new("--json"), Path::new("-e"), &fixture("dates.pdf")]);
    let r = &json(&o)[0];
    assert!(r.get("names").is_none(), "names only with -a");
    assert_eq!(r["extra"]["eofCount"], 0);
    assert!(r["extra"]["afterLastEof"].is_null());
    assert!(r["extra"]["entropy"]["insideStreams"]["value"].is_null());
    assert_eq!(r["suspicious"], Value::Array(vec![]));

    let o = pdfid([Path::new("--json"), &fixture("benign.pdf")]);
    assert!(json(&o)[0].get("extra").is_none(), "extra only with -e");
}

#[test]
fn json_non_pdf_and_errors() {
    let o = pdfid([
        Path::new("--json"),
        &fixture("noheader.bin"),
        Path::new("/nonexistent.pdf"),
        &fixture("benign.pdf"),
    ]);
    assert_eq!(o.status.code(), Some(1));
    let v = json(&o);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0]["isPdf"], false);
    assert!(v[0]["header"].is_null());
    assert!(v[0].get("keywords").is_none());
    assert_eq!(v[1]["file"], "/nonexistent.pdf");
    assert!(!v[1]["error"].as_str().unwrap().is_empty());
    assert_eq!(v[2]["isPdf"], true);

    // forced scan of a non-PDF reports keywords but isPdf=false
    let o = pdfid([
        Path::new("--json"),
        Path::new("-f"),
        &fixture("noheader.bin"),
    ]);
    let r = &json(&o)[0];
    assert_eq!(r["isPdf"], false);
    assert_eq!(r["keywords"]["/JavaScript"]["count"], 1);
}

#[test]
fn json_escapes_strings() {
    let d = tmpdir("json_escape");
    let f = d.join("q\"b\\s\tt\u{1}\n\ré.pdf");
    fs::copy(fixture("names.pdf"), &f).unwrap();
    let o = pdfid([Path::new("--json"), Path::new("-a"), &f]);
    let r = &json(&o)[0];
    assert_eq!(r["file"].as_str().unwrap(), f.to_str().unwrap());
    let names = r["names"].as_object().unwrap();
    assert!(names.contains_key("/\u{0}x"));
    assert!(names.contains_key("/été"));
    assert!(names.contains_key("/\u{ff}"));
}

#[test]
fn json_empty_input_list() {
    let d = tmpdir("json_empty");
    let o = pdfid([Path::new("--json"), Path::new("-s"), &d]);
    assert!(o.status.success());
    assert_eq!(stdout(&o).trim(), "[]");
}

// ---------------------------------------------------------------- disarm

#[test]
fn disarm_writes_file_next_to_input() {
    let d = tmpdir("disarm");
    let f = d.join("in.pdf");
    fs::copy(fixture("evil.pdf"), &f).unwrap();
    let o = pdfid([Path::new("-d"), &f]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = d.join("in.disarmed.pdf");
    assert!(stdout(&o).contains(&format!(" Disarmed -> {}\n", out.display())));
    assert!(stdout(&o).starts_with("/OpenAction -> /oPENaCTION\n"));
    assert!(stdout(&o).contains("/J#61vaScript -> /j#41VAsCRIPT\n"));
    let orig = fs::read(&f).unwrap();
    let dis = fs::read(&out).unwrap();
    assert_eq!(orig.len(), dis.len());
    assert_eq!(
        fs::read(&f).unwrap(),
        fs::read(fixture("evil.pdf")).unwrap(),
        "input untouched"
    );
    let diff = orig.iter().zip(&dis).filter(|(a, b)| a != b).count();
    assert!(diff > 0);
    // rescan: nothing active left
    let r = &json(&pdfid([Path::new("--json"), &out]))[0];
    for k in [
        "/JS",
        "/JavaScript",
        "/AA",
        "/OpenAction",
        "/JBIG2Decode",
        "/RichMedia",
        "/Launch",
    ] {
        assert_eq!(r["keywords"][k]["count"], 0, "{k}");
    }
    // not in the original's disarm set, stays
    assert_eq!(r["keywords"]["/EmbeddedFile"]["count"], 1);
}

#[test]
fn disarm_file_naming() {
    let d = tmpdir("disarm_names");
    fs::copy(fixture("evil.pdf"), d.join("noext")).unwrap();
    fs::copy(fixture("evil.pdf"), d.join("x.bin")).unwrap();
    fs::copy(fixture("evil.pdf"), d.join("a.b.pdf")).unwrap();
    let o = pdfid([
        Path::new("-d"),
        &d.join("noext"),
        &d.join("x.bin"),
        &d.join("a.b.pdf"),
    ]);
    assert!(o.status.success());
    for n in ["noext.disarmed", "x.disarmed.bin", "a.b.disarmed.pdf"] {
        assert!(d.join(n).is_file(), "{n} missing");
    }
}

#[test]
fn disarm_json_reports_path() {
    let d = tmpdir("disarm_json");
    let f = d.join("in.pdf");
    fs::copy(fixture("evil.pdf"), &f).unwrap();
    let r = &json(&pdfid([Path::new("--json"), Path::new("-d"), &f]))[0];
    assert_eq!(
        r["disarmed"].as_str().unwrap(),
        d.join("in.disarmed.pdf").to_str().unwrap()
    );
}

#[test]
fn disarm_write_failure_is_an_error() {
    let d = tmpdir("disarm_fail");
    let f = d.join("in.pdf");
    fs::copy(fixture("evil.pdf"), &f).unwrap();
    fs::create_dir(d.join("in.disarmed.pdf")).unwrap(); // target occupied by a directory
    let o = pdfid([Path::new("-d"), &f]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("in.disarmed.pdf"));
    assert!(!stdout(&o).contains("Disarmed ->"));
    assert!(
        stdout(&o).contains(&kw_line("/OpenAction", 1)),
        "report still printed"
    );
}

#[test]
fn disarm_skipped_for_non_pdf() {
    let d = tmpdir("disarm_nonpdf");
    let f = d.join("x.bin");
    fs::copy(fixture("noheader.bin"), &f).unwrap();
    let o = pdfid([Path::new("-d"), &f]);
    assert!(o.status.success());
    assert!(!d.join("x.disarmed.bin").exists());
}
