//! Compares the binary's output with golden files produced by the original
//! pdfid.py (see tests/gen_fixtures.py). Only the first line (tool name and
//! version) differs by design and is skipped.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const FLAGSETS: &[(&str, &[&str])] = &[
    ("default", &[]),
    ("n", &["-n"]),
    ("e", &["-e"]),
    ("a", &["-a"]),
    ("a_e_n", &["-a", "-e", "-n"]),
    ("f_e_a", &["-f", "-e", "-a"]),
];

fn dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name)
}

fn run(args: &[&str], file: &Path) -> Vec<u8> {
    let out = Command::new(env!("CARGO_BIN_EXE_pdfid"))
        .args(args)
        .arg(file)
        .output()
        .expect("run pdfid");
    out.stdout
}

/// Output without the "PDFiD-rs <version> <file>" line (and without disarm log lines before it).
fn body(out: &[u8]) -> Vec<u8> {
    let start = out
        .windows(9)
        .position(|w| w == b"PDFiD-rs ")
        .expect("header line");
    let nl = out[start..]
        .iter()
        .position(|&b| b == b'\n')
        .expect("newline")
        + start;
    out[nl + 1..].to_vec()
}

fn fixtures() -> Vec<PathBuf> {
    let mut v: Vec<_> = fs::read_dir(dir("fixtures"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    assert!(v.len() >= 20, "fixtures missing");
    v
}

/// Number of golden files matching `pred`, so no golden file can be silently skipped.
fn golden_count(pred: impl Fn(&str) -> bool) -> usize {
    fs::read_dir(dir("golden"))
        .unwrap()
        .filter(|e| pred(&e.as_ref().unwrap().file_name().to_string_lossy()))
        .count()
}

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn output_matches_original() {
    let mut compared = 0;
    let mut failures = Vec::new();
    for f in fixtures() {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        for (fs_name, flags) in FLAGSETS {
            let golden = dir("golden").join(format!("{name}.{fs_name}.txt"));
            let Ok(expected) = fs::read(&golden) else {
                continue;
            };
            let actual = body(&run(flags, &f));
            compared += 1;
            if actual != expected {
                failures.push(format!(
                    "{name} [{fs_name}]\n--- expected\n{}\n--- actual\n{}",
                    show(&expected),
                    show(&actual)
                ));
            }
        }
    }
    assert_eq!(
        compared,
        golden_count(|n| !n.ends_with(".disarmed_rescan.txt")),
        "golden files not compared"
    );
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn disarmed_files_match_original() {
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR")).join("golden_disarm");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let mut compared = 0;
    let mut failures = Vec::new();
    for f in fixtures() {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        let golden = dir("golden").join(format!("{name}.disarmed_rescan.txt"));
        let Ok(expected) = fs::read(&golden) else {
            continue;
        };
        let copy = tmp.join(&name);
        fs::copy(&f, &copy).unwrap();
        run(&["-d"], &copy);
        let p = Path::new(&name);
        let disarmed = tmp.join(format!(
            "{}.disarmed.{}",
            p.file_stem().unwrap().to_string_lossy(),
            p.extension().unwrap().to_string_lossy()
        ));
        let size_ok =
            fs::metadata(&disarmed).map(|m| m.len()).ok() == fs::metadata(&f).map(|m| m.len()).ok();
        let actual = body(&run(&["-a", "-f"], &disarmed));
        compared += 1;
        if !size_ok || actual != expected {
            failures.push(format!(
                "{name} (size ok: {size_ok})\n--- expected\n{}\n--- actual\n{}",
                show(&expected),
                show(&actual)
            ));
        }
    }
    assert_eq!(
        compared,
        golden_count(|n| n.ends_with(".disarmed_rescan.txt")),
        "disarm golden files not compared"
    );
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
