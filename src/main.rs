use pdfid::{scan, Count, Options, Report, VERSION};
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs};

const USAGE: &str = "\
pdfid (Rust port of pdfid.py by Didier Stevens)

Usage: pdfid [OPTIONS] <FILE|DIR|->...

Options:
  -a, --all       Show all names
  -e, --extra     Extra info: %%EOF, dates, entropy
  -n, --nozero    Hide keywords with count 0
  -d, --disarm    Write <name>.disarmed.pdf with active-content names case-swapped
  -f, --force     Scan files without %PDF- header
  -s, --scan      Recurse into directories
      --json      JSON output
      --triage    Exit code 2 if suspicious keywords are found
  -h, --help      Show this help
  -V, --version   Show version

Exit codes: 0 ok, 1 error (takes precedence), 2 suspicious (--triage)";

#[derive(Default)]
struct Cli {
    opts: Options,
    nozero: bool,
    recurse: bool,
    json: bool,
    triage: bool,
    inputs: Vec<String>,
}

fn parse_args() -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut only_files = false;
    for arg in env::args().skip(1) {
        if only_files || arg == "-" || !arg.starts_with('-') {
            cli.inputs.push(arg);
            continue;
        }
        let long = |name: &str, cli: &mut Cli| -> Result<(), String> {
            match name {
                "all" | "a" => cli.opts.all_names = true,
                "extra" | "e" => cli.opts.extra = true,
                "nozero" | "n" => cli.nozero = true,
                "disarm" | "d" => cli.opts.disarm = true,
                "force" | "f" => cli.opts.force = true,
                "scan" | "s" => cli.recurse = true,
                "json" => cli.json = true,
                "triage" => cli.triage = true,
                "help" | "h" => return Err(String::new()),
                "version" | "V" => {
                    println!("pdfid {VERSION}");
                    std::process::exit(0);
                }
                other => return Err(format!("unknown option: {other}")),
            }
            Ok(())
        };
        if arg == "--" {
            only_files = true;
        } else if let Some(name) = arg.strip_prefix("--") {
            long(name, &mut cli)?;
        } else {
            for c in arg[1..].chars() {
                long(&c.to_string(), &mut cli)?;
            }
        }
    }
    if cli.inputs.is_empty() {
        return Err(String::new());
    }
    Ok(cli)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        let md = fs::symlink_metadata(&p)?;
        if md.is_dir() {
            walk(&p, out)?;
        } else if md.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

/// `x.pdf` -> `x.disarmed.pdf` (same naming as pdfid.py).
fn disarmed_path(p: &Path) -> PathBuf {
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = match p.extension() {
        Some(ext) => format!("{stem}.disarmed.{}", ext.to_string_lossy()),
        None => format!("{stem}.disarmed"),
    };
    p.with_file_name(name)
}

fn line(k: &str, c: &Count) -> String {
    let mut s = format!(" {k:<16} {:>7}", c.count);
    if c.hex > 0 {
        let _ = write!(s, "({})", c.hex);
    }
    s
}

fn fmt_entropy(e: &pdfid::Entropy) -> String {
    match e.value {
        Some(v) => format!("{v:.6}"),
        None => "N/A     ".into(),
    }
}

fn text(name: &str, r: &Report, cli: &Cli, disarmed: Option<&Path>) -> String {
    let mut o = String::new();
    for (a, b) in &r.disarm_log {
        let _ = writeln!(o, "/{a} -> /{b}");
    }
    let _ = writeln!(o, "PDFiD-rs {VERSION} {name}");
    if !r.scanned {
        let _ = writeln!(o, " Not a PDF document\n");
        return o;
    }
    let _ = writeln!(o, " PDF Header: {}", r.header.as_deref().unwrap_or(""));
    for (k, c) in &r.keywords {
        if !(cli.nozero && c.count == 0) {
            let _ = writeln!(o, "{}", line(k, c));
        }
    }
    for (k, c) in &r.names {
        let _ = writeln!(o, "{}", line(k, c));
    }
    if let Some(e) = &r.extra {
        let _ = writeln!(
            o,
            "{}",
            line(
                "%%EOF",
                &Count {
                    count: e.eof_count,
                    hex: 0
                }
            )
        );
        if e.eof_count > 0 {
            let _ = writeln!(
                o,
                "{}",
                line(
                    "After last %%EOF",
                    &Count {
                        count: e.after_last_eof,
                        hex: 0
                    }
                )
            );
        }
        for (d, n) in &e.dates {
            let _ = writeln!(o, " {d:<23} {n}");
        }
        for (label, en) in [
            ("Total entropy:          ", &e.total),
            ("Entropy inside streams: ", &e.inside_streams),
            ("Entropy outside streams:", &e.outside_streams),
        ] {
            let _ = writeln!(o, " {label} {} ({:>10} bytes)", fmt_entropy(en), en.bytes);
        }
    }
    if cli.triage {
        let sus = r.suspicious();
        if !sus.is_empty() {
            let list: Vec<_> = sus.iter().map(|(k, _)| *k).collect();
            let _ = writeln!(o, " Suspicious: {}", list.join(", "));
        }
    }
    if let Some(p) = disarmed {
        let _ = writeln!(o, " Disarmed -> {}", p.display());
    }
    o.push('\n');
    o
}

fn js(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn count_map<'a>(it: impl Iterator<Item = (&'a str, &'a Count)>) -> String {
    let parts: Vec<_> = it
        .map(|(k, c)| format!("{}:{{\"count\":{},\"hexcodes\":{}}}", js(k), c.count, c.hex))
        .collect();
    format!("{{{}}}", parts.join(","))
}

fn json(name: &str, r: &Report, cli: &Cli, disarmed: Option<&Path>) -> String {
    let mut f = vec![
        format!("\"file\":{}", js(name)),
        format!("\"isPdf\":{}", r.is_pdf()),
        format!(
            "\"header\":{}",
            r.header.as_deref().map_or("null".into(), js)
        ),
    ];
    if r.scanned {
        f.push(format!(
            "\"keywords\":{}",
            count_map(r.keywords.iter().map(|(k, c)| (*k, c)))
        ));
        if cli.opts.all_names {
            f.push(format!(
                "\"names\":{}",
                count_map(r.names.iter().map(|(k, c)| (k.as_str(), c)))
            ));
        }
        if let Some(e) = &r.extra {
            let dates: Vec<_> = e
                .dates
                .iter()
                .map(|(d, n)| format!("{{\"date\":{},\"name\":{}}}", js(d), js(n)))
                .collect();
            let ent = |en: pdfid::Entropy| match en.value {
                Some(v) => format!("{{\"value\":{v:.6},\"bytes\":{}}}", en.bytes),
                None => format!("{{\"value\":null,\"bytes\":{}}}", en.bytes),
            };
            f.push(format!(
                "\"extra\":{{\"eofCount\":{},\"afterLastEof\":{},\"dates\":[{}],\"entropy\":{{\"total\":{},\"insideStreams\":{},\"outsideStreams\":{}}}}}",
                e.eof_count,
                if e.eof_count > 0 { e.after_last_eof.to_string() } else { "null".into() },
                dates.join(","),
                ent(e.total),
                ent(e.inside_streams),
                ent(e.outside_streams)
            ));
        }
        let sus: Vec<_> = r.suspicious().iter().map(|(k, _)| js(k)).collect();
        f.push(format!("\"suspicious\":[{}]", sus.join(",")));
    }
    if let Some(p) = disarmed {
        f.push(format!("\"disarmed\":{}", js(&p.to_string_lossy())));
    }
    format!("{{{}}}", f.join(","))
}

fn main() -> ExitCode {
    let cli = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(1);
        }
    };

    let mut targets: Vec<Option<PathBuf>> = Vec::new(); // None = stdin
    let mut errors = false;
    for inp in &cli.inputs {
        if inp == "-" {
            targets.push(None);
            continue;
        }
        let p = PathBuf::from(inp);
        if p.is_dir() {
            if !cli.recurse {
                eprintln!("error: {inp} is a directory (use -s)");
                errors = true;
                continue;
            }
            let mut files = Vec::new();
            if let Err(e) = walk(&p, &mut files) {
                eprintln!("error: {inp}: {e}");
                errors = true;
            }
            targets.extend(files.into_iter().map(Some));
        } else {
            targets.push(Some(p));
        }
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut suspicious = false;
    let mut json_items = Vec::new();

    for t in &targets {
        let (name, data) = match t {
            None => {
                let mut buf = Vec::new();
                match io::stdin().read_to_end(&mut buf) {
                    Ok(_) => ("<stdin>".to_string(), buf),
                    Err(e) => {
                        eprintln!("error: <stdin>: {e}");
                        errors = true;
                        continue;
                    }
                }
            }
            Some(p) => match fs::read(p) {
                Ok(d) => (p.display().to_string(), d),
                Err(e) => {
                    eprintln!("error: {}: {e}", p.display());
                    errors = true;
                    if cli.json {
                        json_items.push(format!(
                            "{{\"file\":{},\"error\":{}}}",
                            js(&p.display().to_string()),
                            js(&e.to_string())
                        ));
                    }
                    continue;
                }
            },
        };

        let report = scan(&data, &cli.opts);
        suspicious |= !report.suspicious().is_empty();

        let mut written = None;
        if let Some(buf) = &report.disarmed {
            match t {
                Some(p) => {
                    let dp = disarmed_path(p);
                    match fs::write(&dp, buf) {
                        Ok(()) => written = Some(dp),
                        Err(e) => {
                            eprintln!("error: {}: {e}", dp.display());
                            errors = true;
                        }
                    }
                }
                None => eprintln!("warning: --disarm ignored for stdin"),
            }
        }

        if cli.json {
            json_items.push(json(&name, &report, &cli, written.as_deref()));
        } else {
            let _ = write!(out, "{}", text(&name, &report, &cli, written.as_deref()));
        }
    }

    if cli.json {
        let _ = writeln!(out, "[{}]", json_items.join(","));
    }

    if errors {
        ExitCode::from(1)
    } else if cli.triage && suspicious {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}
