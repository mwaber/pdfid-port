//! Rust port of Didier Stevens' `pdfid.py` (0.2.10).
//!
//! Scans a PDF byte stream with a lightweight tokenizer (no full parse) and counts
//! keywords that indicate active content. PDF name obfuscation via `#xx` hex
//! escapes is decoded, and obfuscated hits are counted separately.
//!
//! Tokenizer, header handling, `%%EOF` / date state machines and entropy
//! attribution follow the original byte for byte, so results are identical.

use std::collections::{BTreeMap, HashMap};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Keywords counted by default (same set and order as pdfid.py).
pub const KEYWORDS: &[&str] = &[
    "obj",
    "endobj",
    "stream",
    "endstream",
    "xref",
    "trailer",
    "startxref",
    "/Page",
    "/Encrypt",
    "/ObjStm",
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/AcroForm",
    "/JBIG2Decode",
    "/RichMedia",
    "/Launch",
    "/EmbeddedFile",
    "/XFA",
];

/// Pseudo-keyword for CVE-2009-3459 (`/Colors` with a value > 2^24).
pub const COLORS_KEY: &str = "/Colors > 2^24";

/// Names whose case is swapped by `--disarm` (same set as pdfid.py).
pub const DISARM: &[&str] = &[
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/JBIG2Decode",
    "/RichMedia",
    "/Launch",
];

/// Keywords considered suspicious for triage (plus [`COLORS_KEY`]).
pub const SUSPICIOUS: &[&str] = &[
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/JBIG2Decode",
    "/RichMedia",
    "/Launch",
    "/EmbeddedFile",
    "/XFA",
];

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Count {
    pub count: u64,
    /// Occurrences that used `#xx` hex escapes.
    pub hex: u64,
}

impl Count {
    fn add(&mut self, hex: bool) {
        self.count += 1;
        if hex {
            self.hex += 1;
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Options {
    /// Collect every name (`-a`).
    pub all_names: bool,
    /// %%EOF, dates, entropy (`-e`).
    pub extra: bool,
    /// Produce a disarmed copy (`-d`).
    pub disarm: bool,
    /// Scan even without a `%PDF` header (`-f`).
    pub force: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Entropy {
    /// `None` when no bytes fall in this bucket (printed as N/A for streams).
    pub value: Option<f64>,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Extra {
    pub eof_count: u64,
    pub after_last_eof: u64,
    /// (date, preceding name), sorted by date.
    pub dates: Vec<(String, String)>,
    pub total: Entropy,
    pub inside_streams: Entropy,
    pub outside_streams: Entropy,
}

#[derive(Debug, Clone)]
pub struct Report {
    /// `None` = no `%PDF` in the first 1024 bytes.
    pub header: Option<String>,
    pub keywords: Vec<(&'static str, Count)>,
    /// Names that are not keywords (only with `all_names`).
    pub names: BTreeMap<String, Count>,
    pub extra: Option<Extra>,
    pub disarmed: Option<Vec<u8>>,
    /// (original, disarmed) name pairs, as printed by pdfid.py.
    pub disarm_log: Vec<(String, String)>,
    /// False if the file had no header and `force` was not set (nothing scanned).
    pub scanned: bool,
}

impl Report {
    pub fn is_pdf(&self) -> bool {
        self.header.is_some()
    }

    pub fn get(&self, key: &str) -> Count {
        self.keywords
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, c)| *c)
            .unwrap_or_default()
    }

    pub fn suspicious(&self) -> Vec<(&'static str, Count)> {
        self.keywords
            .iter()
            .filter(|(k, c)| c.count > 0 && (SUSPICIOUS.contains(k) || *k == COLORS_KEY))
            .copied()
            .collect()
    }
}

/// Relaxed header search like pdfid.py: `%PDF` within the first 1024 bytes; the
/// header line ends at the first CR/LF in the next 10 bytes. Returns the header
/// string (max. 10 chars) and the number of leading bytes consumed, which are
/// excluded from tokenizing.
pub fn find_header(data: &[u8]) -> (Option<String>, usize) {
    let win = &data[..data.len().min(1024)];
    let Some(idx) = find(win, b"%PDF") else {
        return (None, 0);
    };
    let mut end = idx + 13;
    for k in idx + 4..idx + 14 {
        if k >= win.len() {
            end = k;
            break;
        }
        if win[k] == b'\n' || win[k] == b'\r' {
            end = k;
            break;
        }
    }
    let end = end.min(win.len());
    let h = repr(&win[idx..end.min(idx + 10)]);
    (Some(h), end)
}

pub fn scan(data: &[u8], opts: &Options) -> Report {
    let (header, body_start) = find_header(data);
    let mut keywords: Vec<(&'static str, Count)> =
        KEYWORDS.iter().map(|k| (*k, Count::default())).collect();
    keywords.push((COLORS_KEY, Count::default()));

    if header.is_none() && !opts.force {
        return Report {
            header,
            keywords,
            names: BTreeMap::new(),
            extra: None,
            disarmed: None,
            disarm_log: Vec::new(),
            scanned: false,
        };
    }

    let mut st = State {
        opts,
        index: KEYWORDS
            .iter()
            .enumerate()
            .map(|(i, k)| (k.as_bytes(), i))
            .collect(),
        keywords,
        names: BTreeMap::new(),
        disarmed: opts.disarm.then(|| data.to_vec()),
        disarm_log: Vec::new(),
        word: Vec::with_capacity(64),
        slash: false,
        hex: false,
        escapes: Vec::new(),
        word_start: 0,
        last_name: Vec::new(),
        inside_stream: false,
        colors: 0,
        freq_all: [0; 256],
        freq_stream: [0; 256],
        eof: EofSm::default(),
        date: DateSm::default(),
        dates: Vec::new(),
    };

    // Header bytes count towards entropy (outside streams) but are not tokenized.
    if opts.extra {
        for &b in &data[..body_start] {
            st.freq_all[b as usize] += 1;
        }
    }

    let n = data.len();
    let mut i = body_start;
    while i < n {
        let b = data[i];
        if b.is_ascii_alphanumeric() {
            st.word.push(b);
        } else if st.slash && b == b'#' {
            if i + 2 < n && data[i + 1].is_ascii_hexdigit() && data[i + 2].is_ascii_hexdigit() {
                let (d1, d2) = (data[i + 1], data[i + 2]);
                st.word.push(hexval(d1) << 4 | hexval(d2));
                st.hex = true;
                st.escapes.push(i);
                if opts.extra {
                    st.entropy(d1);
                    st.entropy(d2);
                    st.eof.parse(d1);
                    st.eof.parse(d2);
                }
                st.post(b);
                i += 3;
                continue;
            }
            // Invalid escape: terminate the name, but stay in name mode (as pdfid.py).
            st.finish(i);
            st.word_start = i + 1;
        } else {
            st.check_colors();
            st.finish(i);
            st.slash = b == b'/';
            st.word_start = i + 1;
        }
        st.post(b);
        i += 1;
    }
    st.finish(n);

    let extra = opts.extra.then(|| {
        if st.eof.state == EofState::Eof {
            st.eof.count += 1;
            st.eof.after = 0;
        }
        let stream_bytes: u64 = st.freq_stream.iter().sum();
        let freq_out: [u64; 256] = std::array::from_fn(|j| st.freq_all[j] - st.freq_stream[j]);
        let mut dates = std::mem::take(&mut st.dates);
        dates.sort_by(|a, b| a.0.cmp(&b.0));
        Extra {
            eof_count: st.eof.count,
            after_last_eof: st.eof.after,
            dates,
            total: entropy(&st.freq_all),
            inside_streams: if stream_bytes == 0 {
                Entropy {
                    value: None,
                    bytes: 0,
                }
            } else {
                entropy(&st.freq_stream)
            },
            outside_streams: entropy(&freq_out),
        }
    });

    st.keywords.last_mut().unwrap().1.count = st.colors;
    Report {
        header,
        keywords: st.keywords,
        names: st.names,
        extra,
        disarmed: st.disarmed,
        disarm_log: st.disarm_log,
        scanned: true,
    }
}

struct State<'a> {
    opts: &'a Options,
    index: HashMap<&'static [u8], usize>,
    keywords: Vec<(&'static str, Count)>,
    names: BTreeMap<String, Count>,
    disarmed: Option<Vec<u8>>,
    disarm_log: Vec<(String, String)>,
    /// Current token, hex escapes decoded, without the leading '/'.
    word: Vec<u8>,
    slash: bool,
    hex: bool,
    /// Absolute offsets of '#' escapes inside the current name.
    escapes: Vec<usize>,
    /// Offset of the first byte of the current token.
    word_start: usize,
    /// Last name seen, without '/'.
    last_name: Vec<u8>,
    inside_stream: bool,
    colors: u64,
    freq_all: [u64; 256],
    freq_stream: [u64; 256],
    eof: EofSm,
    date: DateSm,
    dates: Vec<(String, String)>,
}

impl State<'_> {
    fn entropy(&mut self, b: u8) {
        self.freq_all[b as usize] += 1;
        if self.inside_stream {
            self.freq_stream[b as usize] += 1;
        }
    }

    /// Per-byte bookkeeping after tokenizing (dates, entropy, %%EOF).
    fn post(&mut self, b: u8) {
        if !self.opts.extra {
            return;
        }
        if let Some(d) = self.date.parse(b) {
            let name = if self.last_name.is_empty() {
                String::new()
            } else {
                format!("/{}", latin1(&self.last_name))
            };
            self.dates.push((d, name));
        }
        self.entropy(b);
        self.eof.parse(b);
    }

    /// CVE-2009-3459: a number > 2^24 following `/Colors`.
    fn check_colors(&mut self) {
        if self.last_name == b"Colors"
            && !self.word.is_empty()
            && self.word.iter().all(u8::is_ascii_digit)
        {
            let k = self
                .word
                .iter()
                .position(|&c| c != b'0')
                .unwrap_or(self.word.len());
            let d = &self.word[k..];
            let big = d.len() > 19
                || std::str::from_utf8(d)
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    > 1 << 24;
            if big {
                self.colors += 1;
            }
        }
    }

    /// Terminates the current token; `end` is the offset of the terminating byte.
    fn finish(&mut self, end: usize) {
        if !self.word.is_empty() {
            if self.slash {
                let mut key = Vec::with_capacity(self.word.len() + 1);
                key.push(b'/');
                key.extend_from_slice(&self.word);
                if let Some(&i) = self.index.get(key.as_slice()) {
                    self.keywords[i].1.add(self.hex);
                } else if self.opts.all_names {
                    self.names.entry(latin1(&key)).or_default().add(self.hex);
                }
                if let Some(buf) = self.disarmed.as_mut() {
                    if DISARM.iter().any(|d| d.as_bytes() == key.as_slice()) {
                        let before = latin1(&buf[self.word_start..end]);
                        swap_case(buf, self.word_start, end, &self.escapes);
                        let after = latin1(&buf[self.word_start..end]);
                        self.disarm_log.push((before, after));
                    }
                }
                self.last_name.clear();
                self.last_name.extend_from_slice(&self.word);
            } else {
                if let Some(&i) = self.index.get(self.word.as_slice()) {
                    self.keywords[i].1.add(false);
                }
                match self.word.as_slice() {
                    b"stream" => self.inside_stream = true,
                    b"endstream" => {
                        if self.inside_stream && self.opts.extra {
                            for &c in b"endstream" {
                                let f = &mut self.freq_stream[c as usize];
                                *f = f.saturating_sub(1);
                            }
                        }
                        self.inside_stream = false;
                    }
                    _ => {}
                }
            }
        }
        self.word.clear();
        self.hex = false;
        self.escapes.clear();
    }
}

#[derive(Default, PartialEq, Eq, Clone, Copy)]
enum EofState {
    #[default]
    Idle,
    P1,
    P2,
    E,
    O,
    Eof,
    EofCr,
    /// `%%EOF` followed by space/tab: next byte only resets.
    EofOther,
}

/// `%%EOF` counter, replicating pdfid.py's `cPDFEOF`.
#[derive(Default)]
struct EofSm {
    state: EofState,
    count: u64,
    after: u64,
}

impl EofSm {
    fn parse(&mut self, c: u8) {
        use EofState::*;
        if self.count > 0 {
            self.after += 1;
        }
        self.state = match (self.state, c) {
            (Idle, b'%') => P1,
            (P1, b'%') => P2,
            (P2, b'E') => E,
            (E, b'O') => O,
            (O, b'F') => Eof,
            (Eof, b'\n' | b'\r' | b' ' | b'\t') => {
                self.count += 1;
                self.after = 0;
                match c {
                    b'\n' => Idle,
                    b'\r' => EofCr,
                    _ => EofOther,
                }
            }
            (EofCr, b) => {
                if b == b'\n' {
                    self.after = 0;
                }
                Idle
            }
            _ => Idle,
        };
    }
}

/// PDF date detector (`D:YYYYMMDDHHmmSS[+-Z]HH'mm`), replicating `cPDFDate`.
#[derive(Default)]
struct DateSm {
    state: u8,
    digits1: String,
    tz: char,
    digits2: String,
}

impl DateSm {
    fn parse(&mut self, b: u8) -> Option<String> {
        let c = b as char;
        if c == 'D' {
            self.state = 1;
            return None;
        }
        match self.state {
            1 => {
                if c == ':' {
                    self.state = 2;
                    self.digits1.clear();
                } else {
                    self.state = 0;
                }
                None
            }
            2 => {
                if self.digits1.len() < 14 {
                    if c.is_ascii_digit() {
                        self.digits1.push(c);
                    } else {
                        self.state = 0;
                    }
                    None
                } else if c == '+' || c == '-' || c == 'Z' {
                    self.state = 3;
                    self.digits2.clear();
                    self.tz = c;
                    None
                } else if !c.is_ascii_digit() {
                    self.state = 0;
                    Some(format!("D:{}", self.digits1))
                } else {
                    self.state = 0;
                    None
                }
            }
            3 => {
                let l = self.digits2.len();
                if l < 2 {
                    if c.is_ascii_digit() {
                        self.digits2.push(c);
                    } else {
                        self.state = 0;
                    }
                    None
                } else if l == 2 {
                    if c == '\'' {
                        self.digits2.push(c);
                    } else {
                        self.state = 0;
                    }
                    None
                } else if c.is_ascii_digit() {
                    self.digits2.push(c);
                    if self.digits2.len() == 5 {
                        self.state = 0;
                        Some(format!("D:{}{}{}", self.digits1, self.tz, self.digits2))
                    } else {
                        None
                    }
                } else {
                    self.state = 0;
                    None
                }
            }
            _ => None,
        }
    }
}

/// Swaps ASCII case of a name in place. Hex escapes are re-encoded (lowercase,
/// like pdfid.py) with the case-swapped character, so `/J#61vaScript` cannot
/// survive disarming. Length is preserved, so xref offsets stay valid.
fn swap_case(buf: &mut [u8], start: usize, end: usize, escapes: &[usize]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut j = start;
    while j < end {
        if escapes.contains(&j) {
            let v = swap(hexval(buf[j + 1]) << 4 | hexval(buf[j + 2]));
            buf[j + 1] = HEX[(v >> 4) as usize];
            buf[j + 2] = HEX[(v & 0xF) as usize];
            j += 3;
        } else {
            buf[j] = swap(buf[j]);
            j += 1;
        }
    }
}

fn swap(b: u8) -> u8 {
    if b.is_ascii_lowercase() {
        b.to_ascii_uppercase()
    } else if b.is_ascii_uppercase() {
        b.to_ascii_lowercase()
    } else {
        b
    }
}

fn hexval(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// `repr(str).strip("'")` as pdfid.py does for the header (bytes mapped as Latin-1).
fn repr(b: &[u8]) -> String {
    let has_sq = b.contains(&b'\'');
    let quote = if has_sq && !b.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut s = String::new();
    s.push(quote);
    for &c in b {
        match c {
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\\' => s.push_str("\\\\"),
            b'\'' if quote == '\'' => s.push_str("\\'"),
            // Python's str.isprintable() for U+0000..U+00FF
            0x20..=0x7e | 0xa1..=0xac | 0xae..=0xff => s.push(c as char),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s.push(quote);
    s.trim_matches('\'').to_string()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn entropy(freq: &[u64; 256]) -> Entropy {
    let n: u64 = freq.iter().sum();
    let mut h = 0.0;
    if n > 0 {
        for &c in freq {
            if c > 0 {
                let p = c as f64 / n as f64;
                h -= p * p.log2();
            }
        }
    }
    Entropy {
        value: Some(h),
        bytes: n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R /AcroForm << >> >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /S /J#61vaScript /JS (app.alert(1)) >>\nendobj\n\
4 0 obj\n<< /Type /Page /Parent 2 0 R /CreationDate (D:20260101120000+01'00') >>\nendobj\n\
5 0 obj\n<< /Length 4 /DecodeParms << /Colors 16777217 >> >>\nstream\nABCD\nendstream\nendobj\n\
xref\ntrailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\nGARBAGE";

    fn opts() -> Options {
        Options {
            all_names: true,
            extra: true,
            disarm: true,
            force: false,
        }
    }

    #[test]
    fn counts_keywords() {
        let r = scan(SAMPLE, &opts());
        assert_eq!(r.header.as_deref(), Some("%PDF-1.7"));
        assert_eq!(r.get("obj").count, 5);
        assert_eq!(r.get("endobj").count, 5);
        assert_eq!(r.get("stream").count, 1);
        assert_eq!(r.get("/Page").count, 1);
        assert_eq!(r.get("/OpenAction").count, 1);
        assert_eq!(r.get("/AcroForm").count, 1);
        assert_eq!(r.get("/JS").count, 1);
        assert_eq!(r.get(COLORS_KEY).count, 1);
        assert!(
            !r.names.contains_key("/JS"),
            "keywords are not listed as names"
        );
        assert_eq!(r.names["/Type"].count, 3);
    }

    #[test]
    fn decodes_hex_obfuscation() {
        let r = scan(SAMPLE, &opts());
        assert_eq!(r.get("/JavaScript"), Count { count: 1, hex: 1 });
    }

    #[test]
    fn disarm_neutralizes_names() {
        let r = scan(SAMPLE, &opts());
        let d = r.disarmed.unwrap();
        assert_eq!(d.len(), SAMPLE.len());
        let again = scan(&d, &Options::default());
        for k in DISARM {
            assert_eq!(again.get(k).count, 0, "{k} survived disarm");
        }
        assert_eq!(again.get("/Page").count, 1);
        assert!(find(&d, b"/j#41VAsCRIPT").is_some());
        assert!(r.disarm_log.contains(&("JS".into(), "js".into())));
    }

    #[test]
    fn extra_info() {
        let e = scan(SAMPLE, &opts()).extra.unwrap();
        assert_eq!(e.eof_count, 1);
        assert_eq!(e.after_last_eof, 7);
        assert_eq!(
            e.dates,
            vec![("D:20260101120000+01'00".into(), "/CreationDate".into())]
        );
        assert_eq!(e.total.bytes, SAMPLE.len() as u64);
        assert_eq!(
            e.inside_streams.bytes + e.outside_streams.bytes,
            SAMPLE.len() as u64
        );
    }

    #[test]
    fn non_pdf_requires_force() {
        let data = b"hello /JavaScript";
        assert!(!scan(data, &Options::default()).scanned);
        let r = scan(
            data,
            &Options {
                force: true,
                ..Default::default()
            },
        );
        assert_eq!(r.get("/JavaScript").count, 1);
    }

    #[test]
    fn invalid_escape_keeps_name_mode() {
        let o = Options {
            all_names: true,
            ..Default::default()
        };
        let r = scan(b"%PDF-1.4\n/J#zzS /JS#", &o);
        assert_eq!(r.get("/JS").count, 1);
        assert!(r.names.contains_key("/J"));
        assert!(r.names.contains_key("/zzS"));
    }

    #[test]
    fn eof_variants() {
        let o = Options {
            extra: true,
            ..Default::default()
        };
        let e = scan(b"%PDF-1.4\n%%EOF\r\n%%EOF", &o).extra.unwrap();
        assert_eq!((e.eof_count, e.after_last_eof), (2, 0));
    }

    fn eof(input: &[u8]) -> (u64, u64) {
        let mut m = EofSm::default();
        input.iter().for_each(|&c| m.parse(c));
        (m.count, m.after)
    }

    #[test]
    fn eof_state_machine() {
        assert_eq!(eof(b"%%EOF\n"), (1, 0));
        assert_eq!(eof(b"%%EOF\nabc"), (1, 3));
        assert_eq!(eof(b"%%EOF\r\nab"), (1, 2));
        assert_eq!(
            eof(b"%%EOF\rab"),
            (1, 2),
            "CR then other: char after CR counted, not reset"
        );
        assert_eq!(eof(b"%%EOF xy"), (1, 2));
        assert_eq!(eof(b"%%EOF\tx"), (1, 1));
        assert_eq!(
            eof(b"%%EOF %%EOF\n"),
            (1, 6),
            "byte after space/tab only resets the token"
        );
        assert_eq!(eof(b"%%%EOF\n"), (0, 0), "third % resets, as in pdfid.py");
        assert_eq!(
            eof(b"%%EOX\n%%EOF"),
            (0, 0),
            "trailing %%EOF without EOL is handled at end of scan"
        );
        assert_eq!(eof(b"%x%%EOF\n%E"), (1, 2));
    }

    fn dates(input: &[u8]) -> Vec<String> {
        let mut m = DateSm::default();
        input.iter().filter_map(|&c| m.parse(c)).collect()
    }

    #[test]
    fn date_state_machine() {
        assert_eq!(dates(b"(D:20200101000000)"), ["D:20200101000000"]);
        assert_eq!(dates(b"D:20200101000000\""), ["D:20200101000000"]);
        assert_eq!(
            dates(b"D:20200101000000+01'00'"),
            ["D:20200101000000+01'00"]
        );
        assert_eq!(dates(b"D:20200101000000-05'30"), ["D:20200101000000-05'30"]);
        assert!(dates(b"D:20200101000000Z)").is_empty(), "Z needs an offset");
        assert!(dates(b"D:2020010100000)").is_empty(), "13 digits");
        assert!(dates(b"D:202001010000001)").is_empty(), "15 digits");
        assert!(dates(b"D:2020x101000000)").is_empty());
        assert!(dates(b"D;20200101000000)").is_empty());
        assert!(
            dates(b"D:20200101000000+0100").is_empty(),
            "missing apostrophe"
        );
        assert!(dates(b"D:20200101000000+0x'00").is_empty());
        assert!(dates(b"D:20200101000000+01'0x").is_empty());
        assert!(dates(b"D:20200101000000+x").is_empty());
        assert_eq!(
            dates(b"DD:20200101000000)"),
            ["D:20200101000000"],
            "D restarts"
        );
        assert_eq!(
            dates(b"D:2020D:20200101000000)"),
            ["D:20200101000000"],
            "D inside digits restarts"
        );
        assert_eq!(
            dates(b"D:20200101000000+01'0D:20210101000000)"),
            ["D:20210101000000"],
            "D during TZ restarts"
        );
    }

    #[test]
    fn header_detection() {
        assert_eq!(find_header(b"%PDF-1.7\nx"), (Some("%PDF-1.7".into()), 8));
        assert_eq!(find_header(b"%PDF-1.7\rx"), (Some("%PDF-1.7".into()), 8));
        assert_eq!(
            find_header(b"%PDF-1.4 /JS /JavaScript"),
            (Some("%PDF-1.4 /".into()), 13)
        );
        assert_eq!(
            find_header(b"%PDF-1"),
            (Some("%PDF-1".into()), 6),
            "short file: clamped"
        );
        assert_eq!(find_header(b"%PDF"), (Some("%PDF".into()), 4));
        assert_eq!(find_header(b"xx%PDF-2.0\n"), (Some("%PDF-2.0".into()), 10));
        assert_eq!(find_header(b"%PD"), (None, 0));
        assert_eq!(find_header(b""), (None, 0));
        // only the first 1024 bytes are searched
        let mut v = vec![b' '; 1020];
        v.extend_from_slice(b"%PDF-1.5\n");
        assert_eq!(
            find_header(&v),
            (Some("%PDF".into()), 1024),
            "header cut at window end"
        );
        let mut v = vec![b' '; 1021];
        v.extend_from_slice(b"%PDF-1.5\n");
        assert_eq!(find_header(&v), (None, 0));
    }

    #[test]
    fn header_repr_matches_python() {
        assert_eq!(repr(b"%PDF-1.7"), "%PDF-1.7");
        assert_eq!(repr(b"%PDF\t\\"), "%PDF\\t\\\\");
        assert_eq!(repr(b"%PDF\n\r"), "%PDF\\n\\r");
        assert_eq!(
            repr(b"%PDF\x00\x7f\x80\xa0\xad"),
            "%PDF\\x00\\x7f\\x80\\xa0\\xad"
        );
        assert_eq!(repr(b"%PDF\xa1\xe9\xff"), "%PDF\u{a1}\u{e9}\u{ff}");
        // contains ' only -> Python uses "..." quotes, which strip("'") keeps
        assert_eq!(repr(b"%PDF'1"), "\"%PDF'1\"");
        // contains ' and " -> '...' with escaped ', then strip("'")
        assert_eq!(repr(b"%PDF'\"1"), "%PDF\\'\"1");
        assert_eq!(repr(b"%PDF\"1"), "%PDF\"1");
    }

    #[test]
    fn report_helpers() {
        let r = scan(SAMPLE, &opts());
        assert!(r.is_pdf());
        assert_eq!(r.get("/DoesNotExist"), Count::default());
        let s: Vec<_> = r.suspicious().iter().map(|(k, _)| *k).collect();
        assert_eq!(s, ["/JS", "/JavaScript", "/OpenAction", COLORS_KEY]);
        assert!(!scan(b"nothing", &Options::default()).is_pdf());
    }

    #[test]
    fn options_off_produce_nothing_extra() {
        let r = scan(SAMPLE, &Options::default());
        assert!(
            r.names.is_empty()
                && r.extra.is_none()
                && r.disarmed.is_none()
                && r.disarm_log.is_empty()
        );
        assert!(r.scanned);
    }

    #[test]
    fn colors_threshold() {
        let c = |s: &[u8]| scan(s, &Options::default()).get(COLORS_KEY).count;
        assert_eq!(c(b"%PDF-1.4\n/Colors 16777216 "), 0, "exactly 2^24");
        assert_eq!(c(b"%PDF-1.4\n/Colors 16777217 "), 1);
        assert_eq!(
            c(b"%PDF-1.4\n/Colors 0000000000000000000000016777217 "),
            1,
            "leading zeros"
        );
        assert_eq!(c(b"%PDF-1.4\n/Colors 00000000000000000000000000000001 "), 0);
        assert_eq!(
            c(b"%PDF-1.4\n/Colors 99999999999999999999999 "),
            1,
            "beyond u64"
        );
        assert_eq!(c(b"%PDF-1.4\n/Colors 1e9 "), 0, "not all digits");
        assert_eq!(
            c(b"%PDF-1.4\n/Colors/99999999 "),
            1,
            "name token counts too (pdfid.py)"
        );
        assert_eq!(
            c(b"%PDF-1.4\n/Colors 3 99999999 "),
            1,
            "applies until the next name"
        );
        assert_eq!(c(b"%PDF-1.4\n/Colors 3 /X 99999999 "), 0);
        assert_eq!(
            c(b"%PDF-1.4\n/Colors 99999999"),
            0,
            "not checked at end of file (pdfid.py)"
        );
        assert_eq!(c(b"%PDF-1.4\n/Colors 99999999#"), 1);
    }

    #[test]
    fn hex_escape_edges() {
        let o = Options {
            all_names: true,
            ..Default::default()
        };
        let r = scan(b"%PDF-1.4\n/#4A#53 /a#2fb /x#4 /y#", &o);
        assert_eq!(r.get("/JS"), Count { count: 1, hex: 1 });
        assert!(
            r.names.contains_key("/a/b"),
            "escaped delimiter stays in the name"
        );
        assert!(r.names.contains_key("/x"));
        assert!(
            r.names.contains_key("/4"),
            "name mode survives invalid escape"
        );
        assert!(r.names.contains_key("/y"));
        // '#' outside a name is just a delimiter
        let r = scan(b"%PDF-1.4\nobj#4A", &o);
        assert_eq!(r.get("obj").count, 1);
    }

    #[test]
    fn swap_case_reencodes_escapes() {
        let mut b = b"/J#61#4a1x".to_vec();
        let n = b.len();
        swap_case(&mut b, 1, n, &[2, 5]);
        assert_eq!(b, b"/j#41#6a1X");
        assert_eq!(swap(b'1'), b'1');
        assert_eq!(hexval(b'g'), 0);
    }

    #[test]
    fn entropy_values() {
        let mut f = [0u64; 256];
        assert_eq!(
            entropy(&f),
            Entropy {
                value: Some(0.0),
                bytes: 0
            }
        );
        f[0] = 4;
        assert_eq!(entropy(&f).value, Some(0.0));
        f[1] = 4;
        assert_eq!(
            entropy(&f),
            Entropy {
                value: Some(1.0),
                bytes: 8
            }
        );
        let all: [u64; 256] = [1; 256];
        assert_eq!(entropy(&all).value, Some(8.0));
    }

    #[test]
    fn stream_entropy_attribution() {
        let o = Options {
            extra: true,
            ..Default::default()
        };
        // "endstream" bytes are moved out of the stream bucket
        let e = scan(b"%PDF-1.4\nstream\nAAAA\nendstream\n", &o)
            .extra
            .unwrap();
        assert_eq!(e.inside_streams.bytes, b"\nAAAA\n".len() as u64);
        // endstream without stream: nothing removed, no underflow
        let e = scan(b"%PDF-1.4\nendstream\n", &o).extra.unwrap();
        assert_eq!(
            e.inside_streams,
            Entropy {
                value: None,
                bytes: 0
            }
        );
        // unterminated stream: everything after "stream" counts as inside
        let e = scan(b"%PDF-1.4\nstream\nxyz", &o).extra.unwrap();
        assert_eq!(e.inside_streams.bytes, 4);
    }

    #[test]
    fn dates_are_sorted_and_named() {
        let o = Options {
            extra: true,
            ..Default::default()
        };
        let e = scan(b"%PDF-1.4\n(D:20300101000000)/B(D:20200101000000)", &o)
            .extra
            .unwrap();
        assert_eq!(
            e.dates,
            vec![
                ("D:20200101000000".to_string(), "/B".to_string()),
                ("D:20300101000000".to_string(), String::new()),
            ]
        );
    }
}
