//! Apache `.htaccess` alt kümesi: RewriteEngine/Base/Cond/Rule, Redirect/RedirectMatch, DirectoryIndex, Options, ErrorDocument.
//! Referans: OpenLiteSpeed `src/http/rewriteengine.cpp` (per-directory bağlam, koşul/yeniden yazma sırası).

use regex::{Regex, RegexBuilder};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_PASSES: usize = 10;

#[derive(Debug, Clone)]
enum CondTest {
    Regex(Regex),
    File,
    Dir,
    NonEmpty,
    ZeroSize,
    Link,
    Executable,
    SubrequestUrl,
    Eq(String),
    Lt(String),
    Gt(String),
    Le(String),
    Ge(String),
    NumEq(i64),
    NumNe(i64),
    NumLt(i64),
    NumGt(i64),
    NumLe(i64),
    NumGe(i64),
}

#[derive(Debug, Clone)]
struct Cond {
    test_string: String,
    negate: bool,
    test: CondTest,
    or: bool,
}

#[derive(Debug, Default, Clone)]
struct Flags {
    last: bool,
    end: bool,
    redirect: Option<u16>,
    qsa: bool,
    qsd: bool,
    forbidden: bool,
    gone: bool,
    skip: usize,
    env: Vec<(String, String)>,
    passthrough: bool,
    next: bool,
    escape_backrefs: bool,
    cookie: Vec<String>,
    content_type: Option<String>,
    handler: Option<String>,
    chain: bool,
}

#[derive(Debug, Clone)]
struct Rule {
    pattern: Regex,
    negate: bool,
    subst: String,
    flags: Flags,
    conds: Vec<Cond>,
}

#[derive(Debug, Clone)]
struct RedirectDir {
    status: u16,
    prefix: Option<String>,
    regex: Option<Regex>,
    target: String,
}

/// `<FilesMatch>` veya `<Files>` bloğundan üretilen erişim denetim kuralı.
#[derive(Debug, Clone)]
pub struct FilesMatchRule {
    pub pattern: Regex,
    pub denied: bool,
}

/// Apache / OpenLiteSpeed `RewriteOptions` direktifi yapılandırması.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RewriteOptions {
    pub inherit: bool,
    pub inherit_before: bool,
    pub inherit_down: bool,
    pub ignore_inherit: bool,
}

#[derive(Debug, Default, Clone)]
pub struct HtAccess {
    engine_on: bool,
    engine_explicit_off: bool,
    base: String,
    has_explicit_base: bool,
    rules: Vec<Rule>,
    redirects: Vec<RedirectDir>,
    pub options: RewriteOptions,
    pub directory_index: Vec<String>,
    pub disable_indexes: Option<bool>,
    pub error_documents: BTreeMap<u16, String>,
    pub files_matches: Vec<FilesMatchRule>,
    /// Ayrıştırılamayan satırlar (günlüğe yazılabilsin diye).
    pub warnings: Vec<String>,
}

/// `.htaccess` değerlendirmesi için genişletilmiş sonuç (ortam değişkenleri, çerezler, MIME/handler ve `[L]` durdurma bilgisi dahil).
#[derive(Debug, Clone, PartialEq)]
pub struct EvalResult {
    pub outcome: Outcome,
    pub env_vars: Vec<(String, String)>,
    pub cookies: Vec<String>,
    pub content_type: Option<String>,
    pub handler: Option<String>,
    pub passthrough: bool,
    pub matched_last: bool,
    pub engine_explicit_off: bool,
}

impl Default for EvalResult {
    fn default() -> Self {
        Self {
            outcome: Outcome::None,
            env_vars: Vec::new(),
            cookies: Vec::new(),
            content_type: None,
            handler: None,
            passthrough: false,
            matched_last: false,
            engine_explicit_off: false,
        }
    }
}

pub struct RequestCtx<'a> {
    /// Çözülmüş (yüzde-kodlaması açılmış) istek yolu, `/` ile başlar.
    pub path: &'a str,
    pub query: &'a str,
    pub host: &'a str,
    pub https: bool,
    pub method: &'a str,
    pub doc_root: &'a Path,
    pub remote_addr: &'a str,
    pub server_port: u16,
    pub headers: &'a [(String, String)],
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Değişiklik yok.
    None,
    /// İç yeniden yazma: yeni yol (`/` ile başlar, çözülmüş) ve sorgu.
    Rewritten {
        path: String,
        query: String,
    },
    Redirect {
        status: u16,
        location: String,
    },
    Forbidden,
    Gone,
}

/// Boşlukla ayır; "çift tırnak", 'tek tırnak' ve `\ ` (kaçışlı boşluk) desteklenir, diğer ters bölüler korunur.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote_char: Option<char> = None;
    let mut has = false;
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            q @ ('"' | '\'') if quote_char.is_none() => {
                quote_char = Some(q);
                has = true;
            }
            q if quote_char == Some(q) => {
                quote_char = None;
                has = true;
            }
            '\\' => {
                let nxt = it.peek().copied();
                match nxt {
                    Some(' ') | Some('"') | Some('\'')
                        if quote_char.is_none() || nxt == quote_char =>
                    {
                        cur.push(it.next().unwrap());
                        has = true;
                    }
                    _ => {
                        cur.push('\\');
                        has = true;
                    }
                }
            }
            c if c.is_whitespace() && quote_char.is_none() => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

const MAX_REGEX_LEN: usize = 2048;
const REGEX_SIZE_LIMIT: usize = 1024 * 1024; // 1 MB
const REGEX_DFA_SIZE_LIMIT: usize = 2 * 1024 * 1024; // 2 MB

fn build_regex(pat: &str, nocase: bool) -> Result<Regex, regex::Error> {
    if pat.len() > MAX_REGEX_LEN {
        return Err(regex::Error::Syntax(format!(
            "Regex deseni azami uzunluk sınırını aşıyor ({MAX_REGEX_LEN} karakter)"
        )));
    }
    RegexBuilder::new(pat)
        .case_insensitive(nocase)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
        .build()
}

fn glob_to_regex(glob: &str) -> String {
    let mut out = String::from("^");
    for c in glob.chars() {
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('$');
    out
}

fn parse_files_open(line: &str) -> Option<(bool, String)> {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("<filesmatch") {
        let rest = &trimmed[11..];
        if rest.starts_with(|c: char| c.is_whitespace() || c == '>') {
            let body = rest.trim_end_matches('>').trim();
            let pat = body.trim_matches('"').trim_matches('\'').trim();
            if !pat.is_empty() {
                return Some((true, pat.to_string()));
            }
        }
    } else if lower.starts_with("<files") {
        let rest = &trimmed[6..];
        if rest.starts_with(|c: char| c.is_whitespace() || c == '>') {
            let body = rest.trim_end_matches('>').trim();
            let pat = body.trim_matches('"').trim_matches('\'').trim();
            if !pat.is_empty() {
                return Some((false, pat.to_string()));
            }
        }
    }
    None
}

fn is_files_close(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    lower.starts_with("</filesmatch") || lower.starts_with("</files")
}

fn parse_cond_flags(raw: Option<&str>) -> (bool, bool) {
    let mut nc = false;
    let mut or = false;
    let Some(raw) = raw else { return (nc, or) };
    let inner = raw.trim().trim_start_matches('[').trim_end_matches(']');
    for part in inner.split(',') {
        let p = part.trim().to_ascii_lowercase();
        match p.as_str() {
            "nc" | "nocase" => nc = true,
            "or" | "ornext" => or = true,
            _ => {}
        }
    }
    (nc, or)
}

fn parse_flags(raw: Option<&str>) -> (Flags, bool, bool) {
    // (flags, nocase, noescape)
    let mut f = Flags::default();
    let mut nc = false;
    let mut ne = false;
    let Some(raw) = raw else { return (f, nc, ne) };
    let inner = raw.trim().trim_start_matches('[').trim_end_matches(']');
    for part in inner.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let (k, v) = match p.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim())),
            None => (p.to_ascii_lowercase(), None),
        };
        match k.as_str() {
            "l" | "last" => f.last = true,
            "end" => f.end = true,
            "r" | "redirect" => {
                f.redirect = Some(match v {
                    Some("permanent") => 301,
                    Some("temp") => 302,
                    Some("seeother") => 303,
                    Some(n) => n.parse().unwrap_or(302),
                    None => 302,
                })
            }
            "nc" | "nocase" => nc = true,
            "qsa" | "qsappend" => f.qsa = true,
            "qsd" | "qsdiscard" => f.qsd = true,
            "f" | "forbidden" => f.forbidden = true,
            "g" | "gone" => f.gone = true,
            "ne" | "noescape" => ne = true,
            "b" | "escape" => f.escape_backrefs = true,
            "pt" | "passthrough" => f.passthrough = true,
            "n" | "next" => f.next = true,
            "s" | "skip" => f.skip = v.and_then(|n| n.parse().ok()).unwrap_or(0),
            "c" | "chain" => f.chain = true,
            "e" | "env" => {
                if let Some(raw_env) = v {
                    if let Some((ek, ev)) = raw_env.split_once(':') {
                        let key = ek.trim();
                        if !key.is_empty() && !key.starts_with('!') {
                            f.env.push((key.to_string(), ev.to_string()));
                        }
                    } else if !raw_env.is_empty() && !raw_env.starts_with('!') {
                        f.env.push((raw_env.to_string(), String::new()));
                    }
                }
            }
            "co" | "cookie" => {
                if let Some(c) = v {
                    f.cookie.push(c.to_string());
                }
            }
            "t" | "type" => {
                if let Some(t) = v {
                    f.content_type = Some(t.to_string());
                }
            }
            "h" | "handler" => {
                if let Some(h) = v {
                    f.handler = Some(h.to_string());
                }
            }
            _ => {}
        }
    }
    (f, nc, ne)
}

fn is_supported_module(name: &str) -> bool {
    matches!(
        name.trim().trim_matches('"').to_ascii_lowercase().as_str(),
        "mod_rewrite.c"
            | "mod_rewrite.so"
            | "mod_rewrite"
            | "rewrite_module"
            | "mod_alias.c"
            | "mod_alias.so"
            | "mod_alias"
            | "alias_module"
            | "mod_dir.c"
            | "mod_dir.so"
            | "mod_dir"
            | "dir_module"
            | "mod_negotiation.c"
            | "mod_negotiation.so"
            | "mod_negotiation"
            | "negotiation_module"
            | "mod_autoindex.c"
            | "mod_autoindex.so"
            | "mod_autoindex"
            | "autoindex_module"
            | "core.c"
    )
}

fn parse_ifmodule_open(line: &str) -> Option<bool> {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("<ifmodule") {
        return None;
    }
    let rest = &trimmed[9..];
    if !rest.is_empty() && !rest.starts_with(|c: char| c.is_whitespace() || c == '>') {
        return None;
    }
    let body = rest.trim_end_matches('>').trim();
    if body.is_empty() {
        return Some(false);
    }
    let token = body.split_whitespace().next().unwrap_or("");
    let (negate, mod_name) = match token.strip_prefix('!') {
        Some(m) => (true, m.trim()),
        None => (false, token),
    };
    let supported = is_supported_module(mod_name);
    Some(if negate { !supported } else { supported })
}

fn is_ifmodule_close(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    lower.starts_with("</ifmodule")
}

fn upsert_env(env_vars: &mut Vec<(String, String)>, key: String, val: String) {
    if let Some((_, existing)) = env_vars.iter_mut().find(|(k, _)| *k == key) {
        *existing = val;
    } else {
        env_vars.push((key, val));
    }
}

/// Dış `[[vhost.rewrite.rules]]` gibi motorların kullanabilmesi için bayrak metnini ve
/// `$N` / `%{VAR}` yer tutucularını açar.
pub(crate) fn expand_request_vars(
    s: &str,
    rule_caps: Option<&Vec<String>>,
    cond_caps: Option<&Vec<String>>,
    ctx: &RequestCtx,
    path: &str,
    query: &str,
) -> String {
    expand(s, rule_caps, cond_caps, ctx, path, query, &[], false)
}

pub(crate) fn absolutize_location(loc: &str, ctx: &RequestCtx) -> String {
    absolutize(loc, ctx)
}

fn status_word(w: &str) -> Option<u16> {
    match w.to_ascii_lowercase().as_str() {
        "permanent" => Some(301),
        "temp" => Some(302),
        "seeother" => Some(303),
        "gone" => Some(410),
        n => n
            .parse::<u16>()
            .ok()
            .filter(|c| (300..400).contains(c) || *c == 410),
    }
}

impl HtAccess {
    pub fn parse(text: &str) -> HtAccess {
        let mut h = HtAccess {
            base: "/".to_string(),
            ..Default::default()
        };
        // satır devamı
        let joined = text.replace("\r\n", "\n").replace("\\\n", " ");
        let mut pending: Vec<Cond> = Vec::new();
        let mut ifmodule_stack: Vec<bool> = Vec::new();
        let mut current_files_ctx: Option<(Regex, bool)> = None;
        for raw in joined.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(active) = parse_ifmodule_open(line) {
                pending.clear();
                ifmodule_stack.push(active);
                continue;
            }
            if is_ifmodule_close(line) {
                pending.clear();
                let _ = ifmodule_stack.pop();
                continue;
            }
            if ifmodule_stack.iter().any(|&active| !active) {
                continue;
            }

            if let Some((is_match, pat)) = parse_files_open(line) {
                pending.clear();
                let re_res = if is_match {
                    build_regex(&pat, true)
                } else {
                    build_regex(&glob_to_regex(&pat), true)
                };
                match re_res {
                    Ok(r) => current_files_ctx = Some((r, true)),
                    Err(e) => {
                        h.warnings
                            .push(format!("FilesMatch regex hatası ({e}): {line}"));
                        current_files_ctx = None;
                    }
                }
                continue;
            }
            if is_files_close(line) {
                pending.clear();
                if let Some((pattern, denied)) = current_files_ctx.take() {
                    h.files_matches.push(FilesMatchRule { pattern, denied });
                }
                continue;
            }
            if let Some((_, ref mut denied)) = current_files_ctx {
                let lower_line = line.to_ascii_lowercase();
                if lower_line.contains("deny from all")
                    || lower_line.contains("require all denied")
                    || lower_line.starts_with("deny")
                {
                    *denied = true;
                    continue;
                } else if lower_line.contains("allow from all")
                    || lower_line.contains("require all granted")
                    || lower_line.starts_with("allow")
                {
                    *denied = false;
                    continue;
                }
                if lower_line.starts_with("order") {
                    continue;
                }
            }

            let toks = tokenize(line);
            if toks.is_empty() {
                continue;
            }
            match toks[0].to_ascii_lowercase().as_str() {
                "rewriteengine" => {
                    let val = toks.get(1).map(|v| v.as_str()).unwrap_or("");
                    let is_on = val.eq_ignore_ascii_case("on") || val == "1" || val.eq_ignore_ascii_case("true");
                    let is_off = val.eq_ignore_ascii_case("off") || val == "0" || val.eq_ignore_ascii_case("false");
                    h.engine_on = is_on;
                    h.engine_explicit_off = is_off;
                }
                "rewriteoptions" => {
                    for opt in toks.iter().skip(1) {
                        let lower = opt.to_ascii_lowercase();
                        match lower.as_str() {
                            "inherit" => h.options.inherit = true,
                            "inheritbefore" | "inherit-before" => h.options.inherit_before = true,
                            "inheritdown" | "inherit-down" => h.options.inherit_down = true,
                            "ignoreinherit" | "ignore-inherit" => h.options.ignore_inherit = true,
                            _ => {}
                        }
                    }
                }
                "rewritebase" => {
                    if let Some(b) = toks.get(1) {
                        let mut b = b.clone();
                        if !b.starts_with('/') {
                            b.insert(0, '/');
                        }
                        if !b.ends_with('/') {
                            b.push('/');
                        }
                        h.base = b;
                        h.has_explicit_base = true;
                    }
                }
                "rewritecond" => {
                    if toks.len() < 3 {
                        h.warnings.push(format!("RewriteCond eksik: {line}"));
                        continue;
                    }
                    let mut pat = toks[2].clone();
                    let mut flags_idx = 3usize;

                    let is_binary_op = |p: &str| {
                        let op = p.strip_prefix('!').unwrap_or(p);
                        matches!(
                            op,
                            "-eq"
                                | "-ne"
                                | "-lt"
                                | "-gt"
                                | "-le"
                                | "-ge"
                                | "<="
                                | ">="
                                | "=="
                                | "="
                                | "<"
                                | ">"
                        )
                    };

                    if is_binary_op(&pat) && toks.len() > 3 && !toks[3].starts_with('[') {
                        pat.push_str(&toks[3]);
                        flags_idx = 4;
                    }

                    let joined_flags: Option<String> = toks.get(flags_idx).and_then(|first| {
                        if first.starts_with('[') {
                            if !first.ends_with(']') {
                                let mut buf = first.clone();
                                for tok in toks.iter().skip(flags_idx + 1) {
                                    buf.push(' ');
                                    buf.push_str(tok);
                                    if tok.ends_with(']') {
                                        break;
                                    }
                                }
                                Some(buf)
                            } else {
                                Some(first.clone())
                            }
                        } else {
                            None
                        }
                    });
                    let (nc, or) = parse_cond_flags(joined_flags.as_deref());
                    let mut pat_str = pat.as_str();
                    let negate = pat_str.starts_with('!');
                    if negate {
                        pat_str = &pat_str[1..];
                    }
                    let test = match pat_str {
                        "-f" | "-F" => Some(CondTest::File),
                        "-d" | "-D" => Some(CondTest::Dir),
                        "-s" | "-S" => Some(CondTest::NonEmpty),
                        "-z" | "-Z" => Some(CondTest::ZeroSize),
                        "-l" | "-L" | "-h" | "-H" => Some(CondTest::Link),
                        "-x" | "-X" => Some(CondTest::Executable),
                        "-u" | "-U" => Some(CondTest::SubrequestUrl),
                        p if p.starts_with("-eq") => {
                            let num = p[3..].trim().parse::<i64>().unwrap_or(0);
                            Some(CondTest::NumEq(num))
                        }
                        p if p.starts_with("-ne") => {
                            let num = p[3..].trim().parse::<i64>().unwrap_or(0);
                            Some(CondTest::NumNe(num))
                        }
                        p if p.starts_with("-lt") => {
                            let num = p[3..].trim().parse::<i64>().unwrap_or(0);
                            Some(CondTest::NumLt(num))
                        }
                        p if p.starts_with("-gt") => {
                            let num = p[3..].trim().parse::<i64>().unwrap_or(0);
                            Some(CondTest::NumGt(num))
                        }
                        p if p.starts_with("-le") => {
                            let num = p[3..].trim().parse::<i64>().unwrap_or(0);
                            Some(CondTest::NumLe(num))
                        }
                        p if p.starts_with("-ge") => {
                            let num = p[3..].trim().parse::<i64>().unwrap_or(0);
                            Some(CondTest::NumGe(num))
                        }
                        p if p.starts_with("<=") => Some(CondTest::Le(p[2..].to_string())),
                        p if p.starts_with(">=") => Some(CondTest::Ge(p[2..].to_string())),
                        p if p.starts_with("==") => Some(CondTest::Eq(p[2..].to_string())),
                        p if p.starts_with('=') => Some(CondTest::Eq(p[1..].to_string())),
                        p if p.starts_with('<') => Some(CondTest::Lt(p[1..].to_string())),
                        p if p.starts_with('>') => Some(CondTest::Gt(p[1..].to_string())),
                        p => match build_regex(p, nc) {
                            Ok(r) => Some(CondTest::Regex(r)),
                            Err(e) => {
                                h.warnings
                                    .push(format!("RewriteCond regex hatası ({e}): {line}"));
                                None
                            }
                        },
                    };
                    match test {
                        Some(t) => pending.push(Cond {
                            test_string: toks[1].clone(),
                            negate,
                            test: t,
                            or,
                        }),
                        None => pending.push(Cond {
                            // geçersiz koşul kuralı etkisiz kılar
                            test_string: String::new(),
                            negate: false,
                            test: CondTest::Eq("\u{0}".into()),
                            or: false,
                        }),
                    }
                }
                "rewriterule" => {
                    if toks.len() < 3 {
                        h.warnings.push(format!("RewriteRule eksik: {line}"));
                        pending.clear();
                        continue;
                    }
                    let joined_flags: Option<String> = toks.get(3).map(|first| {
                        if first.starts_with('[') && !first.ends_with(']') {
                            let mut buf = first.clone();
                            for tok in toks.iter().skip(4) {
                                buf.push(' ');
                                buf.push_str(tok);
                                if tok.ends_with(']') {
                                    break;
                                }
                            }
                            buf
                        } else {
                            first.clone()
                        }
                    });
                    let (flags, nc, _ne) = parse_flags(joined_flags.as_deref());
                    let mut pat = toks[1].as_str();
                    let negate = pat.starts_with('!');
                    if negate {
                        pat = &pat[1..];
                    }
                    match build_regex(pat, nc) {
                        Ok(r) => h.rules.push(Rule {
                            pattern: r,
                            negate,
                            subst: toks[2].clone(),
                            flags,
                            conds: std::mem::take(&mut pending),
                        }),
                        Err(e) => {
                            h.warnings
                                .push(format!("RewriteRule regex hatası ({e}): {line}"));
                            pending.clear();
                        }
                    }
                }
                d @ ("redirect" | "redirectpermanent" | "redirecttemp" | "redirectmatch") => {
                    let is_match = d == "redirectmatch";
                    let mut args: Vec<&String> = toks.iter().skip(1).collect();
                    let mut status = match d {
                        "redirectpermanent" => 301,
                        _ => 302,
                    };
                    if let Some(first) = args.first() {
                        if let Some(code) = status_word(first) {
                            if args.len() >= 2 {
                                status = code;
                                args.remove(0);
                            }
                        }
                    }
                    if status == 410 {
                        if let Some(p) = args.first() {
                            h.redirects.push(RedirectDir {
                                status,
                                prefix: if is_match { None } else { Some((*p).clone()) },
                                regex: if is_match {
                                    build_regex(p, false).ok()
                                } else {
                                    None
                                },
                                target: String::new(),
                            });
                        }
                        continue;
                    }
                    if args.len() < 2 {
                        h.warnings.push(format!("{} eksik: {line}", toks[0]));
                        continue;
                    }
                    if is_match {
                        match build_regex(args[0], false) {
                            Ok(r) => h.redirects.push(RedirectDir {
                                status,
                                prefix: None,
                                regex: Some(r),
                                target: args[1].clone(),
                            }),
                            Err(e) => h
                                .warnings
                                .push(format!("RedirectMatch regex hatası ({e}): {line}")),
                        }
                    } else {
                        h.redirects.push(RedirectDir {
                            status,
                            prefix: Some(args[0].clone()),
                            regex: None,
                            target: args[1].clone(),
                        });
                    }
                }
                "directoryindex" => {
                    h.directory_index = toks.iter().skip(1).cloned().collect();
                }
                "options" => {
                    for opt in toks.iter().skip(1) {
                        if opt.eq_ignore_ascii_case("-indexes") {
                            h.disable_indexes = Some(true);
                        } else if opt.eq_ignore_ascii_case("+indexes")
                            || opt.eq_ignore_ascii_case("indexes")
                        {
                            h.disable_indexes = Some(false);
                        }
                    }
                }
                "errordocument" => {
                    if toks.len() >= 3 {
                        if let Ok(code) = toks[1].parse::<u16>() {
                            let target = toks[2..].join(" ");
                            if !target.is_empty() {
                                h.error_documents.insert(code, target);
                            }
                        } else {
                            h.warnings
                                .push(format!("ErrorDocument geçersiz kod: {line}"));
                        }
                    } else {
                        h.warnings.push(format!("ErrorDocument eksik: {line}"));
                    }
                }
                _ => {}
            }
        }
        h
    }

    pub fn is_empty(&self) -> bool {
        !self.engine_on
            && self.redirects.is_empty()
            && self.directory_index.is_empty()
            && self.disable_indexes.is_none()
            && self.error_documents.is_empty()
            && self.files_matches.is_empty()
    }

    pub fn evaluate(&self, ctx: &RequestCtx) -> Outcome {
        self.evaluate_in_dir(ctx, "/").outcome
    }

    /// `.htaccess` dosyasını bulunduğu dizin öneki (`dir_prefix`, örn. `"/"` veya `"/sub/"`) bağlamında
    /// değerlendirir ve `Outcome` ile birlikte `[E=KEY:VAL]` değişkenlerini döndürür.
    pub fn evaluate_in_dir(&self, ctx: &RequestCtx, dir_prefix: &str) -> EvalResult {
        let mut env_vars: Vec<(String, String)> = Vec::new();
        let mut cookies: Vec<String> = Vec::new();
        let mut content_type: Option<String> = None;
        let mut handler: Option<String> = None;
        let mut passthrough = false;

        // <FilesMatch> ve <Files> erişim denetimi
        let filename = ctx.path.rsplit('/').next().unwrap_or("");
        if !filename.is_empty() {
            for rule in &self.files_matches {
                if rule.pattern.is_match(filename) && rule.denied {
                    return EvalResult {
                        outcome: Outcome::Forbidden,
                        env_vars,
                        cookies,
                        content_type,
                        handler,
                        passthrough,
                        matched_last: true,
                        engine_explicit_off: self.engine_explicit_off,
                    };
                }
            }
        }

        // mod_alias: Redirect / RedirectMatch
        for r in &self.redirects {
            let hit = if let Some(p) = &r.prefix {
                ctx.path == p
                    || (ctx.path.starts_with(p.as_str())
                        && (p.ends_with('/') || ctx.path[p.len()..].starts_with('/')))
            } else if let Some(re) = &r.regex {
                re.is_match(ctx.path)
            } else {
                false
            };
            if !hit {
                continue;
            }
            if r.status == 410 {
                return EvalResult {
                    outcome: Outcome::Gone,
                    env_vars,
                    cookies,
                    content_type,
                    handler,
                    passthrough,
                    matched_last: true,
                    engine_explicit_off: self.engine_explicit_off,
                };
            }
            let location = if let Some(p) = &r.prefix {
                format!(
                    "{}{}",
                    r.target.trim_end_matches('/'),
                    &ctx.path[p.len().min(ctx.path.len())..]
                )
            } else {
                let caps: Vec<String> = r
                    .regex
                    .as_ref()
                    .and_then(|re| re.captures(ctx.path))
                    .map(|c| {
                        c.iter()
                            .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                            .collect()
                    })
                    .unwrap_or_default();
                expand(
                    &r.target,
                    Some(&caps),
                    None,
                    ctx,
                    ctx.path,
                    ctx.query,
                    &env_vars,
                    false,
                )
            };
            return EvalResult {
                outcome: Outcome::Redirect {
                    status: r.status,
                    location: absolutize(&location, ctx),
                },
                env_vars,
                cookies,
                content_type,
                handler,
                passthrough,
                matched_last: true,
                engine_explicit_off: self.engine_explicit_off,
            };
        }
        if !self.engine_on {
            return EvalResult {
                outcome: Outcome::None,
                env_vars,
                cookies,
                content_type,
                handler,
                passthrough,
                matched_last: false,
                engine_explicit_off: self.engine_explicit_off,
            };
        }

        let norm_dir = if dir_prefix.is_empty() {
            "/"
        } else {
            dir_prefix
        };
        let match_base = if self.has_explicit_base {
            self.base.as_str()
        } else {
            norm_dir
        };
        let subst_base = if self.has_explicit_base {
            self.base.as_str()
        } else {
            norm_dir
        };

        let mut path = ctx.path.to_string();
        let mut query = ctx.query.to_string();
        let mut changed = false;
        let mut matched_last = false;
        let mut history: Vec<(String, String)> = Vec::with_capacity(MAX_PASSES + 1);
        history.push((path.clone(), query.clone()));

        for pass in 0..MAX_PASSES {
            let mut pass_changed = false;
            let mut i = 0usize;
            while i < self.rules.len() {
                let rule = &self.rules[i];
                // per-directory: yol, RewriteBase/dizin önekinden arındırılıp başındaki / atılır
                let mut target = path.as_str();
                if match_base != "/" {
                    let base_prefix = match_base.trim_end_matches('/');
                    if target == base_prefix || target.starts_with(match_base) {
                        target = &target[base_prefix.len()..];
                    }
                }
                let target = target.trim_start_matches('/');

                let caps_opt = rule.pattern.captures(target);
                let matched = caps_opt.is_some() != rule.negate;
                if !matched {
                    i += 1;
                    continue;
                }
                let rule_caps: Vec<String> = caps_opt
                    .map(|c| {
                        c.iter()
                            .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                            .collect()
                    })
                    .unwrap_or_default();

                let (conds_ok, cond_caps) =
                    self.check_conds(rule, ctx, &path, &query, &rule_caps, &env_vars);
                if !conds_ok {
                    i += 1;
                    continue;
                }

                for (ek, ev) in &rule.flags.env {
                    let expanded_val = expand(
                        ev,
                        Some(&rule_caps),
                        cond_caps.as_ref(),
                        ctx,
                        &path,
                        &query,
                        &env_vars,
                        rule.flags.escape_backrefs,
                    );
                    upsert_env(&mut env_vars, ek.clone(), expanded_val);
                }

                for c in &rule.flags.cookie {
                    let expanded_cookie = expand(
                        c,
                        Some(&rule_caps),
                        cond_caps.as_ref(),
                        ctx,
                        &path,
                        &query,
                        &env_vars,
                        rule.flags.escape_backrefs,
                    );
                    cookies.push(expanded_cookie);
                }

                if let Some(ct) = &rule.flags.content_type {
                    let exp = expand(
                        ct,
                        Some(&rule_caps),
                        cond_caps.as_ref(),
                        ctx,
                        &path,
                        &query,
                        &env_vars,
                        rule.flags.escape_backrefs,
                    );
                    content_type = Some(exp);
                }

                if let Some(h) = &rule.flags.handler {
                    let exp = expand(
                        h,
                        Some(&rule_caps),
                        cond_caps.as_ref(),
                        ctx,
                        &path,
                        &query,
                        &env_vars,
                        rule.flags.escape_backrefs,
                    );
                    handler = Some(exp);
                }

                if rule.flags.passthrough {
                    passthrough = true;
                }

                if rule.flags.forbidden {
                    return EvalResult {
                        outcome: Outcome::Forbidden,
                        env_vars,
                        cookies,
                        content_type,
                        handler,
                        passthrough,
                        matched_last: true,
                        engine_explicit_off: self.engine_explicit_off,
                    };
                }
                if rule.flags.gone {
                    return EvalResult {
                        outcome: Outcome::Gone,
                        env_vars,
                        cookies,
                        content_type,
                        handler,
                        passthrough,
                        matched_last: true,
                        engine_explicit_off: self.engine_explicit_off,
                    };
                }

                let expanded = expand(
                    &rule.subst,
                    Some(&rule_caps),
                    cond_caps.as_ref(),
                    ctx,
                    &path,
                    &query,
                    &env_vars,
                    rule.flags.escape_backrefs,
                );
                let mut new_path = path.clone();
                let mut new_query = query.clone();
                let external = expanded.starts_with("http://")
                    || expanded.starts_with("https://")
                    || expanded.starts_with("//");

                if expanded != "-" {
                    let (p_part, q_part) = match expanded.split_once('?') {
                        Some((p, q)) => (p.to_string(), Some(q.to_string())),
                        None => (expanded.clone(), None),
                    };
                    if external {
                        let mut loc = p_part;
                        let q = match (q_part, rule.flags.qsa, query.is_empty()) {
                            (Some(q), true, false) => format!("{q}&{query}"),
                            (Some(q), _, _) => q,
                            (None, _, _) if rule.flags.qsd => String::new(),
                            (None, _, _) => query.clone(),
                        };
                        if !q.is_empty() {
                            loc.push('?');
                            loc.push_str(&q);
                        }
                        let abs_loc = absolutize(&loc, ctx);
                        let current_abs = absolutize(ctx.path, ctx);
                        let current_with_q = if query.is_empty() {
                            current_abs.clone()
                        } else {
                            format!("{current_abs}?{query}")
                        };
                        if abs_loc == current_abs || abs_loc == current_with_q {
                            return EvalResult {
                                outcome: Outcome::None,
                                env_vars,
                                cookies,
                                content_type,
                                handler,
                                passthrough,
                                matched_last: true,
                                engine_explicit_off: self.engine_explicit_off,
                            };
                        }
                        return EvalResult {
                            outcome: Outcome::Redirect {
                                status: rule.flags.redirect.unwrap_or(302),
                                location: abs_loc,
                            },
                            env_vars,
                            cookies,
                            content_type,
                            handler,
                            passthrough,
                            matched_last: true,
                            engine_explicit_off: self.engine_explicit_off,
                        };
                    }
                    new_path = if p_part.starts_with('/') {
                        p_part
                    } else {
                        format!("{}{}", subst_base, p_part)
                    };
                    new_query = match (q_part, rule.flags.qsa, query.is_empty()) {
                        (Some(q), true, false) => format!("{q}&{query}"),
                        (Some(q), _, _) => q,
                        (None, _, _) if rule.flags.qsd => String::new(),
                        (None, _, _) => query.clone(),
                    };
                }

                if let Some(code) = rule.flags.redirect {
                    let mut loc = new_path.clone();
                    if !new_query.is_empty() {
                        loc.push('?');
                        loc.push_str(&new_query);
                    }
                    let abs_loc = absolutize(&loc, ctx);
                    let current_abs = absolutize(ctx.path, ctx);
                    let current_with_q = if ctx.query.is_empty() {
                        current_abs.clone()
                    } else {
                        format!("{current_abs}?{}", ctx.query)
                    };
                    if abs_loc == current_abs || abs_loc == current_with_q {
                        return EvalResult {
                            outcome: Outcome::None,
                            env_vars,
                            cookies,
                            content_type,
                            handler,
                            passthrough,
                            matched_last: true,
                            engine_explicit_off: self.engine_explicit_off,
                        };
                    }
                    return EvalResult {
                        outcome: Outcome::Redirect {
                            status: code,
                            location: abs_loc,
                        },
                        env_vars,
                        cookies,
                        content_type,
                        handler,
                        passthrough,
                        matched_last: true,
                        engine_explicit_off: self.engine_explicit_off,
                    };
                }

                if new_path != path || new_query != query {
                    // Yönlendirme döngüsü (Rewrite Loop) tespiti ve DoS koruması
                    if history
                        .iter()
                        .any(|(p, q)| p == &new_path && q == &new_query)
                    {
                        return EvalResult {
                            outcome: Outcome::Forbidden,
                            env_vars,
                            cookies,
                            content_type,
                            handler,
                            passthrough,
                            matched_last: true,
                            engine_explicit_off: self.engine_explicit_off,
                        };
                    }
                    history.push((new_path.clone(), new_query.clone()));
                    path = new_path;
                    query = new_query;
                    changed = true;
                    pass_changed = true;
                }
                if rule.flags.end {
                    let outcome = if changed {
                        Outcome::Rewritten { path, query }
                    } else {
                        Outcome::None
                    };
                    return EvalResult {
                        outcome,
                        env_vars,
                        cookies,
                        content_type,
                        handler,
                        passthrough,
                        matched_last: true,
                        engine_explicit_off: self.engine_explicit_off,
                    };
                }
                if rule.flags.last {
                    matched_last = true;
                    break;
                }
                if rule.flags.next {
                    i = 0;
                    continue;
                }
                i += 1 + rule.flags.skip;
            }
            if !pass_changed {
                break;
            }
            if pass == MAX_PASSES - 1 && pass_changed {
                // Azami geçiş sınırı (MAX_PASSES) aşıldı -> Sonsuz döngü DoS engeli
                return EvalResult {
                    outcome: Outcome::Forbidden,
                    env_vars,
                    cookies,
                    content_type,
                    handler,
                    passthrough,
                    matched_last: true,
                    engine_explicit_off: self.engine_explicit_off,
                };
            }
        }

        let outcome = if changed {
            Outcome::Rewritten { path, query }
        } else {
            Outcome::None
        };
        EvalResult {
            outcome,
            env_vars,
            cookies,
            content_type,
            handler,
            passthrough,
            matched_last,
            engine_explicit_off: self.engine_explicit_off,
        }
    }

    pub fn engine_on(&self) -> bool {
        self.engine_on
    }

    pub fn rules_len(&self) -> usize {
        self.rules.len()
    }

    fn check_conds(
        &self,
        rule: &Rule,
        ctx: &RequestCtx,
        path: &str,
        query: &str,
        rule_caps: &Vec<String>,
        env_vars: &[(String, String)],
    ) -> (bool, Option<Vec<String>>) {
        let mut cond_caps: Option<Vec<String>> = None;
        let mut group = false;
        for c in &rule.conds {
            let ts = expand(
                &c.test_string,
                Some(rule_caps),
                cond_caps.as_ref(),
                ctx,
                path,
                query,
                env_vars,
                false,
            );
            let ts = ts.replace("%{QUERY_STRING}", query);
            let (mut r, caps) = match &c.test {
                CondTest::Regex(re) => match re.captures(&ts) {
                    Some(m) => (
                        true,
                        Some(
                            m.iter()
                                .map(|x| x.map(|x| x.as_str().to_string()).unwrap_or_default())
                                .collect::<Vec<_>>(),
                        ),
                    ),
                    None => (false, None),
                },
                CondTest::File => {
                    let p = if Path::new(&ts).is_absolute() {
                        PathBuf::from(&ts)
                    } else {
                        ctx.doc_root.join(&ts)
                    };
                    (p.is_file(), None)
                }
                CondTest::Dir => {
                    let p = if Path::new(&ts).is_absolute() {
                        PathBuf::from(&ts)
                    } else {
                        ctx.doc_root.join(&ts)
                    };
                    (p.is_dir(), None)
                }
                CondTest::NonEmpty => {
                    let p = if Path::new(&ts).is_absolute() {
                        PathBuf::from(&ts)
                    } else {
                        ctx.doc_root.join(&ts)
                    };
                    (
                        std::fs::metadata(&p)
                            .map(|m| m.is_file() && m.len() > 0)
                            .unwrap_or(false),
                        None,
                    )
                }
                CondTest::ZeroSize => {
                    let p = if Path::new(&ts).is_absolute() {
                        PathBuf::from(&ts)
                    } else {
                        ctx.doc_root.join(&ts)
                    };
                    (
                        std::fs::metadata(&p)
                            .map(|m| m.is_file() && m.len() == 0)
                            .unwrap_or(false)
                            || ts.is_empty(),
                        None,
                    )
                }
                CondTest::Link => {
                    let p = if Path::new(&ts).is_absolute() {
                        PathBuf::from(&ts)
                    } else {
                        ctx.doc_root.join(&ts)
                    };
                    (
                        std::fs::symlink_metadata(&p)
                            .map(|m| m.file_type().is_symlink())
                            .unwrap_or(false),
                        None,
                    )
                }
                CondTest::Executable => {
                    let p = if Path::new(&ts).is_absolute() {
                        PathBuf::from(&ts)
                    } else {
                        ctx.doc_root.join(&ts)
                    };
                    (p.is_file(), None)
                }
                CondTest::SubrequestUrl => {
                    let p = if Path::new(&ts).is_absolute() {
                        PathBuf::from(&ts)
                    } else {
                        ctx.doc_root.join(ts.trim_start_matches('/'))
                    };
                    (p.exists() || !ts.is_empty(), None)
                }
                CondTest::NumEq(expected) => (
                    ts.trim().parse::<i64>().map(|v| v == *expected).unwrap_or(false),
                    None,
                ),
                CondTest::NumNe(expected) => (
                    ts.trim().parse::<i64>().map(|v| v != *expected).unwrap_or(false),
                    None,
                ),
                CondTest::NumLt(expected) => (
                    ts.trim().parse::<i64>().map(|v| v < *expected).unwrap_or(false),
                    None,
                ),
                CondTest::NumGt(expected) => (
                    ts.trim().parse::<i64>().map(|v| v > *expected).unwrap_or(false),
                    None,
                ),
                CondTest::NumLe(expected) => (
                    ts.trim().parse::<i64>().map(|v| v <= *expected).unwrap_or(false),
                    None,
                ),
                CondTest::NumGe(expected) => (
                    ts.trim().parse::<i64>().map(|v| v >= *expected).unwrap_or(false),
                    None,
                ),
                CondTest::Eq(v) => (&ts == v, None),
                CondTest::Lt(v) => (ts.as_str() < v.as_str(), None),
                CondTest::Gt(v) => (ts.as_str() > v.as_str(), None),
                CondTest::Le(v) => (ts.as_str() <= v.as_str(), None),
                CondTest::Ge(v) => (ts.as_str() >= v.as_str(), None),
            };
            if c.negate {
                r = !r;
            } else if r && caps.is_some() {
                cond_caps = caps;
            }
            group = group || r;
            if !c.or {
                if !group {
                    return (false, None);
                }
                group = false;
            }
        }
        // sonda OR bayrağı kalmışsa grup sonucu kullanılır
        if rule.conds.last().map(|c| c.or).unwrap_or(false) && !group {
            return (false, None);
        }
        (true, cond_caps)
    }
}

fn client_is_https(ctx: &RequestCtx) -> bool {
    for (k, v) in ctx.headers {
        if k.eq_ignore_ascii_case("x-forwarded-proto") {
            return v.eq_ignore_ascii_case("https");
        }
        if k.eq_ignore_ascii_case("x-forwarded-ssl") {
            return v.eq_ignore_ascii_case("on");
        }
    }
    ctx.https
}

fn absolutize(loc: &str, ctx: &RequestCtx) -> String {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    let is_https = client_is_https(ctx);
    if loc.starts_with("//") {
        let scheme = if is_https { "https" } else { "http" };
        return format!("{scheme}:{loc}");
    }
    let scheme = if is_https { "https" } else { "http" };
    let path = if loc.starts_with('/') {
        loc.to_string()
    } else {
        format!("/{loc}")
    };
    format!("{scheme}://{}{}", ctx.host, path)
}

fn url_encode_backref(val: &str) -> String {
    let mut out = String::with_capacity(val.len() * 3);
    for b in val.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}

use std::time::SystemTime;

fn get_time_vars() -> (String, String, String, String, String, String, String, String) {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sec = (secs % 60) as u32;
    let min = ((secs / 60) % 60) as u32;
    let hour = ((secs / 3600) % 24) as u32;
    let wday = (((secs / 86400) + 4) % 7) as u32;

    let z = (secs / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let year = format!("{:04}", y);
    let mon = format!("{:02}", m);
    let day = format!("{:02}", d);
    let hour_s = format!("{:02}", hour);
    let min_s = format!("{:02}", min);
    let sec_s = format!("{:02}", sec);
    let wday_s = format!("{}", wday);
    let time_s = format!("{}{}{}{}{}{}", year, mon, day, hour_s, min_s, sec_s);

    (year, mon, day, hour_s, min_s, sec_s, wday_s, time_s)
}

fn var_value(
    name: &str,
    ctx: &RequestCtx,
    path: &str,
    query: &str,
    env_vars: &[(String, String)],
) -> String {
    let n = name.trim();
    if let Some(env_name) = n.strip_prefix("ENV:") {
        let env_name = env_name.trim();
        if let Some((_, v)) = env_vars
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(env_name))
        {
            return v.clone();
        }
        if let Ok(v) = std::env::var(env_name) {
            return v;
        }
        return String::new();
    }
    if let Some(h) = n.strip_prefix("HTTP:") {
        return header(ctx, h.trim());
    }

    let upper = n.to_ascii_uppercase();
    if upper.starts_with("HTTP_") {
        match upper.as_str() {
            "HTTP_HOST" => return ctx.host.to_string(),
            "HTTP_USER_AGENT" => return header(ctx, "user-agent"),
            "HTTP_REFERER" => return header(ctx, "referer"),
            "HTTP_COOKIE" => return header(ctx, "cookie"),
            "HTTP_ACCEPT" => return header(ctx, "accept"),
            "HTTP_ACCEPT_ENCODING" => return header(ctx, "accept-encoding"),
            "HTTP_ACCEPT_LANGUAGE" => return header(ctx, "accept-language"),
            "HTTP_AUTHORIZATION" => return header(ctx, "authorization"),
            "HTTP_X_FORWARDED_PROTO" => return header(ctx, "x-forwarded-proto"),
            "HTTP_X_FORWARDED_FOR" => return header(ctx, "x-forwarded-for"),
            other => {
                let h_name = &other[5..];
                let res = header(ctx, h_name);
                if !res.is_empty() {
                    return res;
                }
                let hyphenated = h_name.replace('_', "-");
                return header(ctx, &hyphenated);
            }
        }
    }

    match upper.as_str() {
        // Apache mod_rewrite standardında REQUEST_URI yalnızca yol bileşenidir (sorgu QUERY_STRING içindedir).
        "REQUEST_URI" => path.to_string(),
        "REQUEST_FILENAME" | "SCRIPT_FILENAME" => resolve_request_filename(ctx.doc_root, path)
            .to_string_lossy()
            .into_owned(),
        "DOCUMENT_ROOT" => ctx.doc_root.to_string_lossy().into_owned(),
        "QUERY_STRING" => query.to_string(),
        "HTTPS" => {
            if ctx.https {
                "on".into()
            } else {
                "off".into()
            }
        }
        "REQUEST_METHOD" => ctx.method.to_string(),
        "REMOTE_ADDR" => ctx.remote_addr.to_string(),
        "SERVER_PORT" => ctx.server_port.to_string(),
        "SERVER_NAME" => ctx.host.split(':').next().unwrap_or("").to_string(),
        "SERVER_ADDR" => "127.0.0.1".into(),
        "SERVER_PROTOCOL" => "HTTP/1.1".into(),
        "SERVER_SOFTWARE" => "ZMax-Server/1.0.0 (OpenLiteSpeed-compatible)".into(),
        "SERVER_ADMIN" => "webmaster@localhost".into(),
        "REQUEST_SCHEME" => {
            if ctx.https {
                "https".into()
            } else {
                "http".into()
            }
        }
        "SCRIPT_NAME" => path.to_string(),
        "PATH_INFO" => String::new(),
        "IS_SUBREQ" => "false".into(),
        "THE_REQUEST" => {
            if query.is_empty() {
                format!("{} {} HTTP/1.1", ctx.method, path)
            } else {
                format!("{} {}?{} HTTP/1.1", ctx.method, path, query)
            }
        }
        "TIME_YEAR" => get_time_vars().0,
        "TIME_MON" => get_time_vars().1,
        "TIME_DAY" => get_time_vars().2,
        "TIME_HOUR" => get_time_vars().3,
        "TIME_MIN" => get_time_vars().4,
        "TIME_SEC" => get_time_vars().5,
        "TIME_WDAY" => get_time_vars().6,
        "TIME" => get_time_vars().7,
        _ => String::new(),
    }
}

/// PHP `PATH_INFO` yollarında (`/script.php/ekstra`) Apache/LiteSpeed uyumlu olarak
/// `REQUEST_FILENAME`'i diskteki gerçek `.php` dosyasına eşler.
fn resolve_request_filename(doc_root: &Path, path: &str) -> PathBuf {
    let trimmed = path.trim_start_matches('/');
    let direct = doc_root.join(trimmed);
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || direct.exists()
    {
        return direct;
    }

    let Ok(canon_root) = std::fs::canonicalize(doc_root) else {
        return direct;
    };

    for (idx, _) in trimmed.match_indices('/') {
        let prefix = &trimmed[..idx];
        let remaining = &trimmed[idx..];
        if !prefix.to_ascii_lowercase().ends_with(".php") {
            continue;
        }
        let last_seg = prefix.rsplit('/').next().unwrap_or("");
        if last_seg.len() <= 4 || last_seg.starts_with('.') {
            continue;
        }
        if prefix
            .split('/')
            .chain(remaining.split('/'))
            .any(|s| !s.is_empty() && s.starts_with('.'))
        {
            continue;
        }
        let cand = doc_root.join(prefix);
        if let Ok(canon_cand) = std::fs::canonicalize(&cand) {
            if canon_cand.starts_with(&canon_root) && canon_cand.is_file() {
                return cand;
            }
        }
    }

    direct
}

fn header(ctx: &RequestCtx, name: &str) -> String {
    ctx.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// `$N` (kural), `%N` (son koşul) ve `%{VAR}` sunucu değişkenlerini açar.
fn expand(
    s: &str,
    rule_caps: Option<&Vec<String>>,
    cond_caps: Option<&Vec<String>>,
    ctx: &RequestCtx,
    path: &str,
    query: &str,
    env_vars: &[(String, String)],
    escape_b: bool,
) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '$' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            let n = b[i + 1].to_digit(10).unwrap() as usize;
            if let Some(v) = rule_caps.and_then(|c| c.get(n)) {
                if escape_b {
                    out.push_str(&url_encode_backref(v));
                } else {
                    out.push_str(v);
                }
            }
            i += 2;
        } else if c == '%' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            let n = b[i + 1].to_digit(10).unwrap() as usize;
            if let Some(v) = cond_caps.and_then(|c| c.get(n)) {
                if escape_b {
                    out.push_str(&url_encode_backref(v));
                } else {
                    out.push_str(v);
                }
            }
            i += 2;
        } else if c == '%' && i + 1 < b.len() && b[i + 1] == '{' {
            if let Some(end) = b[i + 2..].iter().position(|&x| x == '}') {
                let name: String = b[i + 2..i + 2 + end].iter().collect();
                out.push_str(&var_value(&name, ctx, path, query, env_vars));
                i += 3 + end;
            } else {
                out.push(c);
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(
        root: &'a Path,
        path: &'a str,
        query: &'a str,
        headers: &'a [(String, String)],
    ) -> RequestCtx<'a> {
        RequestCtx {
            path,
            query,
            host: "site.test",
            https: false,
            method: "GET",
            doc_root: root,
            remote_addr: "1.2.3.4",
            server_port: 80,
            headers,
        }
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("zmax_ht_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const WP: &str = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n";

    #[test]
    fn wordpress_permalink_rewrites_missing_paths_only() {
        let root = tmp("wp");
        std::fs::write(root.join("index.php"), "x").unwrap();
        std::fs::write(root.join("style.css"), "x").unwrap();
        std::fs::create_dir_all(root.join("klasor")).unwrap();
        let h = HtAccess::parse(WP);
        assert!(h.warnings.is_empty(), "{:?}", h.warnings);
        let none: Vec<(String, String)> = vec![];
        assert_eq!(
            h.evaluate(&ctx(&root, "/ornek-yazi/", "p=1", &none)),
            Outcome::Rewritten {
                path: "/index.php".into(),
                query: "p=1".into()
            }
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/style.css", "", &none)),
            Outcome::None
        );
        assert_eq!(h.evaluate(&ctx(&root, "/klasor", "", &none)), Outcome::None);
        assert_eq!(
            h.evaluate(&ctx(&root, "/index.php", "", &none)),
            Outcome::None
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn redirect_flags_and_backrefs() {
        let root = tmp("rd");
        let h = HtAccess::parse(
            "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]\nRewriteRule ^eski/(.*)$ /yeni/$1 [R=permanent]\n",
        );
        let none: Vec<(String, String)> = vec![];
        assert_eq!(
            h.evaluate(&ctx(&root, "/a/b", "x=1", &none)),
            Outcome::Redirect {
                status: 301,
                location: "https://site.test/a/b?x=1".into()
            }
        );
        let mut c = ctx(&root, "/eski/sayfa", "", &none);
        c.https = true;
        assert_eq!(
            h.evaluate(&c),
            Outcome::Redirect {
                status: 301,
                location: "https://site.test/yeni/sayfa".into()
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn forbidden_gone_or_cond_nocase_and_qsa() {
        let root = tmp("fg");
        let h = HtAccess::parse(
            "RewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} badbot [NC,OR]\nRewriteCond %{HTTP_REFERER} spam\\.com\nRewriteRule .* - [F]\nRewriteRule ^kaldirildi$ - [G]\nRewriteRule ^p/(\\d+)$ /sayfa.php?id=$1 [QSA,L]\n",
        );
        let ua = vec![("User-Agent".to_string(), "xBADBOTx".to_string())];
        assert_eq!(h.evaluate(&ctx(&root, "/x", "", &ua)), Outcome::Forbidden);
        let ref_ = vec![("Referer".to_string(), "http://spam.com/".to_string())];
        assert_eq!(h.evaluate(&ctx(&root, "/x", "", &ref_)), Outcome::Forbidden);
        let none: Vec<(String, String)> = vec![];
        assert_eq!(
            h.evaluate(&ctx(&root, "/kaldirildi", "", &none)),
            Outcome::Gone
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/p/42", "a=1", &none)),
            Outcome::Rewritten {
                path: "/sayfa.php".into(),
                query: "id=42&a=1".into()
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn redirect_directives_and_directory_index() {
        let root = tmp("al");
        let h = HtAccess::parse(
            "DirectoryIndex anasayfa.php index.html\nRedirect 301 /eski https://yeni.test/y\nRedirectMatch 302 ^/kat/(\\d+)$ /kategori.php?id=$1\nRedirect gone /silindi\n",
        );
        assert_eq!(h.directory_index, vec!["anasayfa.php", "index.html"]);
        let none: Vec<(String, String)> = vec![];
        assert_eq!(
            h.evaluate(&ctx(&root, "/eski/alt", "", &none)),
            Outcome::Redirect {
                status: 301,
                location: "https://yeni.test/y/alt".into()
            }
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/kat/7", "", &none)),
            Outcome::Redirect {
                status: 302,
                location: "http://site.test/kategori.php?id=7".into()
            }
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/silindi", "", &none)),
            Outcome::Gone
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/eskiden", "", &none)),
            Outcome::None
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_regex_is_reported_not_fatal() {
        let h = HtAccess::parse(
            "RewriteEngine On\nRewriteRule ^(?=a)b$ /x [L]\nRewriteRule ^ok$ /y [L]\n",
        );
        assert_eq!(h.warnings.len(), 1);
        let root = std::env::temp_dir();
        let none: Vec<(String, String)> = vec![];
        assert_eq!(
            h.evaluate(&ctx(&root, "/ok", "", &none)),
            Outcome::Rewritten {
                path: "/y".into(),
                query: String::new()
            }
        );
    }

    #[test]
    fn rewrite_loop_is_bounded() {
        let root = std::env::temp_dir();
        let h =
            HtAccess::parse("RewriteEngine On\nRewriteRule ^a$ /b [L]\nRewriteRule ^b$ /a [L]\n");
        let none: Vec<(String, String)> = vec![];
        // sonsuz döngüye girmeden döner
        let _ = h.evaluate(&ctx(&root, "/a", "", &none));
    }

    #[test]
    fn request_uri_and_the_request_query_behavior() {
        let root = tmp("req_uri");
        let h = HtAccess::parse(
            "RewriteEngine On\nRewriteCond %{REQUEST_URI} ^/sayfa/$\nRewriteRule ^ /eslesti [L]\nRewriteCond %{THE_REQUEST} \\?gizli=1\nRewriteRule ^ - [F]\n",
        );
        let none: Vec<(String, String)> = vec![];
        // REQUEST_URI sorgu dizesi olmadan yalnızca path olmalıdır
        assert_eq!(
            h.evaluate(&ctx(&root, "/sayfa/", "foo=bar", &none)),
            Outcome::Rewritten {
                path: "/eslesti".into(),
                query: "foo=bar".into()
            }
        );
        // THE_REQUEST ise sorgu dizesini içermelidir
        assert_eq!(
            h.evaluate(&ctx(&root, "/baska", "gizli=1", &none)),
            Outcome::Forbidden
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wordpress_htaccess_preserves_existing_php_path_info() {
        let root = tmp("wp_path_info");
        std::fs::write(root.join("index.php"), "<?php").unwrap();
        std::fs::write(root.join("php_test.php"), "<?php").unwrap();
        let h = HtAccess::parse(WP);
        let none: Vec<(String, String)> = vec![];
        assert_eq!(
            h.evaluate(&ctx(&root, "/php_test.php/urun/42", "renk=mavi", &none)),
            Outcome::None
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/olmayan.php/urun/42", "renk=mavi", &none)),
            Outcome::Rewritten {
                path: "/index.php".into(),
                query: "renk=mavi".into()
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn zpanel_redirects_block_https_www_and_nowww_with_backrefs() {
        let root = tmp("zpanel_redirs");
        let none: Vec<(String, String)> = vec![];

        // 1. Force HTTPS + Enforce non-WWW (%1 geri başvurusu)
        let ht_non_www = concat!(
            "# BEGIN zPanel Redirects\n",
            "<IfModule mod_rewrite.c>\n",
            "RewriteEngine On\n\n",
            "# Force HTTPS\n",
            "RewriteCond %{HTTPS} off\n",
            "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n",
            "# Enforce non-WWW\n",
            "RewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\n",
            "RewriteRule ^(.*)$ https://%1%{REQUEST_URI} [L,R=301]\n",
            "</IfModule>\n",
        );
        let h1 = HtAccess::parse(ht_non_www);
        assert!(h1.warnings.is_empty(), "{:?}", h1.warnings);

        // HTTP iken HTTPS'e yönlenmeli
        let mut c_http = ctx(&root, "/blog/yazi-1", "sayfa=2", &none);
        c_http.host = "site.test";
        c_http.https = false;
        assert_eq!(
            h1.evaluate(&c_http),
            Outcome::Redirect {
                status: 301,
                location: "https://site.test/blog/yazi-1?sayfa=2".into(),
            }
        );

        // HTTPS ve www.site.test iken %1 ile site.test'e yönlenmeli
        let mut c_www = ctx(&root, "/hakkimizda", "ref=google", &none);
        c_www.host = "www.site.test";
        c_www.https = true;
        assert_eq!(
            h1.evaluate(&c_www),
            Outcome::Redirect {
                status: 301,
                location: "https://site.test/hakkimizda?ref=google".into(),
            }
        );

        // Zaten HTTPS ve non-www iken döngüye girmemeli (Outcome::None)
        let mut c_ok = ctx(&root, "/iletisim", "", &none);
        c_ok.host = "site.test";
        c_ok.https = true;
        assert_eq!(h1.evaluate(&c_ok), Outcome::None);

        // 2. Enforce WWW (RewriteCond %{HTTP_HOST} !^www\. [NC])
        let ht_www = concat!(
            "# BEGIN zPanel Redirects\n",
            "<IfModule mod_rewrite.c>\n",
            "RewriteEngine On\n",
            "RewriteCond %{HTTP_HOST} !^www\\. [NC]\n",
            "RewriteRule ^(.*)$ https://www.%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n",
            "</IfModule>\n",
        );
        let h2 = HtAccess::parse(ht_www);
        let mut c_nowww = ctx(&root, "/urunler", "kategori=1", &none);
        c_nowww.host = "site.test";
        c_nowww.https = true;
        assert_eq!(
            h2.evaluate(&c_nowww),
            Outcome::Redirect {
                status: 301,
                location: "https://www.site.test/urunler?kategori=1".into(),
            }
        );

        // 3. Host bazlı alan adı yönlendirmesi
        let ht_host = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{HTTP_HOST} ^eski-alan\\.test$ [NC]\n",
            "RewriteRule ^(.*)$ https://yeni-alan.test/$1 [R=301,L]\n",
        );
        let h3 = HtAccess::parse(ht_host);
        let mut c_old_host = ctx(&root, "/sayfa/detay", "id=9", &none);
        c_old_host.host = "eski-alan.test";
        assert_eq!(
            h3.evaluate(&c_old_host),
            Outcome::Redirect {
                status: 301,
                location: "https://yeni-alan.test/sayfa/detay?id=9".into(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn files_match_deny_and_require_all_denied() {
        let root = tmp("fm_test");
        let none: Vec<(String, String)> = vec![];

        let ht = concat!(
            "<FilesMatch \"^\\.ht\">\n",
            "    Require all denied\n",
            "</FilesMatch>\n",
            "<FilesMatch \"\\.(env|log|sql|ini|bak)$\">\n",
            "    Order allow,deny\n",
            "    Deny from all\n",
            "</FilesMatch>\n",
            "<FilesMatch \"^(wp-config\\.php|readme\\.html)$\">\n",
            "    Deny from all\n",
            "</FilesMatch>\n",
        );
        let h = HtAccess::parse(ht);
        assert_eq!(h.files_matches.len(), 3);

        // Yasaklı dosyalar -> Outcome::Forbidden
        assert_eq!(
            h.evaluate(&ctx(&root, "/.htaccess", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/.htpasswd", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/app.env", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/database.sql", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/errors.log", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/config.ini", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/yedek.bak", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/wp-config.php", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/readme.html", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/sub/klasor/secret.sql", "", &none)),
            Outcome::Forbidden
        );

        // İzinli normal dosyalar -> Outcome::None (rewrite rule yok)
        assert_eq!(
            h.evaluate(&ctx(&root, "/index.php", "", &none)),
            Outcome::None
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/style.css", "", &none)),
            Outcome::None
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/resim.jpg", "", &none)),
            Outcome::None
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn files_wildcard_glob_denial() {
        let root = tmp("files_glob");
        let none: Vec<(String, String)> = vec![];

        let ht = concat!(
            "<Files \"*.private\">\n",
            "    Require all denied\n",
            "</Files>\n",
            "<Files \"gizli.txt\">\n",
            "    Deny from all\n",
            "</Files>\n",
        );
        let h = HtAccess::parse(ht);
        assert_eq!(h.files_matches.len(), 2);

        assert_eq!(
            h.evaluate(&ctx(&root, "/anahtar.private", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/dizin/anahtar.private", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/gizli.txt", "", &none)),
            Outcome::Forbidden
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/dizin/gizli.txt", "", &none)),
            Outcome::Forbidden
        );

        assert_eq!(
            h.evaluate(&ctx(&root, "/acik.txt", "", &none)),
            Outcome::None
        );
        assert_eq!(
            h.evaluate(&ctx(&root, "/anahtar.pub", "", &none)),
            Outcome::None
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rewrite_loop_detection_and_self_redirect_safety() {
        let root = tmp("loop_safety");
        let none: Vec<(String, String)> = vec![];

        // 1. İki kural arasında ping-pong sonsuz döngüsü (/a -> /b -> /a)
        let ht_pingpong = "RewriteEngine On\nRewriteRule ^a$ /b [L]\nRewriteRule ^b$ /a [L]\n";
        let h_loop = HtAccess::parse(ht_pingpong);
        // Döngü tespit edildiğinde DoS koruması gereği Outcome::Forbidden döner
        assert_eq!(
            h_loop.evaluate(&ctx(&root, "/a", "", &none)),
            Outcome::Forbidden
        );

        // 2. Kendine yönlendirme (Self-redirect 301/302)
        let ht_self = "RewriteEngine On\nRewriteRule ^kendisi$ /kendisi [R=301,L]\n";
        let h_self = HtAccess::parse(ht_self);
        assert_eq!(
            h_self.evaluate(&ctx(&root, "/kendisi", "", &none)),
            Outcome::None
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn regex_max_length_dos_protection() {
        let huge_pattern = "a".repeat(2500);
        let ht_bad = format!("RewriteEngine On\nRewriteRule {huge_pattern} /hedef [L]\n");
        let h = HtAccess::parse(&ht_bad);
        // Desenin uzunluğu 2048 karakterden büyük olduğu için warnings'e yazılmalı ve sunucu çökmemeli
        assert_eq!(h.warnings.len(), 1);
        assert!(h.warnings[0].contains("azami uzunluk"));
    }

    #[test]
    fn unknown_host_and_custom_port_behavior() {
        let root = tmp("unk_host");
        let none: Vec<(String, String)> = vec![];

        let ht = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{HTTP_HOST} ^$\n",
            "RewriteRule ^ - [F]\n",
            "RewriteCond %{SERVER_NAME} ^site\\.test$\n",
            "RewriteRule ^bilgi$ /bilgi.php [L]\n",
        );
        let h = HtAccess::parse(ht);

        // Boş / tanımsız host -> Forbidden
        let mut c_empty = ctx(&root, "/sayfa", "", &none);
        c_empty.host = "";
        assert_eq!(h.evaluate(&c_empty), Outcome::Forbidden);

        // Port içeren host (site.test:19480) -> SERVER_NAME portsüz 'site.test' olarak eşleşmeli
        let mut c_port = ctx(&root, "/bilgi", "", &none);
        c_port.host = "site.test:19480";
        assert_eq!(
            h.evaluate(&c_port),
            Outcome::Rewritten {
                path: "/bilgi.php".into(),
                query: String::new()
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_nextjs_clean_urls_and_fallback() {
        let root = tmp("nextjs");
        let none: Vec<(String, String)> = vec![];

        std::fs::write(root.join("about.html"), "<h1>About</h1>").unwrap();
        std::fs::write(root.join("contact.html"), "<h1>Contact</h1>").unwrap();
        std::fs::write(root.join("404.html"), "<h1>Not Found</h1>").unwrap();
        std::fs::write(root.join("style.css"), "body {}").unwrap();

        let ht = concat!(
            "RewriteEngine On\n",
            "RewriteBase /\n",
            "# Next.js clean URLs: /about -> /about.html\n",
            "RewriteCond %{REQUEST_FILENAME} !-f\n",
            "RewriteCond %{REQUEST_FILENAME} !-d\n",
            "RewriteCond %{REQUEST_FILENAME}.html -f\n",
            "RewriteRule ^(.+)$ $1.html [L]\n",
            "# Next.js 404 Fallback\n",
            "RewriteCond %{REQUEST_FILENAME} !-f\n",
            "RewriteCond %{REQUEST_FILENAME} !-d\n",
            "RewriteCond %{DOCUMENT_ROOT}/404.html -f\n",
            "RewriteRule ^ /404.html [L]\n",
        );
        let h = HtAccess::parse(ht);
        assert!(h.warnings.is_empty(), "{:?}", h.warnings);

        // 1. /about -> /about.html olarak yeniden yazılmalı
        assert_eq!(
            h.evaluate(&ctx(&root, "/about", "", &none)),
            Outcome::Rewritten {
                path: "/about.html".into(),
                query: String::new(),
            }
        );

        // 2. /contact -> /contact.html
        assert_eq!(
            h.evaluate(&ctx(&root, "/contact", "src=ref", &none)),
            Outcome::Rewritten {
                path: "/contact.html".into(),
                query: "src=ref".into(),
            }
        );

        // 3. Gerçek dosya (/style.css) -> Yeniden yazılmamalı (Outcome::None)
        assert_eq!(
            h.evaluate(&ctx(&root, "/style.css", "", &none)),
            Outcome::None
        );

        // 4. Olmayan sayfa (/olmayan-sayfa) -> /404.html'e yeniden yazılmalı
        assert_eq!(
            h.evaluate(&ctx(&root, "/olmayan-sayfa", "", &none)),
            Outcome::Rewritten {
                path: "/404.html".into(),
                query: String::new(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_force_https_variations() {
        let root = tmp("ssl_force");
        let none: Vec<(String, String)> = vec![];

        // Model 1: %{HTTPS} off
        let ht1 = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{HTTPS} off\n",
            "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n",
        );
        let h1 = HtAccess::parse(ht1);
        let mut c_http = ctx(&root, "/sayfa", "a=1", &none);
        c_http.https = false;
        assert_eq!(
            h1.evaluate(&c_http),
            Outcome::Redirect {
                status: 301,
                location: "https://site.test/sayfa?a=1".into(),
            }
        );
        let mut c_https = ctx(&root, "/sayfa", "a=1", &none);
        c_https.https = true;
        assert_eq!(h1.evaluate(&c_https), Outcome::None);

        // Model 2: %{HTTPS} !=on
        let ht2 = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{HTTPS} !=on\n",
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n",
        );
        let h2 = HtAccess::parse(ht2);
        assert_eq!(
            h2.evaluate(&c_http),
            Outcome::Redirect {
                status: 301,
                location: "https://site.test/sayfa?a=1".into(),
            }
        );
        assert_eq!(h2.evaluate(&c_https), Outcome::None);

        // Model 3: %{HTTP:X-Forwarded-Proto} !https
        let ht3 = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{HTTP:X-Forwarded-Proto} !https\n",
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n",
        );
        let h3 = HtAccess::parse(ht3);
        let proto_http = vec![("X-Forwarded-Proto".to_string(), "http".to_string())];
        let mut c_proto_http = ctx(&root, "/api/v1", "", &proto_http);
        c_proto_http.https = true; // arkada TLS olsa bile proto header http
        assert_eq!(
            h3.evaluate(&c_proto_http),
            Outcome::Redirect {
                status: 301,
                location: "https://site.test/api/v1".into(),
            }
        );
        let proto_https = vec![("X-Forwarded-Proto".to_string(), "https".to_string())];
        let c_proto_https = ctx(&root, "/api/v1", "", &proto_https);
        assert_eq!(h3.evaluate(&c_proto_https), Outcome::None);

        // Model 4: %{SERVER_PORT} -eq 80
        let ht4 = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{SERVER_PORT} -eq 80\n",
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n",
        );
        let h4 = HtAccess::parse(ht4);
        let mut c_p80 = ctx(&root, "/port80", "", &none);
        c_p80.server_port = 80;
        assert_eq!(
            h4.evaluate(&c_p80),
            Outcome::Redirect {
                status: 301,
                location: "https://site.test/port80".into(),
            }
        );
        let mut c_p443 = ctx(&root, "/port80", "", &none);
        c_p443.server_port = 443;
        assert_eq!(h4.evaluate(&c_p443), Outcome::None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_www_removal_and_enforcement() {
        let root = tmp("www_tests");
        let none: Vec<(String, String)> = vec![];

        // 1. WWW Kaldırma (Enforce non-WWW)
        let ht_non_www = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\n",
            "RewriteRule ^(.*)$ https://%1/$1 [R=301,L]\n",
        );
        let h1 = HtAccess::parse(ht_non_www);
        let mut c_www = ctx(&root, "/urunler/bilgisayar", "sira=fiyat", &none);
        c_www.host = "www.magaza.test";
        c_www.https = true;
        assert_eq!(
            h1.evaluate(&c_www),
            Outcome::Redirect {
                status: 301,
                location: "https://magaza.test/urunler/bilgisayar?sira=fiyat".into(),
            }
        );

        let mut c_non_www = ctx(&root, "/urunler/bilgisayar", "", &none);
        c_non_www.host = "magaza.test";
        c_non_www.https = true;
        assert_eq!(h1.evaluate(&c_non_www), Outcome::None);

        // 2. WWW Ekleme (Enforce WWW)
        let ht_www = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{HTTP_HOST} !^www\\. [NC]\n",
            "RewriteCond %{HTTP_HOST} ^(.+)$ [NC]\n",
            "RewriteRule ^(.*)$ https://www.%1/$1 [R=301,L]\n",
        );
        let h2 = HtAccess::parse(ht_www);
        assert_eq!(
            h2.evaluate(&c_non_www),
            Outcome::Redirect {
                status: 301,
                location: "https://www.magaza.test/urunler/bilgisayar".into(),
            }
        );
        assert_eq!(h2.evaluate(&c_www), Outcome::None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_ols_numeric_comparisons_and_engine_flags() {
        let root = tmp("ols_num");
        let none: Vec<(String, String)> = vec![];

        // RewriteEngine 1 (OLS standardı)
        let ht_engine = "RewriteEngine 1\nRewriteRule ^test$ /test.php [L]\n";
        let h_eng = HtAccess::parse(ht_engine);
        assert!(h_eng.engine_on());
        assert_eq!(
            h_eng.evaluate(&ctx(&root, "/test", "", &none)),
            Outcome::Rewritten {
                path: "/test.php".into(),
                query: String::new(),
            }
        );

        // RewriteEngine 0 (OLS standardı)
        let ht_off = "RewriteEngine 0\nRewriteRule ^test$ /test.php [L]\n";
        let h_off = HtAccess::parse(ht_off);
        assert!(!h_off.engine_on());
        assert_eq!(h_off.evaluate(&ctx(&root, "/test", "", &none)), Outcome::None);

        // Sayısal Karşılaştırmalar: -gt, -lt, -ge, -le, -ne
        let ht_num = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{SERVER_PORT} -gt 1024\n",
            "RewriteRule ^dev - [E=DEV_PORT:1]\n",
            "RewriteCond %{SERVER_PORT} -le 80\n",
            "RewriteRule ^insecure$ /secure [R=301,L]\n",
            "RewriteCond %{SERVER_PORT} -ne 443\n",
            "RewriteRule ^not443$ /isnot443 [L]\n",
        );
        let h_num = HtAccess::parse(ht_num);

        let mut c_dev = ctx(&root, "/dev", "", &none);
        c_dev.server_port = 8080;
        let res_dev = h_num.evaluate_in_dir(&c_dev, "/");
        assert!(res_dev.env_vars.iter().any(|(k, v)| k == "DEV_PORT" && v == "1"));

        let mut c_insec = ctx(&root, "/insecure", "", &none);
        c_insec.server_port = 80;
        assert_eq!(
            h_num.evaluate(&c_insec),
            Outcome::Redirect {
                status: 301,
                location: "http://site.test/secure".into(),
            }
        );

        let mut c_not443 = ctx(&root, "/not443", "", &none);
        c_not443.server_port = 8080;
        assert_eq!(
            h_num.evaluate(&c_not443),
            Outcome::Rewritten {
                path: "/isnot443".into(),
                query: String::new(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_env_vars_and_dynamic_headers() {
        let root = tmp("env_dyn");
        let headers = vec![
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            ("X-Requested-With".to_string(), "XMLHttpRequest".to_string()),
            ("Authorization".to_string(), "Bearer token123".to_string()),
        ];

        let ht = concat!(
            "RewriteEngine On\n",
            "# Ortam değişkeni ata\n",
            "RewriteRule ^api/.* - [E=API_MODE:v2,E=AUTH_COPY:%{HTTP:Authorization}]\n",
            "# Ortam değişkenini koşulda doğrula\n",
            "RewriteCond %{ENV:API_MODE} =v2\n",
            "RewriteCond %{HTTP_UPGRADE} =websocket [NC]\n",
            "RewriteCond %{HTTP_X_REQUESTED_WITH} =XMLHttpRequest\n",
            "RewriteRule ^api/ws /ws_handler.php [L]\n",
        );
        let h = HtAccess::parse(ht);
        assert!(h.warnings.is_empty(), "{:?}", h.warnings);

        let c = ctx(&root, "/api/ws", "client=web", &headers);
        let res = h.evaluate_in_dir(&c, "/");
        assert_eq!(
            res.outcome,
            Outcome::Rewritten {
                path: "/ws_handler.php".into(),
                query: "client=web".into(),
            }
        );
        assert!(res.env_vars.iter().any(|(k, v)| k == "API_MODE" && v == "v2"));
        assert!(res.env_vars.iter().any(|(k, v)| k == "AUTH_COPY" && v == "Bearer token123"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_escape_backrefs_flag_b() {
        let root = tmp("escape_b");
        let none: Vec<(String, String)> = vec![];

        let ht = "RewriteEngine On\nRewriteRule ^ara/(.*)$ /search.php?query=$1 [B,L]\n";
        let h = HtAccess::parse(ht);

        // Boşluk ve özel karakter içeren arama sorgusu [B] bayrağı ile encode edilmeli
        assert_eq!(
            h.evaluate(&ctx(&root, "/ara/mehmet can", "", &none)),
            Outcome::Rewritten {
                path: "/search.php".into(),
                query: "query=mehmet%20can".into(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_protocol_relative_redirect() {
        let root = tmp("proto_rel");
        let none: Vec<(String, String)> = vec![];

        let ht = "RewriteEngine On\nRewriteRule ^cdn/(.*)$ //cdn.site.test/$1 [R=301,L]\n";
        let h = HtAccess::parse(ht);

        let mut c_https = ctx(&root, "/cdn/resim.png", "", &none);
        c_https.https = true;
        assert_eq!(
            h.evaluate(&c_https),
            Outcome::Redirect {
                status: 301,
                location: "https://cdn.site.test/resim.png".into(),
            }
        );

        let mut c_http = ctx(&root, "/cdn/resim.png", "", &none);
        c_http.https = false;
        assert_eq!(
            h.evaluate(&c_http),
            Outcome::Redirect {
                status: 301,
                location: "http://cdn.site.test/resim.png".into(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_single_quote_and_space_flags() {
        let root = tmp("single_q");
        let ua = vec![("User-Agent".to_string(), "Googlebot".to_string())];

        // Tek tırnak ve bayraklar arasında boşluk: [NC, OR]
        let ht = concat!(
            "RewriteEngine On\n",
            "RewriteCond %{HTTP_USER_AGENT} 'Googlebot' [NC, OR]\n",
            "RewriteCond %{HTTP_HOST} 'bot-zone.test' [NC]\n",
            "RewriteRule ^ - [E=IS_BOT:1]\n",
        );
        let h = HtAccess::parse(ht);
        assert!(h.warnings.is_empty(), "{:?}", h.warnings);

        let mut c = ctx(&root, "/sayfa", "", &ua);
        c.host = "normal-site.test";
        let res = h.evaluate_in_dir(&c, "/");
        assert!(res.env_vars.iter().any(|(k, v)| k == "IS_BOT" && v == "1"));

        let _ = std::fs::remove_dir_all(&root);
    }
}
