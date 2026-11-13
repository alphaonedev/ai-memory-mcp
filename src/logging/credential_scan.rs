//! Credential-option scanning with a persistent URL cursor (#8205 round 7).

use super::{
    CREDENTIAL_OPTION_KEYS, EXACT_CREDENTIAL_KEYS, SCHEME_SEPARATOR, URL_PASSWORD_MASK,
    connection_value_end, scan_charge, url_scan,
};

/// ASCII punctuation ignored inside credential keys.
const CREDENTIAL_KEY_PUNCTUATION: [char; 2] = ['_', '-'];
/// Unicode dash spellings normalized to the same credential-key hyphen.
const CREDENTIAL_KEY_DASHES: &[char] = &[
    '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}', '\u{2015}', '\u{2212}', '\u{fe63}',
];
const FULLWIDTH_ASCII_START: u32 = 0xff01;
const FULLWIDTH_ASCII_END: u32 = 0xff5e;
const FULLWIDTH_ASCII_OFFSET: u32 = 0xfee0;
/// Thirteen uppercase/lowercase Latin mathematical styles, in alphabet order.
const MATHEMATICAL_LATIN_START: u32 = 0x1d400;
const MATHEMATICAL_LATIN_END: u32 = 0x1d6a3;
const LATIN_ALPHABET_LEN: u32 = 26;
const LATIN_STYLE_LEN: u32 = LATIN_ALPHABET_LEN * 2;
/// The five mathematical digit styles all have the same ASCII decimal value.
const MATHEMATICAL_DIGIT_START: u32 = 0x1d7ce;
const MATHEMATICAL_DIGIT_END: u32 = 0x1d7ff;
const DECIMAL_DIGITS: u32 = 10;

/// Mathematical letters allocated in the Letterlike Symbols block.
const LETTERLIKE_LATIN: &[(char, char)] = &[
    ('\u{2102}', 'C'),
    ('\u{210a}', 'g'),
    ('\u{210b}', 'H'),
    ('\u{210c}', 'H'),
    ('\u{210d}', 'H'),
    ('\u{210e}', 'h'),
    ('\u{2110}', 'I'),
    ('\u{2111}', 'I'),
    ('\u{2112}', 'L'),
    ('\u{2113}', 'l'),
    ('\u{2115}', 'N'),
    ('\u{2119}', 'P'),
    ('\u{211a}', 'Q'),
    ('\u{211b}', 'R'),
    ('\u{211c}', 'R'),
    ('\u{211d}', 'R'),
    ('\u{2124}', 'Z'),
    ('\u{2128}', 'Z'),
    ('\u{212a}', 'K'),
    ('\u{212c}', 'B'),
    ('\u{212d}', 'C'),
    ('\u{212f}', 'e'),
    ('\u{2130}', 'E'),
    ('\u{2131}', 'F'),
    ('\u{2133}', 'M'),
    ('\u{2134}', 'o'),
    ('\u{2139}', 'i'),
    ('\u{2145}', 'D'),
    ('\u{2146}', 'd'),
    ('\u{2147}', 'e'),
    ('\u{2148}', 'i'),
    ('\u{2149}', 'j'),
];

/// Cached boundaries are absolute UTF-8 offsets in the original borrowed message.
/// OWNERSHIP-15: only offsets returned by str searches construct these ranges.
struct UrlContext {
    span: std::ops::Range<usize>,
    authority_end: usize,
}

impl UrlContext {
    fn at_separator(msg: &str, separator: usize, floor: usize) -> Option<Self> {
        let offset = scan_charge::charged_scheme_start(msg, separator, floor);
        let run = url_scan::next_url_run(&msg[offset..])?;
        let authority_end = offset + run.authority_end;
        let span = offset + run.span.start..offset + run.span.end;
        Some(Self {
            span,
            authority_end,
        })
    }
}

/// Keep keys; mask values to line end or closing quote. Discover each URL only
/// when its scheme separator is reached; never search ahead into an owned value.
pub(super) fn redact_connection_options(msg: &str) -> String {
    let mut text = String::with_capacity(msg.len());
    let mut resume = 0;
    let mut pending_url: Option<UrlContext> = None;
    // Every input character is visited once, including characters skipped under
    // a value's ownership. Each search below charges the bytes it walks (#8674).
    scan_charge::charge(msg.len());
    for (offset, separator) in msg.char_indices() {
        if offset < resume {
            continue;
        }
        if pending_url
            .as_ref()
            .is_some_and(|url| offset >= url.span.end)
        {
            pending_url = None;
        }
        if pending_url.is_none() && msg[offset..].starts_with(SCHEME_SEPARATOR) {
            pending_url = UrlContext::at_separator(msg, offset, resume);
        }
        if !matches!(credential_key_char(separator), Some('=' | ':')) {
            continue;
        }
        // The authority owns its separators. Path/query/fragment keys retain
        // the complete-value masking posture of ruling 6717162013.
        if pending_url
            .as_ref()
            .is_some_and(|url| url.span.start <= offset && offset < url.authority_end)
        {
            continue;
        }
        if credential_key(&msg[resume..offset]) {
            let value = &msg[offset + separator.len_utf8()..];
            let start = msg.len() - value.trim_start().len();
            let end = connection_value_end(&msg[start..]);
            scan_charge::charge(start - offset + end + 1);
            text.push_str(&msg[resume..start]);
            text.push_str(URL_PASSWORD_MASK);
            resume = start + end;
        }
    }
    text.push_str(&msg[resume..]);
    text
}

/// Key slices between successive separators are disjoint; quoted slices may
/// overlap at most once per quote spelling. Normalization therefore stays linear.
fn credential_key(prefix: &str) -> bool {
    let untrimmed = prefix.len();
    let prefix = prefix.trim_end();
    scan_charge::charge(untrimmed - prefix.len() + 1);
    let key = if let Some(quote) = prefix.chars().last().filter(|ch| matches!(ch, '\'' | '"')) {
        let inner = &prefix[..prefix.len() - quote.len_utf8()];
        let Some(start) = scan_charge::charged_rfind(inner.rfind(quote), inner.len()) else {
            return false;
        };
        &inner[start + quote.len_utf8()..]
    } else {
        let key = prefix
            .rsplit_once(|ch: char| {
                credential_key_char(ch).is_some_and(|folded| {
                    !(folded.is_alphanumeric() || CREDENTIAL_KEY_PUNCTUATION.contains(&folded))
                })
            })
            .map_or(prefix, |(_, key)| key);
        scan_charge::charge(key.len() + 1);
        key
    };
    let normalized: String = key
        .chars()
        .filter_map(credential_key_char)
        .filter(|ch| !CREDENTIAL_KEY_PUNCTUATION.contains(ch))
        .flat_map(char::to_lowercase)
        .collect();
    scan_charge::charge_key_match(key.len(), normalized.len());
    EXACT_CREDENTIAL_KEYS.contains(&normalized.as_str())
        || CREDENTIAL_OPTION_KEYS
            .iter()
            .any(|name| normalized.contains(name))
}

/// Drop format/ignorable code points, then fold compatibility ASCII and math
/// Latin/digits without changing source offsets (OWNERSHIP-15).
/// Checked scalar construction retains the original character on invalid input.
fn credential_key_char(ch: char) -> Option<char> {
    if credential_key_ignorable(ch) {
        return None;
    }
    let code = u32::from(ch);
    let folded = if (FULLWIDTH_ASCII_START..=FULLWIDTH_ASCII_END).contains(&code) {
        char::from_u32(code - FULLWIDTH_ASCII_OFFSET)
    } else if (MATHEMATICAL_LATIN_START..=MATHEMATICAL_LATIN_END).contains(&code) {
        let letter = (code - MATHEMATICAL_LATIN_START) % LATIN_STYLE_LEN;
        let base = if letter < LATIN_ALPHABET_LEN {
            'A'
        } else {
            'a'
        };
        char::from_u32(u32::from(base) + letter % LATIN_ALPHABET_LEN)
    } else if (MATHEMATICAL_DIGIT_START..=MATHEMATICAL_DIGIT_END).contains(&code) {
        char::from_u32(u32::from('0') + (code - MATHEMATICAL_DIGIT_START) % DECIMAL_DIGITS)
    } else if let Some((_, folded)) = LETTERLIKE_LATIN.iter().find(|(letter, _)| *letter == ch) {
        Some(*folded)
    } else if CREDENTIAL_KEY_DASHES.contains(&ch) {
        Some('-')
    } else {
        Some(ch)
    };
    Some(folded.unwrap_or(ch))
}

/// Unicode Cf ranges copy the landed `yaml_frontmatter` classification.
/// Variation selectors and other default-ignorable fillers also carry no key text.
/// CONST-01: this range-only predicate can be evaluated at compile time.
const fn credential_key_ignorable(ch: char) -> bool {
    matches!(ch,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}'
        | '\u{890}'..='\u{891}' | '\u{8e2}' | '\u{180e}'
        | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}'
        | '\u{110bd}' | '\u{110cd}' | '\u{13430}'..='\u{1343f}'
        | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}'
        | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'
        | '\u{34f}' | '\u{115f}'..='\u{1160}' | '\u{17b4}'..='\u{17b5}'
        | '\u{180b}'..='\u{180d}' | '\u{180f}' | '\u{3164}'
        | '\u{fe00}'..='\u{fe0f}' | '\u{ffa0}' | '\u{e0100}'..='\u{e01ef}'
    )
}
