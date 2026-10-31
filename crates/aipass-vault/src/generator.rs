// SPDX-License-Identifier: Apache-2.0
//! Password generator (CONTRACTS §2.6, design doc §6.2) and a parser for the Apple
//! `passwordrules` attribute (`minlength`, `maxlength`, `required`, `allowed`,
//! `max-consecutive`).
//!
//! Every character is drawn uniformly from the alphabet with rejection sampling on the OS
//! CSPRNG ([`aipass_crypto::rng::random_below`]); whole candidates that violate a
//! constraint (each required class present, max consecutive identical characters) are
//! rejected and redrawn, so the result is uniform over all valid passwords.
//! **Models never generate passwords** — only this trusted code does.

use std::collections::BTreeSet;

use aipass_crypto::SecretString;
use aipass_types::vault::PasswordRules;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// Lower-case letters.
pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
/// Upper-case letters.
pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Digits.
pub const DIGITS: &str = "0123456789";
/// The `special` class of the passwordrules syntax (space is excluded when generating).
pub const SPECIAL: &str = "-~!@#$%^&*_+=`|(){}[:;\"'<>,.?]/\\";
/// Maximum rejected candidates before giving up (only reachable with contradictory rules).
pub const MAX_ATTEMPTS: u32 = 10_000;

fn set_of(s: &str) -> BTreeSet<char> {
    s.chars().collect()
}

fn ascii_printable() -> BTreeSet<char> {
    // 0x21..=0x7e: printable without space
    (0x21u8..=0x7e).map(char::from).collect()
}

fn generate_with(
    alphabet: &[char],
    required: &[BTreeSet<char>],
    length: usize,
    max_consecutive: Option<u32>,
) -> Result<SecretString> {
    if alphabet.is_empty() || length == 0 {
        return Err(VaultError::InvalidInput(
            "password alphabet or length is empty",
        ));
    }
    if required
        .iter()
        .any(|r| r.is_empty() || !r.iter().any(|c| alphabet.contains(c)))
    {
        return Err(VaultError::InvalidInput(
            "a required character class has no allowed characters",
        ));
    }
    if required.len() > length {
        return Err(VaultError::InvalidInput(
            "password is too short for the required character classes",
        ));
    }
    let n = u32::try_from(alphabet.len())
        .map_err(|_| VaultError::InvalidInput("alphabet too large"))?;
    for _ in 0..MAX_ATTEMPTS {
        let mut buf: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(length));
        for _ in 0..length {
            let i = aipass_crypto::rng::random_below(n)? as usize;
            buf.push(alphabet[i]);
        }
        if !required
            .iter()
            .all(|set| buf.iter().any(|c| set.contains(c)))
        {
            continue;
        }
        if let Some(maxc) = max_consecutive
            && maxc > 0
        {
            let mut run = 1u32;
            let mut ok = true;
            for w in buf.windows(2) {
                if w[0] == w[1] {
                    run += 1;
                    if run > maxc {
                        ok = false;
                        break;
                    }
                } else {
                    run = 1;
                }
            }
            if !ok {
                continue;
            }
        }
        let s: String = buf.iter().collect();
        return Ok(SecretString::new(s));
    }
    Err(VaultError::InvalidInput(
        "password rules cannot be satisfied",
    ))
}

/// Generate a password for [`PasswordRules`].
pub fn generate_password(rules: &PasswordRules) -> Result<SecretString> {
    rules.validate().map_err(VaultError::InvalidInput)?;
    let ambiguous = set_of(PasswordRules::AMBIGUOUS);
    let filter = |s: BTreeSet<char>| -> BTreeSet<char> {
        if rules.exclude_ambiguous {
            s.difference(&ambiguous).copied().collect()
        } else {
            s
        }
    };
    let mut classes: Vec<BTreeSet<char>> = Vec::new();
    if rules.lower {
        classes.push(filter(set_of(LOWER)));
    }
    if rules.upper {
        classes.push(filter(set_of(UPPER)));
    }
    if rules.digits {
        classes.push(filter(set_of(DIGITS)));
    }
    if rules.symbols && !rules.symbol_set.is_empty() {
        classes.push(filter(
            rules
                .symbol_set
                .chars()
                .filter(|c| c.is_ascii_graphic())
                .collect(),
        ));
    }
    classes.retain(|c| !c.is_empty());
    let alphabet: Vec<char> = classes
        .iter()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let required: Vec<BTreeSet<char>> = if rules.require_each_class {
        classes.clone()
    } else {
        Vec::new()
    };
    generate_with(&alphabet, &required, rules.length as usize, None)
}

/// Parsed Apple `passwordrules` attribute.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordRuleSpec {
    /// `minlength`.
    pub min_length: Option<u32>,
    /// `maxlength`.
    pub max_length: Option<u32>,
    /// Each `required:` property (a union of its classes).
    pub required: Vec<BTreeSet<char>>,
    /// Union of every `allowed:` property.
    pub allowed: BTreeSet<char>,
    /// `max-consecutive`.
    pub max_consecutive: Option<u32>,
}

fn parse_class_list(value: &str) -> Result<BTreeSet<char>> {
    let mut out = BTreeSet::new();
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    let bad = || VaultError::InvalidInput("invalid passwordrules character class");
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || c == ',' {
            i += 1;
            continue;
        }
        if c == '[' {
            i += 1;
            let mut closed = false;
            while i < chars.len() {
                let d = chars[i];
                if d == ']' {
                    // `]]` → a literal `]` followed by the closing bracket
                    if i + 1 < chars.len() && chars[i + 1] == ']' {
                        out.insert(']');
                        i += 2;
                        closed = true;
                        break;
                    }
                    i += 1;
                    closed = true;
                    break;
                }
                if d.is_ascii_graphic() || d == ' ' {
                    if d != ' ' {
                        out.insert(d);
                    }
                } else {
                    return Err(bad());
                }
                i += 1;
            }
            if !closed {
                return Err(bad());
            }
            continue;
        }
        let start = i;
        while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '-') {
            i += 1;
        }
        let ident: String = chars[start..i]
            .iter()
            .collect::<String>()
            .to_ascii_lowercase();
        match ident.as_str() {
            "upper" => out.extend(UPPER.chars()),
            "lower" => out.extend(LOWER.chars()),
            "digit" => out.extend(DIGITS.chars()),
            "special" => out.extend(SPECIAL.chars()),
            "ascii-printable" | "unicode" => out.extend(ascii_printable()),
            _ => return Err(bad()),
        }
    }
    Ok(out)
}

/// Parse an Apple `passwordrules` attribute value, e.g.
/// `minlength: 20; required: lower; required: upper; required: digit; required: [-().&@?'#,/"+]; max-consecutive: 2;`.
/// Unknown properties are ignored (forward compatibility); malformed values are errors.
pub fn parse_passwordrules(input: &str) -> Result<PasswordRuleSpec> {
    if input.len() > 4096 {
        return Err(VaultError::InvalidInput("passwordrules attribute too long"));
    }
    let mut spec = PasswordRuleSpec::default();
    // split on ';' outside of brackets
    let mut props = Vec::new();
    let mut cur = String::new();
    let mut depth = false;
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '[' && !depth {
            depth = true;
        } else if c == ']' && depth {
            if i + 1 < chars.len() && chars[i + 1] == ']' {
                cur.push(']');
                i += 1;
            }
            depth = false;
        }
        if c == ';' && !depth {
            props.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    if !cur.trim().is_empty() {
        props.push(cur);
    }
    let int = |v: &str| -> Result<u32> {
        v.trim()
            .parse::<u32>()
            .map_err(|_| VaultError::InvalidInput("invalid passwordrules number"))
    };
    for p in props {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let Some((name, value)) = p.split_once(':') else {
            return Err(VaultError::InvalidInput("invalid passwordrules property"));
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "minlength" => spec.min_length = Some(int(value)?),
            "maxlength" => spec.max_length = Some(int(value)?),
            "max-consecutive" => {
                let v = int(value)?;
                spec.max_consecutive = Some(spec.max_consecutive.map_or(v, |old| old.min(v)));
            }
            "required" => spec.required.push(parse_class_list(value)?),
            "allowed" => spec.allowed.extend(parse_class_list(value)?),
            _ => {}
        }
    }
    if let (Some(a), Some(b)) = (spec.min_length, spec.max_length)
        && a > b
    {
        return Err(VaultError::InvalidInput(
            "passwordrules minlength exceeds maxlength",
        ));
    }
    Ok(spec)
}

impl PasswordRuleSpec {
    /// Effective alphabet: `allowed` ∪ every required class (ASCII printable without space
    /// when nothing is specified).
    pub fn alphabet(&self) -> BTreeSet<char> {
        let mut a = self.allowed.clone();
        for r in &self.required {
            a.extend(r.iter().copied());
        }
        if a.is_empty() {
            a = ascii_printable();
        }
        a
    }

    /// Length used for generation: `preferred` (default 20) clamped to the site's bounds
    /// and to 1..=128.
    pub fn effective_length(&self, preferred: Option<u32>) -> u32 {
        let lo = self.min_length.unwrap_or(1).max(1);
        let hi = self
            .max_length
            .unwrap_or(PasswordRules::MAX_LEN)
            .clamp(1, PasswordRules::MAX_LEN);
        preferred.unwrap_or(20).clamp(lo.min(hi), hi)
    }

    /// Lossy conversion to [`PasswordRules`] (for storing as an entry's `password_rules`).
    pub fn to_password_rules(&self, preferred: Option<u32>) -> PasswordRules {
        let a = self.alphabet();
        let lower = a.iter().any(char::is_ascii_lowercase);
        let upper = a.iter().any(char::is_ascii_uppercase);
        let digits = a.iter().any(char::is_ascii_digit);
        let symbol_set: String = a.iter().filter(|c| c.is_ascii_punctuation()).collect();
        PasswordRules {
            length: self
                .effective_length(preferred)
                .clamp(PasswordRules::MIN_LEN, PasswordRules::MAX_LEN),
            lower,
            upper,
            digits,
            symbols: !symbol_set.is_empty(),
            symbol_set: if symbol_set.is_empty() {
                PasswordRules::DEFAULT_SYMBOLS.to_owned()
            } else {
                symbol_set
            },
            exclude_ambiguous: false,
            require_each_class: true,
        }
    }
}

/// Generate a password that satisfies a parsed `passwordrules` spec.
pub fn generate_from_spec(
    spec: &PasswordRuleSpec,
    preferred_length: Option<u32>,
) -> Result<SecretString> {
    let alphabet: Vec<char> = spec.alphabet().into_iter().collect();
    let len = spec.effective_length(preferred_length) as usize;
    generate_with(&alphabet, &spec.required, len, spec.max_consecutive)
}

/// Generate for a site: `passwordrules` (if present) wins over `rules`; otherwise `rules`
/// (default rules when `None`) with an optional length override.
pub fn generate_for_site(
    rules: Option<&PasswordRules>,
    passwordrules: Option<&str>,
    length: Option<u32>,
) -> Result<SecretString> {
    if let Some(pr) = passwordrules.filter(|s| !s.trim().is_empty()) {
        let spec = parse_passwordrules(pr)?;
        return generate_from_spec(&spec, length);
    }
    let mut r = rules.cloned().unwrap_or_default();
    if let Some(l) = length {
        r.length = l;
    }
    generate_password(&r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_cover_every_class() {
        for _ in 0..200 {
            let p = generate_password(&PasswordRules::default()).unwrap();
            let s = p.expose();
            assert_eq!(s.chars().count(), 20);
            assert!(s.chars().any(|c| c.is_ascii_lowercase()));
            assert!(s.chars().any(|c| c.is_ascii_uppercase()));
            assert!(s.chars().any(|c| c.is_ascii_digit()));
            assert!(
                s.chars()
                    .any(|c| PasswordRules::DEFAULT_SYMBOLS.contains(c))
            );
        }
    }

    #[test]
    fn ambiguous_and_bounds() {
        let r = PasswordRules {
            length: 64,
            exclude_ambiguous: true,
            ..Default::default()
        };
        for _ in 0..50 {
            let p = generate_password(&r).unwrap();
            assert!(
                !p.expose()
                    .chars()
                    .any(|c| PasswordRules::AMBIGUOUS.contains(c))
            );
        }
        assert!(
            generate_password(&PasswordRules {
                length: 7,
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            generate_password(&PasswordRules {
                length: 129,
                ..Default::default()
            })
            .is_err()
        );
        let digits_only = PasswordRules {
            lower: false,
            upper: false,
            symbols: false,
            length: 8,
            ..Default::default()
        };
        assert!(
            generate_password(&digits_only)
                .unwrap()
                .expose()
                .chars()
                .all(|c| c.is_ascii_digit())
        );
    }

    #[test]
    fn passwordrules_parser() {
        let s = parse_passwordrules(
            "minlength: 8; maxlength: 16; required: lower; required: upper; required: digit; required: [-().&@?'#,/\"+]; max-consecutive: 2;",
        )
        .unwrap();
        assert_eq!(s.min_length, Some(8));
        assert_eq!(s.max_length, Some(16));
        assert_eq!(s.required.len(), 4);
        assert!(
            s.required[3].contains(&'&')
                && s.required[3].contains(&'"')
                && s.required[3].contains(&',')
        );
        assert_eq!(s.max_consecutive, Some(2));
        for _ in 0..100 {
            let p = generate_from_spec(&s, None).unwrap();
            let v: Vec<char> = p.expose().chars().collect();
            assert_eq!(v.len(), 16);
            assert!(v.windows(3).all(|w| !(w[0] == w[1] && w[1] == w[2])));
            assert!(v.iter().any(|c| s.required[3].contains(c)));
            assert!(v.iter().all(|c| s.alphabet().contains(c)));
        }
        let u = parse_passwordrules("required: upper, digit; allowed: [-]];").unwrap();
        assert!(u.required[0].contains(&'A') && u.required[0].contains(&'7'));
        assert!(u.allowed.contains(&'-') && u.allowed.contains(&']'));
        assert!(parse_passwordrules("required: nonsense;").is_err());
        assert!(parse_passwordrules("minlength: 20; maxlength: 10").is_err());
        assert!(parse_passwordrules("required: [abc").is_err());
        let site = generate_for_site(
            None,
            Some("required: digit; allowed: lower; maxlength: 12"),
            None,
        )
        .unwrap();
        assert_eq!(site.expose().len(), 12);
        let r = parse_passwordrules("minlength: 12; required: lower; required: digit")
            .unwrap()
            .to_password_rules(None);
        assert!(r.lower && r.digits && !r.upper);
    }
}
