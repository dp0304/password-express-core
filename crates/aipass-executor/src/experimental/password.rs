// SPDX-License-Identifier: Apache-2.0
//! CSPRNG password generation for adapter-driven sign-ups (models never generate passwords,
//! design doc §6.2). Uniform selection with rejection sampling from the OS CSPRNG; when
//! `require_each_class` is set, candidates lacking a class are rejected and regenerated
//! (uniform over the valid set).

use aipass_crypto::SecretString;
use aipass_types::ApiError;
use aipass_types::vault::PasswordRules;
use zeroize::Zeroizing;

use crate::errors;

/// Generate a password following `rules`.
pub fn generate(rules: &PasswordRules) -> Result<SecretString, ApiError> {
    rules
        .validate()
        .map_err(|_| errors::invalid("密码规则无效", "Invalid password rules."))?;
    let ambiguous = |c: char| rules.exclude_ambiguous && PasswordRules::AMBIGUOUS.contains(c);
    let mut classes: Vec<Vec<char>> = Vec::new();
    if rules.lower {
        classes.push(('a'..='z').filter(|c| !ambiguous(*c)).collect());
    }
    if rules.upper {
        classes.push(('A'..='Z').filter(|c| !ambiguous(*c)).collect());
    }
    if rules.digits {
        classes.push(('0'..='9').filter(|c| !ambiguous(*c)).collect());
    }
    if rules.symbols && !rules.symbol_set.is_empty() {
        let mut s: Vec<char> = rules
            .symbol_set
            .chars()
            .filter(|c| !ambiguous(*c))
            .collect();
        s.sort_unstable();
        s.dedup();
        classes.push(s);
    }
    classes.retain(|c| !c.is_empty());
    if classes.is_empty() || (rules.require_each_class && classes.len() > rules.length as usize) {
        return Err(errors::invalid("密码规则无效", "Invalid password rules."));
    }
    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    for _ in 0..1000 {
        let mut pw = Zeroizing::new(String::with_capacity(rules.length as usize));
        for _ in 0..rules.length {
            let i = aipass_crypto::rng::random_below(alphabet.len() as u32)
                .map_err(|_| ApiError::internal())? as usize;
            pw.push(alphabet[i]);
        }
        if !rules.require_each_class || classes.iter().all(|c| pw.chars().any(|x| c.contains(&x))) {
            return Ok(SecretString::new(pw.to_string()));
        }
    }
    Err(ApiError::internal())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_rules() {
        let r = PasswordRules::default();
        let p = generate(&r).unwrap();
        assert_eq!(p.expose().chars().count(), 20);
        assert!(p.expose().chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.expose().chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.expose().chars().any(|c| c.is_ascii_digit()));
        let r = PasswordRules {
            length: 12,
            symbols: false,
            exclude_ambiguous: true,
            ..PasswordRules::default()
        };
        for _ in 0..50 {
            let p = generate(&r).unwrap();
            assert!(
                p.expose()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() && !"Il1O0o".contains(c))
            );
        }
        assert_ne!(generate(&r).unwrap(), generate(&r).unwrap());
    }
}
