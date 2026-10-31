// SPDX-License-Identifier: Apache-2.0
//! Three-way merge of entry payloads (CONTRACTS §3.2, design doc §10.3, A11).
//!
//! Per field against the common base version:
//! * changed on one side only → that side wins;
//! * **secret-bearing** fields (`secret`, `totp`, `fields[sensitive]`) changed on both
//!   sides to different values → **conflict**: the merged current keeps the remote secrets
//!   and the local version is appended to `conflict_versions` (automatic use pauses);
//! * **destination** fields (`username`, `urls`, `database`) are coupled to the secret:
//!   a conflicting change to them, or a secret change on one side combined with a
//!   different destination change on the other, is a conflict too — otherwise the merge
//!   could pair a new secret with a host / origin it was never set for (§9.6, §10.3). The
//!   merged current then keeps the remote secrets *and* the remote destination;
//! * other fields changed on both sides → remote wins, except `notes`, which are
//!   concatenated with a `--- 冲突副本 / conflict copy ---` marker.

use aipass_types::vault::{CustomField, EntryPayload};

/// Marker inserted between concatenated notes.
pub const NOTES_CONFLICT_MARKER: &str = "--- 冲突副本 / conflict copy ---";

/// Result of a merge.
#[derive(Debug, Clone)]
pub struct MergeOutcome {
    /// Payload to become the current version.
    pub merged: EntryPayload,
    /// A secret-bearing field conflicted: the local payload must be kept as a conflict
    /// version and automatic use paused.
    pub secret_conflict: bool,
}

fn pick<T: PartialEq + Clone>(base: &T, local: &T, remote: &T) -> (T, bool) {
    if local == base || local == remote {
        (remote.clone(), false)
    } else if remote == base {
        (local.clone(), false)
    } else {
        (remote.clone(), true)
    }
}

fn split_fields(f: &[CustomField]) -> (Vec<CustomField>, Vec<CustomField>) {
    f.iter().cloned().partition(|x| x.sensitive)
}

/// Merge `local` and `remote`, both derived from `base`.
pub fn merge3(base: &EntryPayload, local: &EntryPayload, remote: &EntryPayload) -> MergeOutcome {
    // secret-bearing
    let (b_sens, b_plain) = split_fields(&base.fields);
    let (l_sens, l_plain) = split_fields(&local.fields);
    let (r_sens, r_plain) = split_fields(&remote.fields);
    let (secret, c1) = pick(&base.secret, &local.secret, &remote.secret);
    let (totp, c2) = pick(&base.totp, &local.totp, &remote.totp);
    let (sens, c3) = pick(&b_sens, &l_sens, &r_sens);

    // destination (coupled to the secret)
    let (username, c4) = pick(&base.username, &local.username, &remote.username);
    let (urls, c5) = pick(&base.urls, &local.urls, &remote.urls);
    let (database, c6) = pick(&base.database, &local.database, &remote.database);
    let secrets_of = |p: &EntryPayload, sens: &Vec<CustomField>| {
        (p.secret.clone(), p.totp.clone(), sens.clone())
    };
    let dest_of = |p: &EntryPayload| (p.username.clone(), p.urls.clone(), p.database.clone());
    let (b_sec, l_sec, r_sec) = (
        secrets_of(base, &b_sens),
        secrets_of(local, &l_sens),
        secrets_of(remote, &r_sens),
    );
    let (b_dest, l_dest, r_dest) = (dest_of(base), dest_of(local), dest_of(remote));
    let dest_differs = l_dest != r_dest;
    let crossed = dest_differs
        && ((l_sec != b_sec && r_dest != b_dest) || (r_sec != b_sec && l_dest != b_dest));
    let secret_conflict = c1 || c2 || c3 || c4 || c5 || c6 || crossed;
    let (secret, totp, sens, username, urls, database) = if secret_conflict {
        (
            remote.secret.clone(),
            remote.totp.clone(),
            r_sens,
            remote.username.clone(),
            remote.urls.clone(),
            remote.database.clone(),
        )
    } else {
        (secret, totp, sens, username, urls, database)
    };

    // non-secret
    let (kind, _) = pick(&base.kind, &local.kind, &remote.kind);
    let (title, _) = pick(&base.title, &local.title, &remote.title);
    let (plain, _) = pick(&b_plain, &l_plain, &r_plain);
    let (project_id, _) = pick(&base.project_id, &local.project_id, &remote.project_id);
    let (tags, _) = pick(&base.tags, &local.tags, &remote.tags);
    let (lifecycle, _) = pick(&base.lifecycle, &local.lifecycle, &remote.lifecycle);
    let (password_rules, _) = pick(
        &base.password_rules,
        &local.password_rules,
        &remote.password_rules,
    );
    let (notes, notes_conflict) = pick(&base.notes, &local.notes, &remote.notes);
    let notes = if notes_conflict {
        let r = remote.notes.clone().unwrap_or_default();
        let l = local.notes.clone().unwrap_or_default();
        Some(format!("{r}\n\n{NOTES_CONFLICT_MARKER}\n{l}"))
    } else {
        notes
    };
    let mut fields = plain;
    fields.extend(sens);

    let merged = EntryPayload {
        kind,
        title,
        username,
        secret,
        urls,
        notes,
        totp,
        fields,
        database,
        project_id,
        tags,
        lifecycle,
        source: remote.source.clone(),
        password_rules,
        created_at: remote.created_at,
        updated_at: local.updated_at.max(remote.updated_at),
    };
    MergeOutcome {
        merged,
        secret_conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::SecretString;
    use aipass_types::vault::EntryKind;

    fn base() -> EntryPayload {
        let mut p = EntryPayload::new(EntryKind::Login, "Shop");
        p.username = Some("alice".into());
        p.secret = Some(SecretString::from("old"));
        p.notes = Some("n".into());
        p
    }

    #[test]
    fn one_sided_changes_merge() {
        let b = base();
        let mut l = b.clone();
        l.title = "Shop (local)".into();
        let mut r = b.clone();
        r.secret = Some(SecretString::from("new-remote"));
        let m = merge3(&b, &l, &r);
        assert!(!m.secret_conflict);
        assert_eq!(m.merged.title, "Shop (local)");
        assert_eq!(m.merged.secret.as_ref().unwrap().expose(), "new-remote");
    }

    #[test]
    fn both_changed_secret_conflicts_and_notes_concat() {
        let b = base();
        let mut l = b.clone();
        l.secret = Some(SecretString::from("local-pw"));
        l.notes = Some("local note".into());
        let mut r = b.clone();
        r.secret = Some(SecretString::from("remote-pw"));
        r.notes = Some("remote note".into());
        r.title = "Remote title".into();
        l.title = "Local title".into();
        let m = merge3(&b, &l, &r);
        assert!(m.secret_conflict);
        assert_eq!(m.merged.secret.as_ref().unwrap().expose(), "remote-pw");
        assert_eq!(m.merged.title, "Remote title");
        let n = m.merged.notes.unwrap();
        assert!(
            n.starts_with("remote note")
                && n.contains(NOTES_CONFLICT_MARKER)
                && n.ends_with("local note")
        );
        // same change on both sides is not a conflict
        let m2 = merge3(&b, &r, &r);
        assert!(!m2.secret_conflict);
    }

    fn db(host: &str, port: u16) -> aipass_types::vault::DatabaseInfo {
        serde_json::from_value(serde_json::json!({
            "engine": "postgres", "host": host, "port": port, "dbname": "app", "sslmode": "require"
        }))
        .unwrap()
    }

    /// CVS-06: a rotated secret is never paired with a destination it was not set for.
    #[test]
    fn secret_and_destination_are_coupled() {
        let mut b = base();
        b.kind = EntryKind::Database;
        b.secret = Some(SecretString::from("S1"));
        b.database = Some(db("db-old", 5432));
        // A: new host + new secret; B: new port on the old host
        let mut a = b.clone();
        a.database = Some(db("db-new", 5432));
        a.secret = Some(SecretString::from("S2"));
        let mut r = b.clone();
        r.database = Some(db("db-old", 6432));
        for (l, rr) in [(&a, &r), (&r, &a)] {
            let m = merge3(&b, l, rr);
            assert!(m.secret_conflict, "automatic use must pause");
            // the current version stays a coherent remote (secret, destination) pair
            assert_eq!(m.merged.secret, rr.secret);
            assert_eq!(m.merged.database, rr.database);
        }
        // secret changed on one side, destination (only) on the other
        let mut s_only = b.clone();
        s_only.secret = Some(SecretString::from("S3"));
        let mut d_only = b.clone();
        d_only.urls = vec!["https://evil.example".into()];
        for (l, rr) in [(&s_only, &d_only), (&d_only, &s_only)] {
            let m = merge3(&b, l, rr);
            assert!(m.secret_conflict);
            assert_eq!(m.merged.secret, rr.secret);
            assert_eq!(m.merged.urls, rr.urls);
        }
        // a secret rotation made together with the same destination change merges
        let mut both = b.clone();
        both.database = Some(db("db-new", 5432));
        both.secret = Some(SecretString::from("S4"));
        let mut same_dest = b.clone();
        same_dest.database = Some(db("db-new", 5432));
        let m = merge3(&b, &both, &same_dest);
        assert!(!m.secret_conflict);
        assert_eq!(m.merged.secret.as_ref().unwrap().expose(), "S4");
    }
}
