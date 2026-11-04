// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

mod export_privacy_fixture;

use export_privacy_fixture::{Fixture, MODE_MASK, OLD_CONTENT, PRIVATE_FILE, Writer};
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

#[test]
fn persona_file_is_private_before_and_after_replacement_8592() {
    let fixture = Fixture::new("team/alpha", "alice");
    fixture.prepare_private_parent(Writer::PersonaHook);
    fixture.export(Writer::PersonaHook).expect("initial export");
    let path = fixture.destination(Writer::PersonaHook);
    assert_eq!(
        fs::metadata(&path).unwrap().mode() & MODE_MASK,
        PRIVATE_FILE
    );
    fs::write(&path, OLD_CONTENT).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let mut old = fs::File::open(&path).unwrap();
    let old_inode = old.metadata().unwrap().ino();
    fixture.export(Writer::PersonaHook).expect("replacement");
    assert_eq!(
        fs::metadata(&path).unwrap().mode() & MODE_MASK,
        PRIVATE_FILE
    );
    assert_ne!(fs::metadata(&path).unwrap().ino(), old_inode);
    let mut old_bytes = Vec::new();
    old.read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, OLD_CONTENT);
}

#[test]
fn persona_destination_symlink_is_refused_without_target_change_8592() {
    let fixture = Fixture::new("team/alpha", "alice");
    fixture.prepare_private_parent(Writer::PersonaHook);
    let target = fixture.dir.path().join("operator-file");
    fs::write(&target, OLD_CONTENT).unwrap();
    symlink(
        fs::canonicalize(&target).unwrap(),
        fixture.destination(Writer::PersonaHook),
    )
    .unwrap();
    assert!(fixture.export(Writer::PersonaHook).is_err());
    assert_eq!(fs::read(target).unwrap(), OLD_CONTENT);
}

#[test]
fn persona_dot_components_cannot_escape_or_alias_root_8592() {
    for (namespace, entity) in [
        ("..", "alice"),
        (".", "alice"),
        ("team", ".."),
        ("team", "."),
    ] {
        let fixture = Fixture::new(namespace, entity);
        assert!(
            fixture.export(Writer::PersonaHook).is_err(),
            "{namespace}/{entity}"
        );
        assert!(!fixture.dir.path().join("alice.md").exists());
        assert!(!fixture.out.join("alice.md").exists());
    }
}
