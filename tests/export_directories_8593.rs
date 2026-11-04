// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

mod export_privacy_fixture;

use export_privacy_fixture::{BROAD_DIR, Fixture, MODE_MASK, PRIVATE_DIR, Writer};
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

const WRITERS: [Writer; 3] = [Writer::Cli, Writer::ReflectionHook, Writer::PersonaHook];

#[test]
fn all_export_directory_components_are_private_8593() {
    for writer in WRITERS {
        let fixture = Fixture::new("team/alpha", "alice");
        let ancestor_mode = fs::metadata(fixture.dir.path()).unwrap().mode();
        fixture.export(writer).expect("export");
        let parent = fixture.namespace_dir(writer);
        let mut current = parent.as_path();
        loop {
            assert_eq!(
                fs::metadata(current).unwrap().mode() & MODE_MASK,
                PRIVATE_DIR,
                "{writer:?}: {}",
                current.display()
            );
            if current == fixture.out {
                break;
            }
            current = current.parent().unwrap();
        }
        assert_eq!(
            fs::metadata(fixture.dir.path()).unwrap().mode(),
            ancestor_mode
        );
    }
}

#[test]
fn broad_existing_root_is_refused_without_chmod_8593() {
    for writer in WRITERS {
        let fixture = Fixture::new("team/alpha", "alice");
        fs::create_dir(&fixture.out).unwrap();
        fs::set_permissions(&fixture.out, fs::Permissions::from_mode(BROAD_DIR)).unwrap();
        assert!(fixture.export(writer).is_err(), "{writer:?}");
        assert_eq!(
            fs::metadata(&fixture.out).unwrap().mode() & MODE_MASK,
            BROAD_DIR
        );
        assert!(!fixture.destination(writer).exists());
    }
}

#[test]
fn broad_existing_namespace_is_refused_without_chmod_8593() {
    for writer in WRITERS {
        let fixture = Fixture::new("team/alpha", "alice");
        fixture.prepare_private_parent(writer);
        let namespace = fixture.namespace_dir(writer);
        fs::set_permissions(&namespace, fs::Permissions::from_mode(BROAD_DIR)).unwrap();
        assert!(fixture.export(writer).is_err(), "{writer:?}");
        assert_eq!(
            fs::metadata(namespace).unwrap().mode() & MODE_MASK,
            BROAD_DIR
        );
        assert!(!fixture.destination(writer).exists());
    }
}

#[test]
fn namespace_symlink_is_refused_without_outside_publication_8593() {
    for writer in WRITERS {
        let fixture = Fixture::new("team", "alice");
        fs::create_dir(&fixture.out).unwrap();
        fs::set_permissions(&fixture.out, fs::Permissions::from_mode(PRIVATE_DIR)).unwrap();
        let outside = fixture.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(PRIVATE_DIR)).unwrap();
        symlink(
            fs::canonicalize(&outside).unwrap(),
            fixture.namespace_dir(writer),
        )
        .unwrap();
        assert!(fixture.export(writer).is_err(), "{writer:?}");
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    }
}
