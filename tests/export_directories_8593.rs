// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

mod export_privacy_fixture;

use export_privacy_fixture::{BROAD_DIR, Fixture, MODE_MASK, PRIVATE_DIR, Writer};
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

const WRITERS: [Writer; 3] = [Writer::Cli, Writer::ReflectionHook, Writer::PersonaHook];
const MODE_WITH_SPECIAL_BITS: u32 = 0o7777;
const PRIVATE_SETGID_DIR: u32 = 0o2700;
#[cfg(target_os = "linux")]
const SETGID_PARENT: u32 = 0o2775;
#[cfg(target_os = "linux")]
const SETGID_BIT: u32 = 0o2000;

#[test]
fn private_setgid_directories_are_accepted_without_chmod_8593() {
    for writer in WRITERS {
        let fixture = Fixture::new("team/alpha", "alice");
        fixture.prepare_private_parent(writer);
        let namespace = fixture.namespace_dir(writer);
        for path in [&fixture.out, &namespace] {
            fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_SETGID_DIR)).unwrap();
        }
        fixture.export(writer).expect("private setgid export");
        for path in [&fixture.out, &namespace] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & MODE_WITH_SPECIAL_BITS,
                PRIVATE_SETGID_DIR,
                "{writer:?}: {}",
                path.display()
            );
        }
        assert!(fixture.destination(writer).is_file());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn inherited_setgid_parent_allows_all_exporters_8593() {
    for writer in WRITERS {
        let fixture = Fixture::new("team/alpha", "alice");
        fs::set_permissions(
            fixture.dir.path(),
            fs::Permissions::from_mode(SETGID_PARENT),
        )
        .unwrap();
        fixture.export(writer).expect("export below setgid parent");
        let namespace = fixture.namespace_dir(writer);
        let mut current = namespace.as_path();
        loop {
            let mode = fs::metadata(current).unwrap().mode();
            assert_eq!(mode & MODE_MASK, PRIVATE_DIR, "{writer:?}");
            assert_eq!(mode & SETGID_BIT, SETGID_BIT, "{writer:?}");
            if current == fixture.out {
                break;
            }
            current = current.parent().unwrap();
        }
        assert!(fixture.destination(writer).is_file());
    }
}

#[test]
fn namespace_refusal_identifies_the_directory_8593() {
    for writer in WRITERS {
        let fixture = Fixture::new("team/alpha", "alice");
        fixture.prepare_private_parent(writer);
        let namespace = fixture.namespace_dir(writer);
        fs::set_permissions(&namespace, fs::Permissions::from_mode(BROAD_DIR)).unwrap();
        let error = fixture.export(writer).expect_err("broad namespace refused");
        let message = format!("{error:#}");
        assert!(
            message.contains(&namespace.display().to_string()),
            "{writer:?}: {message}"
        );
        assert!(message.contains("mode 0700"), "{writer:?}: {message}");
    }
}

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
