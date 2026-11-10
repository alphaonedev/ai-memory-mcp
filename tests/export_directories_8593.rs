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
/// Exact refusal text of the private export directory check (#8716): it names the
/// permission bits compared, never a bare "mode", because special bits are ignored.
const REFUSAL_TEXT: &str = "export directory must be owned by the current user with permission bits 0700 (owner only); choose a private root or repair its permissions explicitly";
/// Special-bit modes the check accepts because only the nine permission bits are compared.
const ACCEPTED_ROOT_MODES: [u32; 4] = [0o700, 0o1700, 0o2700, 0o4700];
/// Modes the check refuses: group or other access, or a missing owner bit.
const REFUSED_ROOT_MODES: [u32; 5] = [0o750, 0o701, 0o770, 0o600, 0o777];
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
        assert!(message.contains(REFUSAL_TEXT), "{writer:?}: {message}");
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

/// Create the export root with exactly `mode` and prove the filesystem kept every bit.
fn root_with_mode(fixture: &Fixture, mode: u32) {
    fs::create_dir(&fixture.out).unwrap();
    fs::set_permissions(&fixture.out, fs::Permissions::from_mode(mode)).unwrap();
    assert_eq!(
        fs::metadata(&fixture.out).unwrap().permissions().mode() & MODE_WITH_SPECIAL_BITS,
        mode,
        "this filesystem did not keep mode {mode:#o} on a directory (#8716 table needs it)"
    );
}

#[test]
fn existing_root_mode_table_outcome_8716() {
    for writer in WRITERS {
        for mode in ACCEPTED_ROOT_MODES {
            let fixture = Fixture::new("team/alpha", "alice");
            root_with_mode(&fixture, mode);
            fixture
                .export(writer)
                .unwrap_or_else(|error| panic!("{writer:?} root {mode:#o} refused: {error:#}"));
            assert!(
                fixture.destination(writer).is_file(),
                "{writer:?} {mode:#o}"
            );
        }
        for mode in REFUSED_ROOT_MODES {
            let fixture = Fixture::new("team/alpha", "alice");
            root_with_mode(&fixture, mode);
            assert!(fixture.export(writer).is_err(), "{writer:?} root {mode:#o}");
            assert!(
                !fixture.destination(writer).exists(),
                "{writer:?} {mode:#o}"
            );
        }
    }
}

#[test]
fn existing_root_refusal_text_is_exact_8716() {
    for writer in WRITERS {
        for mode in REFUSED_ROOT_MODES {
            let fixture = Fixture::new("team/alpha", "alice");
            root_with_mode(&fixture, mode);
            let error = fixture.export(writer).expect_err("refused root");
            let message = format!("{error:#}");
            assert!(
                message.contains(REFUSAL_TEXT),
                "{writer:?} root {mode:#o}: {message}"
            );
            assert!(
                !message.contains("with mode 0700"),
                "{writer:?} root {mode:#o}: {message}"
            );
        }
    }
}
