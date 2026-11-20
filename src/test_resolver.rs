//! #9367 — THE production view of a source file for every lib source pin: the
//! ONE resolver the integration-test structural gates already share
//! (#4198/#4200, tests/common/cfg_test_modules.rs), included once for the
//! whole lib with `#[path]`, never copied, so a lib pin and an
//! integration-test pin cannot disagree on what is test-only.
//!
//! It lives in its own module, not in `crate::test_support`: that file is a
//! use-target of the #8346 census, read as an allow-list of items with no
//! `#[path]`, and one lib crate loading the file twice is
//! `clippy::duplicate_mod` (#6569).

#[path = "../tests/common/cfg_test_modules.rs"]
pub(crate) mod cfg_test_modules;
