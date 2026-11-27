//! Pins of the #10176 process-start gate, layer 1 (`clippy.toml` `disallowed-methods`).
//!
//! clippy reports a `disallowed-methods` entry whose path does not resolve as a
//! warning, and the strict clippy gate does not raise that warning to an error.
//! A misspelt or renamed entry would then silently stop guarding anything. Each
//! function below names exactly one entry as a function value, never calls it,
//! and carries an item-level `#[expect(clippy::disallowed_methods)]`. When an
//! entry stops resolving, the lint no longer fires in its function, the
//! expectation is unfulfilled and the strict clippy gate turns red here.
//!
//! The Linux-only libc names are pinned under `cfg(target_os = "linux")`, and
//! each target-only start or loader (BSD, Cygwin, `VxWorks`, PSP, WALI, the
//! Windows CRT, Haiku and the glibc `dlmopen`) under the cfg of the targets
//! libc 0.2.191 declares it for: the CI clippy jobs run on Linux glibc, and on
//! another target those names do not exist. The 29 entries that do not exist
//! on Linux glibc carry `allow-invalid = true` in `clippy.toml`, which drops
//! only the unresolved-path warning there; the pins below still go red on a
//! target that has the function if its entry stops resolving.
//! No function here starts a process: none is called with arguments that reach
//! the operating system, and the one test only takes each function value.

#[expect(
    clippy::disallowed_methods,
    reason = "pins the clippy.toml entry std::process::Command::new; names the function, never calls it (#10176)"
)]
fn pin_std_command_new() -> usize {
    let constructor = std::process::Command::new::<&str>;
    std::mem::size_of_val(&constructor)
}

#[expect(
    clippy::disallowed_methods,
    reason = "pins the clippy.toml entry tokio::process::Command::new; names the function, never calls it (#10176)"
)]
fn pin_tokio_command_new() -> usize {
    let constructor = tokio::process::Command::new::<&str>;
    std::mem::size_of_val(&constructor)
}

#[expect(
    clippy::disallowed_methods,
    reason = "pins the clippy.toml entry assert_cmd::Command::new; names the function, never calls it (#10176)"
)]
fn pin_assert_cmd_new() -> usize {
    let constructor = assert_cmd::Command::new::<&str>;
    std::mem::size_of_val(&constructor)
}

#[expect(
    clippy::disallowed_methods,
    reason = "pins the clippy.toml entry assert_cmd::Command::cargo_bin; names the function, never calls it (#10176)"
)]
fn pin_assert_cmd_cargo_bin() -> usize {
    let constructor = assert_cmd::Command::cargo_bin::<&str>;
    std::mem::size_of_val(&constructor)
}

#[expect(
    clippy::disallowed_methods,
    reason = "pins the clippy.toml entry assert_cmd::cargo::CommandCargoExt::cargo_bin; names the function, never calls it (#10176)"
)]
fn pin_command_cargo_ext_cargo_bin() -> usize {
    let constructor =
        <std::process::Command as assert_cmd::cargo::CommandCargoExt>::cargo_bin::<&str>;
    std::mem::size_of_val(&constructor)
}

#[expect(
    clippy::disallowed_methods,
    reason = "pins the clippy.toml entry ai_memory::spawn_audit::audited_command; names the function, never calls it (#10176)"
)]
fn pin_audited_command() -> usize {
    let constructor = ai_memory::spawn_audit::audited_command::<&str>;
    std::mem::size_of_val(&constructor)
}

#[expect(
    clippy::disallowed_methods,
    reason = "pins the clippy.toml entry ai_memory::spawn_audit::audited_tokio_command; names the function, never calls it (#10176)"
)]
fn pin_audited_tokio_command() -> usize {
    let constructor = ai_memory::spawn_audit::audited_tokio_command::<&str>;
    std::mem::size_of_val(&constructor)
}

#[expect(
    clippy::disallowed_methods,
    reason = "pins the clippy.toml entry libc::vfork; names the function, never calls it (#10176)"
)]
#[expect(
    deprecated,
    reason = "libc marks vfork deprecated; the pin only names it, so the entry stays guarded (#10176)"
)]
fn pin_libc_vfork() -> usize {
    let entry = libc::vfork;
    std::mem::size_of_val(&entry)
}

/// One pin per POSIX libc entry of `clippy.toml`; each names its function value only.
macro_rules! libc_pins {
    ($($(#[$cfg:meta])* $pin:ident => $name:ident;)+) => {
        $(
            $(#[$cfg])*
            #[expect(
                clippy::disallowed_methods,
                reason = "pins one libc entry of clippy.toml; names the function, never calls it (#10176)"
            )]
            fn $pin() -> usize {
                let entry = libc::$name;
                std::mem::size_of_val(&entry)
            }
        )+
        /// Every libc pin of this target, in the order of `clippy.toml`.
        const LIBC_PINS: &[fn() -> usize] = &[$($(#[$cfg])* $pin,)+];
    };
}

libc_pins! {
    pin_libc_fork => fork;
    #[cfg(target_os = "linux")]
    pin_libc_clone => clone;
    pin_libc_daemon => daemon;
    pin_libc_forkpty => forkpty;
    pin_libc_execl => execl;
    pin_libc_execle => execle;
    pin_libc_execlp => execlp;
    pin_libc_execv => execv;
    pin_libc_execve => execve;
    pin_libc_execvp => execvp;
    #[cfg(target_os = "linux")]
    pin_libc_execvpe => execvpe;
    pin_libc_fexecve => fexecve;
    #[cfg(target_os = "linux")]
    pin_libc_execveat => execveat;
    pin_libc_posix_spawn => posix_spawn;
    pin_libc_posix_spawnp => posix_spawnp;
    pin_libc_system => system;
    pin_libc_popen => popen;
    pin_libc_syscall => syscall;
    pin_libc_dlopen => dlopen;
    pin_libc_dlsym => dlsym;
    #[cfg(target_os = "linux")]
    pin_libc_dlvsym => dlvsym;
    #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "hurd"))]
    pin_libc_dlmopen => dlmopen;
    #[cfg(any(target_vendor = "apple", target_os = "freebsd", target_os = "dragonfly"))]
    #[allow(non_snake_case)]
    pin_libc_execvP => execvP;
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    pin_libc_exect => exect;
    #[cfg(target_os = "freebsd")]
    pin_libc_rfork => rfork;
    #[cfg(target_os = "freebsd")]
    pin_libc_pdfork => pdfork;
    #[cfg(target_os = "freebsd")]
    pin_libc_kld_load => kld_load;
    #[cfg(target_os = "cygwin")]
    pin_libc_dlfork => dlfork;
    #[cfg(windows)]
    pin_libc_execlpe => execlpe;
    #[cfg(windows)]
    pin_libc_wexecl => wexecl;
    #[cfg(windows)]
    pin_libc_wexecle => wexecle;
    #[cfg(windows)]
    pin_libc_wexeclp => wexeclp;
    #[cfg(windows)]
    pin_libc_wexeclpe => wexeclpe;
    #[cfg(windows)]
    pin_libc_wexecv => wexecv;
    #[cfg(windows)]
    pin_libc_wexecve => wexecve;
    #[cfg(windows)]
    pin_libc_wexecvp => wexecvp;
    #[cfg(windows)]
    pin_libc_wexecvpe => wexecvpe;
    #[cfg(target_os = "haiku")]
    pin_libc_load_image => load_image;
    #[cfg(target_os = "haiku")]
    pin_libc_load_add_on => load_add_on;
    #[cfg(target_os = "vxworks")]
    #[allow(non_snake_case)]
    pin_libc_rtpSpawn => rtpSpawn;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceKernelLoadExec => sceKernelLoadExec;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceKernelLoadModule => sceKernelLoadModule;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceKernelLoadModuleBufferUsbWlan => sceKernelLoadModuleBufferUsbWlan;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceKernelLoadModuleByID => sceKernelLoadModuleByID;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceKernelLoadModuleMs => sceKernelLoadModuleMs;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceUtilityLoadAvModule => sceUtilityLoadAvModule;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceUtilityLoadModule => sceUtilityLoadModule;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceUtilityLoadNetModule => sceUtilityLoadNetModule;
    #[cfg(target_os = "psp")]
    #[allow(non_snake_case)]
    pin_libc_sceUtilityLoadUsbModule => sceUtilityLoadUsbModule;
    #[cfg(all(target_os = "linux", target_env = "musl", target_arch = "wasm32"))]
    #[allow(non_snake_case)]
    pin_libc___syscall_SYS_execve => __syscall_SYS_execve;
    #[cfg(all(target_os = "linux", target_env = "musl", target_arch = "wasm32"))]
    #[allow(non_snake_case)]
    pin_libc___syscall_SYS_fork => __syscall_SYS_fork;
}

/// The number of `clippy.toml` `disallowed-methods` entries pinned on the CI
/// clippy target, Linux glibc: the 29 POSIX and Linux entries plus dlmopen.
/// Every other target-only entry is pinned under the cfg of its targets.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const LINUX_PIN_COUNT: usize = 30;

#[test]
fn every_pin_names_a_function_value_and_none_is_called() {
    let named = [
        pin_std_command_new,
        pin_tokio_command_new,
        pin_assert_cmd_new,
        pin_assert_cmd_cargo_bin,
        pin_command_cargo_ext_cargo_bin,
        pin_audited_command,
        pin_audited_tokio_command,
        pin_libc_vfork,
    ];
    // A function item is zero-sized: every pin returns 0 and starts nothing.
    for pin in named.iter().chain(LIBC_PINS) {
        assert_eq!(pin(), 0);
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    assert_eq!(named.len() + LIBC_PINS.len(), LINUX_PIN_COUNT);
}
