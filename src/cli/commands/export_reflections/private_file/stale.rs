// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Best-effort stale-stage cleanup anchored to a checked directory descriptor.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::time::{Duration, SystemTime};

const STAGING_PREFIX: &[u8] = b".private-export-";
const STAGING_SUFFIX: &[u8] = b".stage";
const STALE_STAGE_AGE: Duration = Duration::from_hours(1);
const STALE_CLEANUP_WARNING: &str = "private_export_stale_stage_cleanup_failed";

/// Own the directory stream, including the descriptor transferred to fdopendir.
struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY (UNSAFE-01, OWNERSHIP-24): this is the sole owner of a
        // successful fdopendir result; closedir also releases its descriptor.
        if unsafe { libc::closedir(self.0) } != 0 {
            warn(&io::Error::last_os_error());
        }
    }
}

fn warn(error: &io::Error) {
    // Only syscall errors or fixed injected messages reach this boundary.
    // Neither payloads nor destination paths are logged.
    tracing::warn!(error = %error, message = STALE_CLEANUP_WARNING);
}

fn open_stream(directory: &File) -> io::Result<DirectoryStream> {
    // SAFETY (UNSAFE-01/02): a live checked descriptor and static C string.
    // Opening "." gives the iterator its own offset, unlike dup/try_clone.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY (UNSAFE-01, OWNERSHIP-24): fd is fresh and owned exactly once.
    let file = unsafe { File::from_raw_fd(fd) };
    // SAFETY (UNSAFE-01): valid owned directory fd. Ownership transfers only
    // on success, so File still closes it if fdopendir fails.
    let stream = unsafe { libc::fdopendir(file.as_raw_fd()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _ = file.into_raw_fd();
    Ok(DirectoryStream(stream))
}

// libc exposes the thread-local errno cell under each platform's native name.
// These aliases keep the same iterator on Unix rather than disabling cleanup.
#[cfg(any(target_os = "solaris", target_os = "illumos"))]
use libc::___errno as errno_location;
#[cfg(any(
    target_env = "newlib",
    target_os = "android",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "nuttx",
    target_os = "cygwin"
))]
use libc::__errno as errno_location;
#[cfg(any(
    target_os = "linux",
    target_os = "l4re",
    target_os = "emscripten",
    target_os = "dragonfly",
    target_os = "redox",
    target_os = "hurd",
    target_os = "fuchsia",
    target_os = "qurt"
))]
use libc::__errno_location as errno_location;
#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
use libc::__error as errno_location;
#[cfg(target_os = "nto")]
use libc::__get_errno_ptr as errno_location;
#[cfg(target_os = "aix")]
use libc::_Errno as errno_location;
#[cfg(target_os = "haiku")]
use libc::_errnop as errno_location;

#[cfg(not(target_os = "vxworks"))]
fn clear_errno() -> io::Result<()> {
    // SAFETY (UNSAFE-01): the native accessor takes no arguments and returns
    // this thread's errno cell. Check the pointer before writing (UNSAFE-09).
    let cell = std::ptr::NonNull::new(unsafe { errno_location() })
        .ok_or_else(|| io::Error::other("thread-local errno cell unavailable"))?;
    // SAFETY (UNSAFE-01/09): non-null native thread-local errno storage;
    // clearing it distinguishes EOF from readdir failure.
    unsafe { cell.as_ptr().write(0) };
    Ok(())
}

#[cfg(target_os = "vxworks")]
fn clear_errno() -> io::Result<()> {
    // SAFETY (UNSAFE-01): errnoSet writes this task's errno value and accepts 0.
    if unsafe { libc::errnoSet(0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_entry(stream: &mut DirectoryStream) -> io::Result<Option<&CStr>> {
    clear_errno()?;
    // SAFETY (UNSAFE-01/09): exclusive access to this live directory stream.
    // The returned entry remains valid until the next readdir/closedir call.
    let entry = unsafe { libc::readdir(stream.0) };
    if entry.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(0) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    // SAFETY (UNSAFE-01/09): readdir supplied an initialized, NUL-terminated
    // d_name; the borrow prevents another read or close while it is in use.
    Ok(Some(unsafe {
        CStr::from_ptr((&raw const (*entry).d_name).cast())
    }))
}

fn remove_stale(directory: &File, name: &CStr, now: SystemTime) -> io::Result<()> {
    let bytes = name.to_bytes();
    if !bytes.starts_with(STAGING_PREFIX) || !bytes.ends_with(STAGING_SUFFIX) {
        return Ok(());
    }
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY (UNSAFE-01/16): live directory fd, valid C name and writable
    // storage; AT_SYMLINK_NOFOLLOW prevents inspecting a symlink's target.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY (UNSAFE-16): successful fstatat initialized the entire stat.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(());
    }
    // SAFETY (UNSAFE-01/02): inspect the candidate through the same directory.
    // NOFOLLOW refuses a substituted symlink; NONBLOCK avoids blocking if a
    // same-user writer substitutes a FIFO between fstatat and openat.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY (UNSAFE-01, OWNERSHIP-24): successful openat returned a fresh fd.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || !now
            .duration_since(metadata.modified()?)
            .is_ok_and(|age| age > STALE_STAGE_AGE)
    {
        return Ok(());
    }
    drop(file);
    #[cfg(test)]
    {
        super::STALE_REMOVAL_ATTEMPTED.set(true);
        if super::FAIL_STALE_REMOVAL.get() {
            return Err(io::Error::other("private_export_stale_removal_injected"));
        }
    }
    // SAFETY (UNSAFE-01): remove this name only in the checked directory;
    // unlinkat never follows a replacement symlink or removes a directory.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn sweep(directory: &File) {
    #[cfg(test)]
    super::STAGING_SWEEP_COUNT.set(super::STAGING_SWEEP_COUNT.get().strict_add(1));
    let mut stream = match open_stream(directory) {
        Ok(stream) => stream,
        Err(error) => {
            warn(&error);
            return;
        }
    };
    let now = SystemTime::now();
    loop {
        match read_entry(&mut stream) {
            Ok(Some(name)) => {
                if let Err(error) = remove_stale(directory, name, now) {
                    warn(&error);
                }
            }
            Ok(None) => return,
            Err(error) => {
                warn(&error);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_of_directory_does_not_reuse_a_previous_os_error_8602() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/stale-export-8602");
        std::fs::create_dir_all(&root).unwrap();
        let scratch = tempfile::tempdir_in(root).unwrap();
        let directory = File::open(scratch.path()).unwrap();
        let mut stream = open_stream(&directory).unwrap();
        loop {
            // SAFETY (UNSAFE-01): a negative descriptor is always invalid;
            // this sets EBADF without closing any resource.
            assert_eq!(unsafe { libc::close(-1) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            if read_entry(&mut stream).unwrap().is_none() {
                break;
            }
        }
    }
}
