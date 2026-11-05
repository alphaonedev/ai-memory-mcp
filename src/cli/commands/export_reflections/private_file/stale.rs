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

// The shipping Unix targets provide these thread-local errno accessors.
#[cfg(target_vendor = "apple")]
fn clear_errno() {
    // SAFETY (UNSAFE-01): __error returns this thread's valid errno cell.
    unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY (UNSAFE-01): __errno_location returns this thread's errno cell.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn read_entry(stream: &mut DirectoryStream) -> io::Result<Option<&CStr>> {
    clear_errno();
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

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn read_entry(_: &mut DirectoryStream) -> io::Result<Option<&CStr>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative staging enumeration is unsupported on this platform",
    ))
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
