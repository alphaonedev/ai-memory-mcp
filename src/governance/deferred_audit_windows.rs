//! Windows owner-only storage primitives for deferred-audit crash evidence.

use anyhow::{Context as _, Result};
use std::ffi::c_void;
use std::fs::File;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, EqualSid,
    GetAclInformation, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo,
    GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns a successful Win32 handle exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: the pointer was allocated by a Win32 LocalAlloc-family API.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct CurrentSid {
    storage: Vec<usize>,
}

impl CurrentSid {
    fn as_ptr(&self) -> PSID {
        // The token buffer is usize-aligned and remains alive for this borrow.
        unsafe { (*self.storage.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

struct PrivateDescriptor {
    allocation: LocalAllocation,
}

impl PrivateDescriptor {
    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.allocation.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObjectKind {
    File,
    Directory,
}

pub(super) fn create_or_open_private_directory(path: &Path) -> Result<(File, bool)> {
    let sid = current_user_sid()?;
    let descriptor = private_descriptor(&sid, ObjectKind::Directory)?;
    let wide = wide_path(path)?;
    let attributes = security_attributes(&descriptor);
    // SAFETY: the UTF-16 path and security descriptor remain alive for the call.
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } != 0;
    if !created {
        // SAFETY: GetLastError immediately follows the failed Win32 call.
        let code = unsafe { GetLastError() };
        if code != ERROR_ALREADY_EXISTS {
            return Err(std::io::Error::from_raw_os_error(code.cast_signed())).with_context(|| {
                format!("create private deferred-audit directory {}", path.display())
            });
        }
    }
    let file = open_existing(path, ObjectKind::Directory, true)?;
    validate_private_handle(
        &file,
        ObjectKind::Directory,
        "deferred-audit spool directory",
    )?;
    Ok((file, created))
}

pub(super) fn open_or_create_private_file(path: &Path, label: &str) -> Result<File> {
    match create_new_private_file(path, label) {
        Ok(file) => Ok(file),
        Err(error) if is_already_exists(&error) => {
            let file = open_existing(path, ObjectKind::File, true)
                .with_context(|| format!("open existing {label} {}", path.display()))?;
            validate_private_handle(&file, ObjectKind::File, label)?;
            Ok(file)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn create_new_private_file(path: &Path, label: &str) -> Result<File> {
    let sid = current_user_sid()?;
    let descriptor = private_descriptor(&sid, ObjectKind::File)?;
    let wide = wide_path(path)?;
    let attributes = security_attributes(&descriptor);
    // SAFETY: arguments point to live buffers; CREATE_NEW never opens an existing object.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("create private {label} {}", path.display()));
    }
    // SAFETY: successful CreateFileW returned an owned file handle.
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    validate_private_handle(&file, ObjectKind::File, label)?;
    Ok(file)
}

pub(super) fn open_private_file(path: &Path, label: &str, writable: bool) -> Result<File> {
    let file = open_existing(path, ObjectKind::File, writable)
        .with_context(|| format!("open private {label} {}", path.display()))?;
    validate_private_handle(&file, ObjectKind::File, label)?;
    Ok(file)
}

fn open_existing(path: &Path, kind: ObjectKind, writable: bool) -> Result<File> {
    let wide = wide_path(path)?;
    let mut access = FILE_GENERIC_READ | READ_CONTROL | SYNCHRONIZE;
    if writable {
        access |= FILE_GENERIC_WRITE;
    }
    if kind == ObjectKind::Directory {
        access |= FILE_LIST_DIRECTORY;
    }
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if kind == ObjectKind::Directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
    // SAFETY: the UTF-16 path remains live; OPEN_EXISTING does not consume pointers.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("open Windows filesystem object");
    }
    // SAFETY: successful CreateFileW returned an owned handle compatible with File.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn validate_private_handle(file: &File, kind: ObjectKind, label: &str) -> Result<()> {
    let raw = file.as_raw_handle().cast::<c_void>();
    let handle = raw as HANDLE;
    let mut tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { zeroed() };
    // SAFETY: tag points to a correctly sized writable structure and handle is live.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut tag).cast(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).expect("tag size fits u32"),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("inspect {label}"));
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!("{label} is a reparse point");
    }
    let is_directory = tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_directory != (kind == ObjectKind::Directory) {
        anyhow::bail!("{label} has the wrong filesystem object type");
    }

    let sid = current_user_sid()?;
    let expected = private_descriptor(&sid, kind)?;
    let expected_acl = descriptor_dacl(expected.as_ptr())?;
    let expected_bytes = acl_bytes(expected_acl)?;

    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut actual_descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: output pointers are valid and the handle remains open for the call.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut actual_descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status.cast_signed()))
            .with_context(|| format!("read {label} security descriptor"));
    }
    let _actual_guard = LocalAllocation(actual_descriptor);
    if owner.is_null() || dacl.is_null() {
        anyhow::bail!("{label} has a missing owner or null DACL");
    }
    // SAFETY: both SID pointers are valid for the lifetime of their backing buffers.
    if unsafe { EqualSid(owner, sid.as_ptr()) } == 0 {
        anyhow::bail!("{label} is not owned by the daemon token user");
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: actual_descriptor is a valid descriptor returned by GetSecurityInfo.
    if unsafe {
        GetSecurityDescriptorControl(actual_descriptor, &raw mut control, &raw mut revision)
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("inspect {label} DACL control"));
    }
    if control & SE_DACL_PROTECTED == 0 {
        anyhow::bail!("{label} DACL inherits permissions");
    }
    if acl_bytes(dacl)? != expected_bytes {
        anyhow::bail!("{label} DACL is not the canonical daemon-owner-only policy");
    }
    Ok(())
}

fn current_user_sid() -> Result<CurrentSid> {
    let mut token: HANDLE = null_mut();
    // SAFETY: output pointer is valid; pseudo-process handle needs no close.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("open current process token");
    }
    let _token = OwnedHandle(token);
    let mut bytes = 0_u32;
    // SAFETY: the documented first call obtains the required buffer size.
    let first = unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &raw mut bytes) };
    if first != 0 {
        anyhow::bail!("unexpected zero-length current token user information");
    }
    // SAFETY: GetLastError immediately follows GetTokenInformation.
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || bytes == 0 {
        return Err(std::io::Error::last_os_error()).context("size current token user information");
    }
    let word = size_of::<usize>();
    let words = usize::try_from(bytes)
        .context("token user buffer length")?
        .div_ceil(word);
    let mut storage = vec![0_usize; words];
    // SAFETY: storage is aligned and contains at least `bytes` writable bytes.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast(),
            bytes,
            &raw mut bytes,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("read current token user information");
    }
    Ok(CurrentSid { storage })
}

fn private_descriptor(sid: &CurrentSid, kind: ObjectKind) -> Result<PrivateDescriptor> {
    let sid_string = sid_string(sid)?;
    let ace_flags = if kind == ObjectKind::Directory {
        "OICI"
    } else {
        ""
    };
    let sddl = format!("O:{sid_string}D:P(A;{ace_flags};FA;;;{sid_string})");
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = null_mut();
    // SAFETY: SDDL is NUL-terminated and output receives a LocalAlloc-owned descriptor.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("build private security descriptor");
    }
    Ok(PrivateDescriptor {
        allocation: LocalAllocation(descriptor),
    })
}

fn sid_string(sid: &CurrentSid) -> Result<String> {
    let mut sid_text = null_mut();
    // SAFETY: SID is valid and output receives a LocalAlloc-owned string.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr(), &raw mut sid_text) } == 0 {
        return Err(std::io::Error::last_os_error()).context("format current token SID");
    }
    let sid_guard = LocalAllocation(sid_text.cast());
    let mut len = 0_usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated string.
    unsafe {
        while *sid_text.add(len) != 0 {
            len += 1;
        }
    }
    // SAFETY: the measured slice lies within the returned NUL-terminated allocation.
    let sid_string = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, len) })
        .context("decode current token SID")?;
    drop(sid_guard);
    Ok(sid_string)
}

fn security_attributes(descriptor: &PrivateDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("attributes size fits u32"),
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    }
}

fn descriptor_dacl(descriptor: PSECURITY_DESCRIPTOR) -> Result<*mut ACL> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = null_mut();
    // SAFETY: descriptor is live and output pointers are valid.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("read canonical DACL");
    }
    if present == 0 || acl.is_null() {
        anyhow::bail!("canonical private descriptor has a missing or null DACL");
    }
    Ok(acl)
}

fn acl_bytes(acl: *const ACL) -> Result<Vec<u8>> {
    let mut info: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    // SAFETY: acl is a valid DACL and info is a correctly sized output buffer.
    if unsafe {
        GetAclInformation(
            acl,
            (&raw mut info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).expect("ACL info size fits u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("inspect DACL size");
    }
    let len = usize::try_from(info.AclBytesInUse).context("DACL byte length")?;
    // SAFETY: AclBytesInUse is the API-reported initialized extent of this ACL.
    Ok(unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), len) }.to_vec())
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        anyhow::bail!("Windows path contains an interior NUL");
    }
    Ok(wide.into_iter().chain(std::iter::once(0)).collect())
}

fn is_already_exists(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
            io.raw_os_error().is_some_and(|code| {
                u32::try_from(code)
                    .is_ok_and(|code| code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS)
            })
        })
    })
}

#[cfg(test)]
pub(super) fn validate_private_path_for_test(path: &Path, directory: bool) -> Result<()> {
    let kind = if directory {
        ObjectKind::Directory
    } else {
        ObjectKind::File
    };
    let file = open_existing(path, kind, true)?;
    validate_private_handle(&file, kind, "deferred-audit test object")
}

#[cfg(test)]
pub(super) fn create_permissive_path_for_test(path: &Path, directory: bool) -> Result<()> {
    create_path_with_sddl_for_test(path, directory, "D:P(A;;FA;;;WD)")
}

#[cfg(test)]
pub(super) fn create_extra_ace_path_for_test(path: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    let sid_text = sid_string(&sid)?;
    create_path_with_sddl_for_test(
        path,
        false,
        &format!("O:{sid_text}D:P(A;;FA;;;{sid_text})(A;;FA;;;WD)"),
    )
}

#[cfg(test)]
pub(super) fn create_null_dacl_path_for_test(path: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    let sid_text = sid_string(&sid)?;
    create_path_with_sddl_for_test(path, false, &format!("O:{sid_text}D:NO_ACCESS_CONTROL"))
}

#[cfg(test)]
pub(super) fn create_legacy_inherited_file_for_test(directory: &Path, file: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    let sid_text = sid_string(&sid)?;
    create_path_with_sddl_for_test(
        directory,
        true,
        &format!("O:{sid_text}D:(A;OICI;FA;;;{sid_text})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
    )?;
    let wide = wide_path(file)?;
    // SAFETY: the path remains live; a null attributes pointer requests normal
    // Windows inheritance from the deliberately legacy-style parent directory.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("create inherited legacy test file");
    }
    // SAFETY: the test owns this successful handle and closes it here.
    unsafe {
        CloseHandle(handle);
    }
    Ok(())
}

#[cfg(test)]
fn create_path_with_sddl_for_test(path: &Path, directory: bool, sddl: &str) -> Result<()> {
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = null_mut();
    // SAFETY: the test SDDL is NUL-terminated and output is LocalAlloc-owned.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("build permissive test descriptor");
    }
    let descriptor = PrivateDescriptor {
        allocation: LocalAllocation(descriptor),
    };
    let attributes = security_attributes(&descriptor);
    let wide = wide_path(path)?;
    if directory {
        // SAFETY: the path and security descriptor remain live for the call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("create permissive test directory");
        }
    } else {
        // SAFETY: arguments point to live buffers and CREATE_NEW owns no inputs.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error()).context("create permissive test file");
        }
        // SAFETY: the test owns this successful handle and closes it here.
        unsafe {
            CloseHandle(handle);
        }
    }
    Ok(())
}
