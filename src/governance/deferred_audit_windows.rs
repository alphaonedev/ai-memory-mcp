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
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, GENERIC_ALL,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL,
    ACL_SIZE_INFORMATION, AclSizeInformation, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
    EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetTokenInformation, INHERIT_ONLY_ACE, IsValidSid, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE,
    TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileAttributeTagInfo, GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    WRITE_DAC, WRITE_OWNER,
};

const ACCESS_ALLOWED_ACE_TYPE: u32 = 0;
const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u32 = 4;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u32 = 5;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u32 = 9;
const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u32 = 11;
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

struct SidBuffer {
    storage: Vec<usize>,
}

impl SidBuffer {
    fn as_ptr(&self) -> PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

struct AllocatedSid(LocalAllocation);

impl AllocatedSid {
    fn as_ptr(&self) -> PSID {
        self.0.0
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
    // Omit delete sharing on the retained directory handle. This prevents a
    // parent writer from renaming the live spool between identity checks.
    let file = open_existing_with_share_delete(path, ObjectKind::Directory, true, false)?;
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

/// Retain every lexical spool ancestor without delete sharing for the journal
/// lifetime. Opening root-to-leaf closes the namespace behind us: once a
/// component handle is acquired, Windows refuses renaming/deleting that
/// component, and `OPEN_REPARSE_POINT` lets us reject a junction/symlink at
/// each final component rather than following it silently.
pub(super) fn open_spool_ancestor_guards(path: &Path) -> Result<Vec<File>> {
    use std::path::Component;

    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        anyhow::bail!("deferred-audit spool path contains a parent traversal");
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve deferred-audit spool parent")?
            .join(path)
    };
    let mut ancestors = absolute.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    let mut guards = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let file = open_existing_with_share_delete(ancestor, ObjectKind::Directory, false, false)
            .with_context(|| {
            format!(
                "open deferred-audit spool ancestor guard {}",
                ancestor.display()
            )
        })?;
        validate_handle_shape(&file, ObjectKind::Directory, super::SPOOL_ANCESTOR_LABEL)?;
        validate_ancestor_security(&file, super::SPOOL_ANCESTOR_LABEL)?;
        guards.push(file);
    }
    Ok(guards)
}

fn validate_ancestor_security(file: &File, label: &str) -> Result<()> {
    let handle = file.as_raw_handle().cast::<c_void>() as HANDLE;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: output pointers are valid and the handle remains live.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status.cast_signed()))
            .with_context(|| format!("read {label} security descriptor"));
    }
    let _descriptor_guard = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        anyhow::bail!("{label} has a missing owner or null DACL");
    }

    let current = current_user_sid()?;
    let system = well_known_sid(WinLocalSystemSid)?;
    let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
    let trusted_installer =
        string_sid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")?;
    let trusted = [
        current.as_ptr(),
        system.as_ptr(),
        administrators.as_ptr(),
        trusted_installer.as_ptr(),
    ];
    if !sid_is_one_of(owner, &trusted) {
        anyhow::bail!("{label} owner is not a trusted Windows principal");
    }

    let mut info: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    // SAFETY: dacl is live with the descriptor and info is correctly sized.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).expect("ACL info size fits u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("inspect {label} DACL"));
    }
    for index in 0..info.AceCount {
        let mut ace = null_mut();
        // SAFETY: index is below the API-reported ACE count and output is valid.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("read {label} DACL ACE"));
        }
        validate_ancestor_ace(ace.cast_const(), &trusted, label)?;
    }
    Ok(())
}

fn validate_ancestor_ace(ace: *const c_void, trusted: &[PSID], label: &str) -> Result<()> {
    // SAFETY: GetAce returned an ACE pointer valid while the DACL is live.
    let header = unsafe { std::ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
    if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
        return Ok(());
    }
    let ace_type = u32::from(header.AceType);
    let simple =
        ace_type == ACCESS_ALLOWED_ACE_TYPE || ace_type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE;
    let object = ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE
        || ace_type == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE;
    if !simple && !object {
        if ace_type == ACCESS_ALLOWED_COMPOUND_ACE_TYPE {
            anyhow::bail!("{label} has an unsupported compound allow ACE");
        }
        return Ok(());
    }
    let ace_bytes = usize::from(header.AceSize);
    let mask_offset = size_of::<ACE_HEADER>();
    if ace_bytes < mask_offset + size_of::<u32>() {
        anyhow::bail!("{label} has a truncated allow ACE");
    }
    // SAFETY: bounds above cover the unaligned mask read.
    let mask = unsafe { std::ptr::read_unaligned(ace.cast::<u8>().add(mask_offset).cast::<u32>()) };
    if !ancestor_mask_is_dangerous(mask) {
        return Ok(());
    }
    let sid_offset = if simple {
        mask_offset + size_of::<u32>()
    } else {
        let flags_offset = mask_offset + size_of::<u32>();
        if ace_bytes < flags_offset + size_of::<u32>() {
            anyhow::bail!("{label} has a truncated object allow ACE");
        }
        // SAFETY: bounds above cover the unaligned flags read.
        let flags =
            unsafe { std::ptr::read_unaligned(ace.cast::<u8>().add(flags_offset).cast::<u32>()) };
        flags_offset
            + size_of::<u32>()
            + if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                16
            } else {
                0
            }
            + if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                16
            } else {
                0
            }
    };
    // SAFETY: GetAce returned this pointer and AceSize is the API-reported
    // extent of the ACE within the live ACL.
    let ace_slice = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), ace_bytes) };
    embedded_sid_length(ace_slice, sid_offset)
        .with_context(|| format!("inspect {label} allow ACE SID bounds"))?;
    // SAFETY: the offset is within this ACE; IsValidSid validates its structure.
    let sid = unsafe { ace.cast::<u8>().add(sid_offset).cast_mut().cast::<c_void>() };
    // SAFETY: sid points into the live ACE and has the minimum SID prefix available.
    if unsafe { IsValidSid(sid) } == 0 {
        anyhow::bail!("{label} has an invalid allow ACE SID");
    }
    if !sid_is_one_of(sid, trusted) {
        anyhow::bail!(
            "{label} grants rename or security-control authority to an untrusted principal"
        );
    }
    Ok(())
}

fn ancestor_mask_is_dangerous(mask: u32) -> bool {
    mask & (FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL) != 0
}

fn embedded_sid_length(ace: &[u8], sid_offset: usize) -> Result<usize> {
    const SID_PREFIX_BYTES: usize = 8;
    let prefix_end = sid_offset
        .checked_add(SID_PREFIX_BYTES)
        .context("allow ACE SID offset overflow")?;
    if prefix_end > ace.len() {
        anyhow::bail!("truncated allow ACE SID prefix");
    }
    let subauthority_count = usize::from(ace[sid_offset + 1]);
    let sid_bytes = SID_PREFIX_BYTES
        .checked_add(
            subauthority_count
                .checked_mul(size_of::<u32>())
                .context("allow ACE SID length overflow")?,
        )
        .context("allow ACE SID length overflow")?;
    let sid_end = sid_offset
        .checked_add(sid_bytes)
        .context("allow ACE SID extent overflow")?;
    if sid_end > ace.len() {
        anyhow::bail!("truncated allow ACE SID subauthorities");
    }
    Ok(sid_bytes)
}

fn well_known_sid(kind: i32) -> Result<SidBuffer> {
    let word = size_of::<usize>();
    let mut bytes = SECURITY_MAX_SID_SIZE;
    let words = usize::try_from(bytes)
        .context("well-known SID buffer length")?
        .div_ceil(word);
    let mut storage = vec![0_usize; words];
    // SAFETY: storage is aligned and contains SECURITY_MAX_SID_SIZE writable bytes.
    if unsafe {
        CreateWellKnownSid(
            kind,
            null_mut(),
            storage.as_mut_ptr().cast(),
            &raw mut bytes,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("build trusted well-known SID");
    }
    Ok(SidBuffer { storage })
}

fn string_sid(value: &str) -> Result<AllocatedSid> {
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid = null_mut();
    // SAFETY: input is NUL-terminated and output receives a LocalAlloc-owned SID.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) } == 0 {
        return Err(std::io::Error::last_os_error()).context("build trusted string SID");
    }
    Ok(AllocatedSid(LocalAllocation(sid)))
}

fn sid_is_one_of(candidate: PSID, trusted: &[PSID]) -> bool {
    trusted.iter().any(|trusted_sid| {
        // SAFETY: candidate and every trusted SID remain live for this comparison.
        unsafe { EqualSid(candidate, *trusted_sid) != 0 }
    })
}

fn open_existing(path: &Path, kind: ObjectKind, writable: bool) -> Result<File> {
    open_existing_with_share_delete(path, kind, writable, true)
}

fn open_existing_with_share_delete(
    path: &Path,
    kind: ObjectKind,
    writable: bool,
    share_delete: bool,
) -> Result<File> {
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
    let share_mode =
        FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share_mode,
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
    validate_handle_shape(file, kind, label)?;

    let raw = file.as_raw_handle().cast::<c_void>();
    let handle = raw as HANDLE;
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

fn validate_handle_shape(file: &File, kind: ObjectKind, label: &str) -> Result<()> {
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
    const BACKSLASH: u16 = b'\\' as u16;
    const SLASH: u16 = b'/' as u16;

    let supplied: Vec<u16> = path.as_os_str().encode_wide().collect();
    if supplied.contains(&0) {
        anyhow::bail!("Windows path contains an interior NUL");
    }
    if let Some(std::path::Component::Prefix(prefix)) = path.components().next() {
        match prefix.kind() {
            std::path::Prefix::VerbatimDisk(_) | std::path::Prefix::VerbatimUNC(_, _) => {
                return Ok(supplied.into_iter().chain(std::iter::once(0)).collect());
            }
            std::path::Prefix::Verbatim(namespace)
                if is_volume_guid_namespace(namespace)
                    && matches!(
                        path.components().nth(1),
                        Some(std::path::Component::RootDir)
                    ) =>
            {
                return Ok(supplied.into_iter().chain(std::iter::once(0)).collect());
            }
            std::path::Prefix::DeviceNS(_) | std::path::Prefix::Verbatim(_) => {
                anyhow::bail!("unsupported Windows device or verbatim path namespace");
            }
            std::path::Prefix::Disk(_) | std::path::Prefix::UNC(_, _) => {}
        }
    }

    let absolute = std::path::absolute(path).context("resolve absolute Windows path")?;
    let mut wide: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        anyhow::bail!("Windows path contains an interior NUL");
    }
    for unit in &mut wide {
        if *unit == SLASH {
            *unit = BACKSLASH;
        }
    }

    let mut extended = if wide.starts_with(&[BACKSLASH, BACKSLASH]) {
        let mut prefixed = "\\\\?\\UNC\\".encode_utf16().collect::<Vec<_>>();
        prefixed.extend_from_slice(&wide[2..]);
        prefixed
    } else {
        let mut prefixed = "\\\\?\\".encode_utf16().collect::<Vec<_>>();
        prefixed.extend_from_slice(&wide);
        prefixed
    };
    extended.push(0);
    Ok(extended)
}

fn is_volume_guid_namespace(namespace: &std::ffi::OsStr) -> bool {
    let units: Vec<u16> = namespace.encode_wide().collect();
    let volume = b"Volume";
    if units.len() != 44
        || !units[..volume.len()]
            .iter()
            .zip(volume)
            .all(|(unit, expected)| {
                u8::try_from(*unit).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
            })
        || units[6] != u16::from(b'{')
    {
        return false;
    }
    if units[43] != u16::from(b'}') {
        return false;
    }

    units[7..43].iter().enumerate().all(|(index, unit)| {
        matches!(index, 8 | 13 | 18 | 23)
            .then_some(u16::from(b'-'))
            .map_or_else(
                || char::from_u32(u32::from(*unit)).is_some_and(|ch| ch.is_ascii_hexdigit()),
                |hyphen| *unit == hyphen,
            )
    })
}

#[cfg(test)]
pub(super) fn wide_path_for_test(path: &Path) -> Result<Vec<u16>> {
    wide_path(path)
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
pub(super) fn create_ancestor_grant_for_test(path: &Path, rights: &str) -> Result<()> {
    let sid = current_user_sid()?;
    let sid_text = sid_string(&sid)?;
    create_path_with_sddl_for_test(
        path,
        true,
        &format!("O:{sid_text}D:P(A;;FA;;;{sid_text})(A;;{rights};;;WD)"),
    )
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

#[cfg(test)]
mod ancestor_policy_tests {
    use super::*;

    fn test_sid(subauthorities: &[u32]) -> Vec<u8> {
        let mut sid = Vec::with_capacity(8 + std::mem::size_of_val(subauthorities));
        sid.push(1);
        sid.push(u8::try_from(subauthorities.len()).unwrap());
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
        for subauthority in subauthorities {
            sid.extend_from_slice(&subauthority.to_le_bytes());
        }
        sid
    }

    fn test_allow_ace(
        ace_type: u32,
        ace_flags: u8,
        mask: u32,
        object_flags: Option<u32>,
        sid: &[u8],
    ) -> Vec<u8> {
        let mut ace = vec![u8::try_from(ace_type).unwrap(), ace_flags, 0, 0];
        ace.extend_from_slice(&mask.to_le_bytes());
        if let Some(object_flags) = object_flags {
            ace.extend_from_slice(&object_flags.to_le_bytes());
            if object_flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                ace.extend_from_slice(&[0x11; 16]);
            }
            if object_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                ace.extend_from_slice(&[0x22; 16]);
            }
        }
        ace.extend_from_slice(sid);
        let ace_size = u16::try_from(ace.len()).unwrap();
        ace[2..4].copy_from_slice(&ace_size.to_le_bytes());
        ace
    }

    fn validate_test_ace(ace: &[u8], trusted: &[PSID]) -> Result<()> {
        validate_ancestor_ace(ace.as_ptr().cast(), trusted, "test ancestor")
    }

    #[test]
    fn dangerous_ancestor_mask_covers_every_namespace_control_right() {
        for mask in [
            FILE_DELETE_CHILD,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
        ] {
            assert!(ancestor_mask_is_dangerous(mask));
        }
        assert!(!ancestor_mask_is_dangerous(FILE_GENERIC_WRITE));
    }

    #[test]
    fn embedded_sid_bounds_cover_simple_and_object_allow_aces() {
        for sid_offset in [8_usize, 12, 28, 44] {
            let mut valid = vec![0_u8; sid_offset + 12];
            valid[sid_offset] = 1;
            valid[sid_offset + 1] = 1;
            assert_eq!(embedded_sid_length(&valid, sid_offset).unwrap(), 12);

            let mut truncated = vec![0_u8; sid_offset + 12];
            truncated[sid_offset] = 1;
            truncated[sid_offset + 1] = 2;
            assert!(embedded_sid_length(&truncated, sid_offset).is_err());
        }
    }

    #[test]
    fn trusted_sid_membership_rejects_a_foreign_principal() {
        let current = string_sid("S-1-5-21-1-2-3-1001").unwrap();
        let system = string_sid("S-1-5-18").unwrap();
        let foreign = string_sid("S-1-5-21-1-2-3-2002").unwrap();
        let trusted = [current.as_ptr(), system.as_ptr()];

        assert!(sid_is_one_of(current.as_ptr(), &trusted));
        assert!(!sid_is_one_of(foreign.as_ptr(), &trusted));
    }

    #[test]
    fn callback_allow_ace_enforces_dangerous_foreign_sid() {
        let trusted_sid = string_sid("S-1-5-18").unwrap();
        let trusted = [trusted_sid.as_ptr()];
        let trusted_bytes = test_sid(&[18]);
        let foreign_bytes = test_sid(&[21, 1, 2, 3, 2002]);

        let trusted_ace = test_allow_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            FILE_DELETE_CHILD,
            None,
            &trusted_bytes,
        );
        assert!(validate_test_ace(&trusted_ace, &trusted).is_ok());

        let foreign_ace = test_allow_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            WRITE_DAC,
            None,
            &foreign_bytes,
        );
        assert!(validate_test_ace(&foreign_ace, &trusted).is_err());

        let benign_foreign_ace = test_allow_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            FILE_GENERIC_WRITE,
            None,
            &foreign_bytes,
        );
        assert!(validate_test_ace(&benign_foreign_ace, &trusted).is_ok());
    }

    #[test]
    fn object_allow_aces_enforce_every_guid_offset() {
        let trusted_sid = string_sid("S-1-5-18").unwrap();
        let trusted = [trusted_sid.as_ptr()];
        let trusted_bytes = test_sid(&[18]);
        let foreign_bytes = test_sid(&[21, 1, 2, 3, 2002]);
        let object_flag_sets = [
            0,
            ACE_OBJECT_TYPE_PRESENT,
            ACE_INHERITED_OBJECT_TYPE_PRESENT,
            ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT,
        ];

        for ace_type in [
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        ] {
            for object_flags in object_flag_sets {
                let trusted_ace =
                    test_allow_ace(ace_type, 0, WRITE_OWNER, Some(object_flags), &trusted_bytes);
                assert!(validate_test_ace(&trusted_ace, &trusted).is_ok());

                let foreign_ace =
                    test_allow_ace(ace_type, 0, GENERIC_ALL, Some(object_flags), &foreign_bytes);
                assert!(validate_test_ace(&foreign_ace, &trusted).is_err());
            }
        }
    }

    #[test]
    fn compound_allow_ace_fails_closed_and_inherit_only_is_ignored() {
        let trusted_sid = string_sid("S-1-5-18").unwrap();
        let trusted = [trusted_sid.as_ptr()];
        let sid = test_sid(&[18]);
        let compound = test_allow_ace(
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
            0,
            FILE_DELETE_CHILD,
            None,
            &sid,
        );
        assert!(validate_test_ace(&compound, &trusted).is_err());

        let inherit_only = test_allow_ace(
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
            u8::try_from(INHERIT_ONLY_ACE).unwrap(),
            GENERIC_ALL,
            Some(ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT),
            &test_sid(&[21, 1, 2, 3, 2002]),
        );
        assert!(validate_test_ace(&inherit_only, &trusted).is_ok());
    }
}
