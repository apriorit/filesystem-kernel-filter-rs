use crate::{
    kernel_objects::{handle::Handle, object_attributes::ObjectAttributes},
    string_utils::NtStrExt,
};
use kerror::{Error, IntoResult};
use nt_string::{
    nt_unicode_str,
    unicode_string::{NtUnicodeStr, NtUnicodeString},
};
use wdk_sys::{
    ntddk::{ZwOpenSymbolicLinkObject, ZwQuerySymbolicLinkObject},
    GENERIC_READ, OBJ_KERNEL_HANDLE, STATUS_BUFFER_TOO_SMALL,
};

const OBJ_MANAGER_PATH_PREFIX: NtUnicodeStr = nt_unicode_str!(r"\??\");
const DOS_DRIVE_NAME_LEN: u16 = 2; // C:

/// Convert the `dos_drive` name to nt-format disk name.
///
/// # Parameters
/// - `dos_drive` - The disk name in dos format (e.g. "C:\").
///
/// Opens the symbolic link to the disk and gets the target of a symbolic link (nt-style disk name).
/// For example "C:\" can be converted to "\Device\HarddiskVolume3\".
pub fn obj_man_dos_drive_to_nt(dos_drive: &NtUnicodeStr) -> kerror::Result<NtUnicodeString> {
    let mut attributes = ObjectAttributes::new()
        .with_object_name(dos_drive.as_ptr().cast())
        .with_attributes(OBJ_KERNEL_HANDLE);

    let mut handle = Handle::new();

    // SAFETY:
    // Inherently unsafe as a system call. The caller ensures that the the `linkhandle` is a valid pointer to handle value
    // and `objectattributes` is a valid pointer to `OBJECT_ATTRIBUTES` structure
    unsafe { ZwOpenSymbolicLinkObject(handle.as_mut_ptr(), GENERIC_READ, attributes.as_mut_ptr()) }
        .into_result()?;

    let mut nt_drive = NtUnicodeString::new();
    let mut size = 0;

    // SAFETY:
    // Inherently unsafe as a system call. The caller ensures that the the `linkhandle` is a valid handle to the `dos_drive`
    // and `nt_drive` is a valid pointer to UNICODE_STRING variable
    let status = unsafe {
        ZwQuerySymbolicLinkObject(handle.handle(), nt_drive.as_mut_ptr().cast(), &raw mut size)
    };

    if status != STATUS_BUFFER_TOO_SMALL {
        log::error!(
            "Failed to query symbolic link to {dos_drive} drive object before buffer allocation: {}",
            status.into_error()
        );
        return Err(Error::from_ntstatus(status));
    }

    nt_drive.try_reserve(size.try_into()?)?;

    // SAFETY:
    // Inherently unsafe as a system call. The caller ensures that the the `linkhandle` is a valid handle to the `dos_drive`
    // and `nt_drive` is a large enough UNICODE_STRING to obtain an nt dos drive name
    unsafe {
        ZwQuerySymbolicLinkObject(handle.handle(), nt_drive.as_mut_ptr().cast(), &raw mut size)
    }
    .into_result()?;

    Ok(nt_drive)
}

/// Convert `dos_path` to nt-formatted path.
///
/// Supports both regular dos-formatted path (e.g. "C:\Path") and object manager dos path (e.g. "\??\C:\Path").
/// Converts both to the following nt-format - "\Device\HarddiskVolume3\Path".
pub fn dos_path_to_nt(dos_path: &NtUnicodeStr) -> kerror::Result<NtUnicodeString> {
    let (mut nt_drive, file_path) = if dos_path.starts_with_no_case(&OBJ_MANAGER_PATH_PREFIX) {
        // \??\C:
        let (obj_man_dos_drive, file_path) = dos_path.split_at(
            u16::try_from(OBJ_MANAGER_PATH_PREFIX.len_in_elements())? + DOS_DRIVE_NAME_LEN,
        )?;

        let nt_drive = obj_man_dos_drive_to_nt(&obj_man_dos_drive)?;

        (nt_drive, file_path)
    } else {
        // C:
        let (drive, file_path) = dos_path.split_at(DOS_DRIVE_NAME_LEN)?;
        let mut obj_man_dos_drive = NtUnicodeString::try_from(&OBJ_MANAGER_PATH_PREFIX)?;
        obj_man_dos_drive.try_push_u16(drive.as_slice())?;

        let nt_drive = obj_man_dos_drive_to_nt(&obj_man_dos_drive)?;

        (nt_drive, file_path)
    };

    nt_drive.try_push_u16(file_path.as_slice())?;

    Ok(nt_drive)
}
