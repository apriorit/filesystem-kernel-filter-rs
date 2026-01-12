use crate::utils::is_any_flag_set;
use bitfield::bitfield;
use core::ptr;
use wdk_sys::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_CREATE, FILE_DELETE_CHILD,
    FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, PFLT_CALLBACK_DATA, WRITE_DAC, WRITE_OWNER,
};

bitfield! {
    /// A wrapper for the options of the file creation operation.
    /// Allows reading and modifying the lower 24 bits and upper 8 bits separately.
    ///
    /// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-create>
    struct CreateOptions(u32);
    /// Lower 24 bits (bits 0-23)
    u32, options, set_options: 23, 0;
    /// Upper 8 bits (bits 24-31)
    u8, disposition, set_disposition: 31, 24;
}

/// Read the `disposition` from the `create` `options` in the `data` structure.
///
/// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-create>
pub fn create_file_disposition(data: PFLT_CALLBACK_DATA) -> u8 {
    // SAFETY:
    // The caller ensures that the `data` parameter is a valid pointer to
    // FLT_CALLBACK_DATA obtained from minifilter `create` callback.
    let create_options = CreateOptions(unsafe { (*(*data).Iopb).Parameters.Create.Options });
    create_options.disposition()
}

/// Set the `disposition` to the `data` `create` `options`.
///
/// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-create>
pub fn set_create_file_disposition(data: PFLT_CALLBACK_DATA, disposition: u8) {
    // SAFETY:
    // The caller ensures that the `data` parameter is a valid pointer to
    // FLT_CALLBACK_DATA obtained from minifilter `create` callback.
    let original_operation_options = unsafe { (*(*data).Iopb).Parameters.Create.Options };

    let mut create_options = CreateOptions(original_operation_options);

    create_options.set_disposition(disposition);

    // SAFETY:
    // The caller ensures that the `data` parameter is a valid pointer to
    // FLT_CALLBACK_DATA obtained from minifilter `create` callback.
    unsafe {
        #[allow(clippy::borrow_as_ptr)]
        ptr::write(
            &mut (*(*data).Iopb).Parameters.Create.Options,
            create_options.0,
        );
    }
}

/// Read the desired access for the `create` operation from the `data` structure.
pub fn create_file_desired_access(data: PFLT_CALLBACK_DATA) -> u32 {
    // SAFETY:
    // The caller ensures that the `data` parameter is a valid pointer to
    // FLT_CALLBACK_DATA obtained from minifilter `create` callback.
    unsafe { (*(*(*data).Iopb).Parameters.Create.SecurityContext).DesiredAccess }
}

/// Check if the `access_rights` parameter contains any rights that can allow file modification.
pub fn is_write_access_rights(access_rights: u32) -> bool {
    is_any_flag_set(
        access_rights,
        FILE_WRITE_DATA
            | FILE_WRITE_ATTRIBUTES
            | FILE_WRITE_EA
            | WRITE_DAC
            | WRITE_OWNER
            | FILE_APPEND_DATA
            | FILE_DELETE_CHILD
            | FILE_ADD_SUBDIRECTORY
            | FILE_ADD_FILE
            | DELETE,
    )
}

/// Checks if the given `disposition` represents a file operation that modifies the file.
pub fn is_modify_disposition(disposition: u8) -> bool {
    [
        FILE_CREATE,
        FILE_SUPERSEDE,
        FILE_OVERWRITE,
        FILE_OVERWRITE_IF,
        FILE_OPEN_IF,
    ]
    .contains(&u32::from(disposition))
}
