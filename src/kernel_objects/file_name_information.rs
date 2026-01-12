use core::ptr::null_mut;
use kerror::{Error, IntoResult};
use nt_string::unicode_string::{NtUnicodeStr, NtUnicodeString};
use wdk_sys::{
    minifilter::{FltGetFileNameInformation, FltReleaseFileNameInformation},
    FLT_FILE_NAME_NORMALIZED, FLT_FILE_NAME_QUERY_DEFAULT, PFLT_CALLBACK_DATA,
    PFLT_FILE_NAME_INFORMATION, STATUS_INVALID_PARAMETER,
};

/// Wrapper for the pointer to the [`FLT_FILE_NAME_INFORMATION`].
///
/// Allows to get a pointer from the [`FLT_CALLBACK_DATA`] structure and
/// get a file path from this pointer.
///
/// Owns the data and releases it in the destructor.
pub struct FileNameInformation {
    file: PFLT_FILE_NAME_INFORMATION,
}

impl TryFrom<PFLT_CALLBACK_DATA> for FileNameInformation {
    type Error = Error;

    /// Try to obtain the pointer to the [`FLT_FILE_NAME_INFORMATION`] from the
    /// [`FLT_CALLBACK_DATA`] with [`FLT_FILE_NAME_NORMALIZED`] and [`FLT_FILE_NAME_QUERY_DEFAULT`]
    /// name options using [`FltGetFileNameInformation`].
    ///
    /// Returns error if [`FltGetFileNameInformation`] call fails.
    fn try_from(data: PFLT_CALLBACK_DATA) -> kerror::Result<Self> {
        let mut file = null_mut();

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that
        // the `callbackdata` parameter is a valid pointer to FLT_CALLBACK_DATA structure,
        // `nameoptions` is a valid combination of `FLT_FILE_NAME_OPTIONS` and
        // `filenameinformation` is a valid pointer to pointer to `FLT_FILE_NAME_INFORMATION`
        unsafe {
            FltGetFileNameInformation(
                data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &raw mut file,
            )
        }
        .into_result()?;

        Ok(Self { file })
    }
}

impl FileNameInformation {
    /// Get file path from the [`FLT_FILE_NAME_INFORMATION`] pointer. Reads
    /// `FLT_FILE_NAME_INFORMATION::Name` field to create a [`NtUnicodeString`]
    /// string
    ///
    /// # Returns
    ///
    /// - `Ok(NtUnicodeString)` - A path to the file.
    /// - `Err(Error(STATUS_INVALID_PARAMETER))` - If the pointer to the
    ///   [`FLT_FILE_NAME_INFORMATION`] is null.
    /// - `Err(Error(STATUS_INSUFFICIENT_RESOURCES))` - If [`NtUnicodeString`]
    ///   allocation fails.
    pub fn path(&self) -> kerror::Result<NtUnicodeString> {
        // SAFETY:
        // The caller ensures that `self.file` is a non-null pointer to FLT_FILE_NAME_INFORMATION
        let name_info = unsafe {
            self.file
                .as_ref()
                .ok_or(STATUS_INVALID_PARAMETER.into_error())?
        };

        // SAFETY:
        // Raw data used to create a NtUnicodeStr from FLT_FILE_NAME_INFORMATION::Name.
        // The system ensures that FLT_FILE_NAME_INFORMATION::Name contains valid UNICODE_STRING
        // data
        let name = unsafe {
            NtUnicodeStr::from_raw_parts(
                name_info.Name.Buffer,
                name_info.Name.Length,
                name_info.Name.MaximumLength,
            )
        };

        Ok(NtUnicodeString::try_from(&name)?)
    }
}

impl Drop for FileNameInformation {
    /// Release [`FLT_FILE_NAME_INFORMATION`] obtained from the [`FltGetFileNameInformation`] using
    /// [`FltReleaseFileNameInformation`] call.
    ///
    /// Does nothing if the pointer is null.
    fn drop(&mut self) {
        if !self.file.is_null() {
            // SAFETY:
            // Inherently unsafe as a system call. The caller ensures that
            // the `filenameinformation` parameter is a valid pointer to FLT_FILE_NAME_INFORMATION structure
            unsafe { FltReleaseFileNameInformation(self.file) };
        }
    }
}
