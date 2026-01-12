use core::ptr::null;
use kerror::Error;
use nt_string::unicode_string::NtUnicodeStr;
use wdk_sys::{
    ntddk::CmCallbackReleaseKeyObjectIDEx, STATUS_OBJECT_NAME_NOT_FOUND, UNICODE_STRING,
};

/// Wrapper for config manager object path obtained from the `CmCallbackGetKeyObjectIDEx` call
///
/// Contains const pointer to the [`NtUnicodeStr`] which doesn't own the data
///
/// Releases the object path in the destructor via `CmCallbackReleaseKeyObjectIDEx` call
///
/// # Examples
/// ```rust,no_run
/// let mut object_path: *mut UNICODE_STRING = null_mut();
///
/// unsafe {
///     CmCallbackGetKeyObjectIDEx(
///         core::ptr::from_ref(&cookie).cast(),
///         object,
///         null_mut(),
///         core::ptr::from_mut(&mut object_path),
///         0,
///     )
/// };
///
/// let cm_object_path = CmKeyObjectPath::from(object_path.cast_const());
/// ```
pub struct CmKeyObjectPath<'a>(pub *const NtUnicodeStr<'a>);

impl From<*const UNICODE_STRING> for CmKeyObjectPath<'_> {
    fn from(str: *const UNICODE_STRING) -> Self {
        Self(str.cast())
    }
}

impl Drop for CmKeyObjectPath<'_> {
    /// Release key object path using `CmCallbackReleaseKeyObjectIDEx` call.
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY:
            // The caller ensures that `self.0` is a valid non-null pointer to `UNICODE_STRING`
            // obtained from the `CmCallbackGetKeyObjectIDEx` call
            unsafe { CmCallbackReleaseKeyObjectIDEx(self.0.cast()) };
            self.0 = null();
        }
    }
}

impl<'a> CmKeyObjectPath<'a> {
    /// Get key object path as a [`NtUnicodeStr`]. This method returns data obtained from
    /// the `CmCallbackGetKeyObjectIDEx` call.
    ///
    /// # Returns
    ///
    /// - `Ok(NtUnicodeStr)` - Reference to key object path if saved pointer is not null.
    /// - `Err(Error(STATUS_OBJECT_NAME_NOT_FOUND))` - If saved pointer is null.
    pub fn path(&self) -> kerror::Result<NtUnicodeStr<'_>> {
        // SAFETY:
        // The caller ensures that `self.0` is a valid pointer to `UNICODE_STRING`
        // and this pointer is not null
        unsafe { self.0.as_ref() }
            .copied()
            .ok_or(Error::from_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND))
    }

    /// Consumes and leaks the `CmKeyObjectPath`, returning a const pointer to the [`NtUnicodeString`].
    pub fn leak(mut self) -> *const NtUnicodeStr<'a> {
        let ptr = self.0;
        self.0 = null();
        ptr
    }
}
