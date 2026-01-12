use core::ptr::null_mut;
use wdk_sys::{ntddk::ZwClose, HANDLE};

/// A RAII wrapper for the [`HANDLE`] structure.
///
/// Holds and owns a handle and closes it in the destructor.
pub struct Handle {
    handle: HANDLE,
}

impl Drop for Handle {
    /// Close the handle using [`ZwClose`] call.
    /// Do nothing if it is null.
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY:
            // Inherently unsafe as a system call. The caller ensures that
            // the `handle` parameter is a valid to open registry key
            let _ = unsafe { ZwClose(self.handle) };
        }
    }
}

impl Handle {
    /// Create a [`Handle`] that stores null handle.
    pub fn new() -> Self {
        Self { handle: null_mut() }
    }

    /// Consumes and sets `handle` parameter. Returns updated [`Handle`].
    pub fn with_handle(mut self, handle: HANDLE) -> Self {
        self.handle = handle;
        self
    }

    /// Get raw [`HANDLE`] value.
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Get a mutable pointer to raw [`HANDLE`] value.
    pub fn as_mut_ptr(&mut self) -> *mut HANDLE {
        &raw mut self.handle
    }
}
