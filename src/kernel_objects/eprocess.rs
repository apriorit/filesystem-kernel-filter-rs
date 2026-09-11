use ntresult::IntoResult;
use wdk_sys::{
    ntddk::{ObfDereferenceObject, PsLookupProcessByProcessId},
    HANDLE, PEPROCESS,
};

/// Wrapper structure for the `EPROCESS` structure. Contains a pointer to the structure.
///
/// Obtains pointer to the `EPROCESS` structure from `PID` using `PsLookupProcessByProcessId`
/// function in [`EProcess::try_from`] method.
///
/// Dereferences the `PEPROCESS` pointer via `ObfDereferenceObject` call in the destructor
pub struct EProcess {
    eprocess: PEPROCESS,
}

impl Drop for EProcess {
    /// Dereference the `PEPROCESS` pointer using `ObfDereferenceObject` call.
    fn drop(&mut self) {
        if !self.eprocess.is_null() {
            // SAFETY:
            // Inherently unsafe as a system call. The caller ensures that
            // the `object` parameter is a valid pointer to EPROCESS structure
            unsafe { ObfDereferenceObject(self.eprocess.cast()) };
        }
    }
}

impl EProcess {
    /// Try to create [`EProcess`] structure from the process identifier.
    /// This method uses `PsLookupProcessByProcessId` call to obtain pointer to
    /// the `EPROCESS` structure
    ///
    /// # Returns
    ///
    /// - `Ok(EProcess)` - [`EProcess`] structure which contains pointer to the `EPROCESS` structure.
    /// - `Err(Error(NTSTATUS))` - An error returned from the `PsLookupProcessByProcessId` function if it fails.
    pub fn from_pid(pid: u32) -> ntresult::Result<Self> {
        let mut eprocess = PEPROCESS::default();

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that
        // the `processid` parameter is a valid process identifier and `process` is a valid pointer to PEPROCESS
        unsafe { PsLookupProcessByProcessId(pid as HANDLE, &raw mut eprocess) }.into_result()?;

        Ok(Self { eprocess })
    }

    /// Get the nested [`PEPROCESS`] pointer.
    pub fn eprocess(&self) -> PEPROCESS {
        self.eprocess
    }
}
