use crate::err_map::IntoNtError;
use nt_string::NtStringError;
use ntresult::Error;
use wdk_sys::{STATUS_BUFFER_OVERFLOW, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER};

impl IntoNtError for NtStringError {
    /// Convert [`NtStringError`] to appropriate `Error`
    fn into_nt_error(self) -> Error {
        match self {
            NtStringError::InsufficientResources => {
                Error::from_ntstatus(STATUS_INSUFFICIENT_RESOURCES)
            }
            NtStringError::BufferSizeExceedsU16 => Error::from_ntstatus(STATUS_BUFFER_OVERFLOW),
            _ => Error::from_ntstatus(STATUS_INVALID_PARAMETER),
        }
    }
}
