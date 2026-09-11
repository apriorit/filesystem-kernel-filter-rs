use crate::err_map::IntoNtError;
use hashbrown::TryReserveError;
use ntresult::Error;
use wdk_sys::STATUS_INSUFFICIENT_RESOURCES;

impl IntoNtError for TryReserveError {
    /// Convert [`hashbrown::TryReserveError`] to appropriate `Error`
    fn into_nt_error(self) -> Error {
        Error::from_ntstatus(STATUS_INSUFFICIENT_RESOURCES)
    }
}
