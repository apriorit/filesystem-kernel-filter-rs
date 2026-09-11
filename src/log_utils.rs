use kernel_logger::kernel_logger::{KernelLogger, KernelLoggerBuilder};
use log::Level;
use ntresult::IntoError;
use wdk_sys::{
    ntddk::DbgPrintEx, _DPFLTR_TYPE::DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, STATUS_UNSUCCESSFUL,
};

/// Configure and initialize kernel logger
///
/// Configures the [`KernelLogger`] and sets it as a global logger for the crate.
/// Sets the max log level to [`Level::Info`].
pub fn setup_logger() -> ntresult::Result<()> {
    let component_id = u32::try_from(DPFLTR_IHVDRIVER_ID)?;

    let logger_builder = KernelLoggerBuilder::new()
        .with_debug_logger()
        .with_log_level(Level::Info);

    KernelLogger::set_logger(logger_builder.build())
        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that the the `component_id`
        // is a valid component id and `Level` is a valid logging level and `Format` is a
        // valid pointer to string
        .inspect_err(|_| unsafe {
            DbgPrintEx(
                component_id,
                DPFLTR_ERROR_LEVEL,
                b"Failed to initialize kernel logger".as_ptr().cast(),
            );
        })
        .map_err(|_| STATUS_UNSUCCESSFUL.into_error())?;

    Ok(())
}
