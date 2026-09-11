//! Rust Minifilter
//!
//! Filesystem kernel filter
//!
//! This driver provides logic to filter filesystem activity according to
//! rules from from the registry which represent `Deny` and `ReadOnly` rules
//! from specified process to specified files
#![no_std]
#![allow(clippy::module_name_repetitions)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::all, clippy::pedantic)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(allocator_api)]

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

mod constants;
mod driver;
mod err_map;
mod flt_utils;
mod kernel_objects;
mod log_utils;
mod minifilter;
mod path_utils;
mod process;
mod process_manager;
mod registry;
mod registry_manager;
mod rules_manager;
mod string_utils;
mod utils;

use driver::Driver;
use kernel_allocator::kernel_allocator::PagedAlloc;
use log_utils::setup_logger;
use nt_string::{nt_unicode_str, unicode_string::NtUnicodeStr};
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, STATUS_SUCCESS};

#[global_allocator]
static GLOBAL_ALLOCATOR: PagedAlloc = PagedAlloc {};

/// Driver altitude.
/// `FSFilter Top`. The driver attaches above all other `FSFilter` types.
///
/// Please make sure that this value is the same as specified in the .inx file
const DRIVER_ALTITUDE: NtUnicodeStr<'static> = nt_unicode_str!("405005");

/// The entry point for the Windows kernel-mode driver.
///
/// # Parameters
/// - `driver_object`: A pointer to the `DRIVER_OBJECT` structure representing the driver.
/// - `registry_path`: A pointer to a `UNICODE_STRING` containing the registry path to the driver's key.
///
/// # Returns
/// - `NTSTATUS` code indicating success (`STATUS_SUCCESS`) or an error code if initialization fails.
///
/// # Description
/// This function is called by the Windows kernel when the driver is loaded. It is responsible for:
/// - Initializing kernel logger.
/// - Initializing the [`Driver`] instance.
///
/// # Notes
/// - If the function returns an error, the driver will not be loaded.
///
/// # Safety
/// This function is inherently unsafe because it serves as the entry point
/// for a Windows kernel driver, interacting directly with low-level system
/// resources. Parameters are provided by the operating system when the driver is started
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver_object: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    if let Err(err) = setup_logger() {
        return err.ntstatus();
    }

    let driver = Driver::create();
    if let Err(err) = driver.init(driver_object, &DRIVER_ALTITUDE) {
        driver.deinit();
        err.ntstatus()
    } else {
        STATUS_SUCCESS
    }
}
