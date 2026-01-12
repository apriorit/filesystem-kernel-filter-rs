use crate::{
    driver::Driver,
    flt_utils::{
        create_file_desired_access, create_file_disposition, is_modify_disposition,
        is_write_access_rights, set_create_file_disposition,
    },
    kernel_objects::file_name_information::FileNameInformation,
    path_utils::dos_path_to_nt,
    process_manager::ProcessManager,
    rules_manager::{FileSystemRuleAction, RulesManager},
};
use core::ptr::null_mut;
use kerror::IntoResult;
use nt_string::unicode_string::NtUnicodeStr;
use wdk_sys::{
    minifilter::{
        FltGetRequestorProcessId, FltRegisterFilter, FltSetCallbackDataDirty, FltStartFiltering,
        FltUnregisterFilter,
    },
    FILE_INFORMATION_CLASS, FILE_OPEN, FILE_OPEN_IF, FILE_RENAME_INFORMATION, FLT_CALLBACK_DATA,
    FLT_OPERATION_REGISTRATION, FLT_PREOP_CALLBACK_STATUS, FLT_REGISTRATION,
    FLT_REGISTRATION_VERSION, IRP_MJ_CREATE, IRP_MJ_OPERATION_END, IRP_MJ_SET_INFORMATION,
    PCFLT_RELATED_OBJECTS, PDRIVER_OBJECT, PFLT_CALLBACK_DATA, PFLT_FILTER, PVOID,
    STATUS_ACCESS_DENIED,
    _FILE_INFORMATION_CLASS::{FileRenameInformation, FileRenameInformationEx},
    _FLT_PREOP_CALLBACK_STATUS::{FLT_PREOP_COMPLETE, FLT_PREOP_SUCCESS_NO_CALLBACK},
};

/// Callbacks for the [`Minifilter`] registration.
#[allow(clippy::cast_possible_truncation)]
const CALLBACKS: &[FLT_OPERATION_REGISTRATION] = &[
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_CREATE as u8,
        Flags: 0,
        PreOperation: Some(Minifilter::pre_create),
        PostOperation: None,
        Reserved1: null_mut(),
    },
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_SET_INFORMATION as u8,
        Flags: 0,
        PreOperation: Some(Minifilter::pre_set_info),
        PostOperation: None,
        Reserved1: null_mut(),
    },
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_OPERATION_END as u8,
        Flags: 0,
        PreOperation: None,
        PostOperation: None,
        Reserved1: null_mut(),
    },
];

/// Registration structure that contains all the information about
/// minifilter driver functions.
#[allow(clippy::cast_possible_truncation)]
const FILTER_REGISTRATION: FLT_REGISTRATION = FLT_REGISTRATION {
    Size: size_of::<FLT_REGISTRATION>() as u16,
    Version: FLT_REGISTRATION_VERSION as u16,
    Flags: 0,
    ContextRegistration: null_mut(),
    OperationRegistration: CALLBACKS.as_ptr(),
    FilterUnloadCallback: Some(Driver::driver_unload_callback),
    InstanceSetupCallback: None,
    InstanceQueryTeardownCallback: None,
    InstanceTeardownStartCallback: None,
    InstanceTeardownCompleteCallback: None,
    GenerateFileNameCallback: None,
    NormalizeNameComponentCallback: None,
    NormalizeContextCleanupCallback: None,
    TransactionNotificationCallback: None,
    NormalizeNameComponentExCallback: None,
    SectionNotificationCallback: None,
};

/// Structure that represents the minifilter and all the necessary information
/// for it's initialization/deinitialization.
///
/// Registers and starts the minifilter. Unregisters it in the destructor.
pub struct Minifilter {
    pub driver: PDRIVER_OBJECT,
    pub handle: PFLT_FILTER,
}

impl Minifilter {
    /// Create zeroed [`Minifilter`] structure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Save the `driver` and register the minifilter using [`Minifilter::register`] function
    pub fn init(&mut self, driver: PDRIVER_OBJECT) -> kerror::Result<()> {
        self.driver = driver;

        self.register()
    }

    /// Start minifilter filtering.
    ///
    /// Calls the [`FltStartFiltering`] with [`Minifilter::handle`] argument previously obtained from the
    /// [`FltRegisterFilter`] function.
    pub fn start_filtering(&self) -> kerror::Result<()> {
        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that the the `filter` parameter is a valid handle to `FLT_FILTER`
        unsafe { FltStartFiltering(self.handle) }.into_result()
    }

    /// Register the minifilter in system
    ///
    /// Calls the [`FltRegisterFilter`] function with [`FILTER_REGISTRATION`] settings and obtains the [`PFLT_FILTER`] pointer to the minifilter
    fn register(&mut self) -> kerror::Result<()> {
        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that the the `driver` parameter is a valid pointer to current driver object
        // and `FILTER_REGISTRATION` is properly initialized structure with callbacks
        unsafe {
            FltRegisterFilter(
                self.driver.cast(),
                &FILTER_REGISTRATION,
                &raw mut self.handle,
            )
        }
        .into_result()
    }

    /// Set values in the `data` parameter that tell the system that the file operation must be blocked.
    ///
    /// Sets the `Information` to zero and the `Status` to [`STATUS_ACCESS_DENIED`] in the `IO_STATUS_BLOCK`.
    ///
    /// Returns the [`FLT_PREOP_COMPLETE`] status which indicates that the `FltMgr` won't send the I/O operation
    /// to any minifilter drivers below the caller in the driver stack or to the file system
    fn deny_access(data: PFLT_CALLBACK_DATA) -> FLT_PREOP_CALLBACK_STATUS {
        // SAFETY:
        // The caller ensures that the `data` parameter is a valid to the `FLT_CALLBACK_DATA` structure
        unsafe {
            (*data).IoStatus.__bindgen_anon_1.Status = STATUS_ACCESS_DENIED;
            (*data).IoStatus.Information = 0;
        }
        FLT_PREOP_COMPLETE
    }

    /// Filters file creation operation using `data` parameter.
    ///
    /// Checks if the `data` parameter has write access rights. Is so, the operation
    /// will be blocked using [`Minifilter::deny_access`].
    ///
    /// Checks the `data` disposition. If it has modification disposition the operation
    /// will be blocked with [`Minifilter::deny_access`].
    ///
    /// # Notes
    /// If the operation has the [`FILE_OPEN_IF`] (open a file if exists or create is doesn't) disposition
    /// the minifilter changes it to the [`FILE_OPEN`] disposition (open a file if exists or
    /// fail if doesn't) to prevent file creation
    fn create_read_only(data: PFLT_CALLBACK_DATA) -> FLT_PREOP_CALLBACK_STATUS {
        let desired_access = create_file_desired_access(data);
        if is_write_access_rights(desired_access) {
            return Self::deny_access(data);
        }

        let disposition = create_file_disposition(data);
        #[allow(clippy::cast_possible_truncation)]
        if disposition == FILE_OPEN_IF as u8 {
            set_create_file_disposition(data, FILE_OPEN as u8);
            // SAFETY:
            // Inherently unsafe as a system call. The caller ensures that
            // the `data` parameter is a valid to the `FLT_CALLBACK_DATA` structure
            unsafe { FltSetCallbackDataDirty(data) };
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if is_modify_disposition(disposition) {
            return Self::deny_access(data);
        }

        FLT_PREOP_SUCCESS_NO_CALLBACK
    }

    /// The `Pre-create` file operation handler which intercepts the create operation and performs filtering.
    ///
    /// This callback gets the process ID of the file operation requestor from the `data` parameter.
    /// It tries to get information about this process from the [`ProcessManager`] using [`ProcessManager::get_or_add_process_info`]
    /// method.
    ///
    /// It tries to get full file path via [`FileNameInformation`] structure and `data` parameter.
    ///
    /// Then it uses the information about the process and file path to search for protection rules in the [`RulesManager`]
    /// If there is no protection rules in the [`RulesManager`] and it returns [`FileSystemRuleAction::Bypass`] action,
    /// the callback just returns [`FLT_PREOP_SUCCESS_NO_CALLBACK`] which indicates that the minifilter is
    /// returning the I/O operation to `FltMgr` for further processing.
    ///
    /// If any protection rule was found and [`RulesManager`] returns it, this callback applies the [`FileSystemRuleAction`]
    /// to the file operation.
    ///
    /// It uses [`Minifilter::deny_access`] handler for [`FileSystemRuleAction::Deny`] and
    /// [`Minifilter::create_read_only`] handler for [`FileSystemRuleAction::ReadOnly`] rule type.
    ///
    /// These steps apply not only to the requestor process, but also to its parent process (if it is still running).
    ///
    /// # Notes
    /// If it fails at any step it just returns the [`FLT_PREOP_SUCCESS_NO_CALLBACK`] status and doesn't perform
    /// filtering to avoid blocking legal operations and corrupting the system.
    ///
    /// # Safety
    /// This function is inherently unsafe because it's a pre-create filesystem callback called by filter manager.
    /// Parameters are provided by the operating system when some process tries to perform a file operation and it
    /// ensures that they are valid.
    unsafe extern "C" fn pre_create(
        data: PFLT_CALLBACK_DATA,
        _flt_objects: PCFLT_RELATED_OBJECTS,
        _completion_context: *mut PVOID,
    ) -> FLT_PREOP_CALLBACK_STATUS {
        // SAFETY:
        // Inherently unsafe as a system call. The system ensures that the the `data` parameter
        // is a valid pointer to `FLT_CALLBACK_DATA` structure
        let pid = unsafe { FltGetRequestorProcessId(data) };

        let Ok(process_info) = ProcessManager::get_or_add_process_info(pid).inspect_err(|err| {
            log::trace!("Failed to get process info in pre_create for pid {pid}: {err}");
        }) else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };

        let Ok(file_name_info) = FileNameInformation::try_from(data).inspect_err(|err| {
            log::trace!(
                "Failed to get file name information in pre_create for process {}: {err}",
                process_info.name
            );
        }) else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };

        let Ok(file_path) = file_name_info
            .path()
            .inspect_err(|err| log::trace!("Failed to get file name in pre_create: {err}"))
        else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };

        match RulesManager::search_rule_action(&process_info.name, &file_path) {
            FileSystemRuleAction::Deny => return Self::deny_access(data),
            FileSystemRuleAction::ReadOnly => return Self::create_read_only(data),
            FileSystemRuleAction::Bypass => {}
        }

        let parent_process_info = ProcessManager::get_or_add_parent_process_info(&process_info);
        if let Some(parent_process_info) = parent_process_info {
            match RulesManager::search_rule_action(&parent_process_info.name, &file_path) {
                FileSystemRuleAction::Deny => return Self::deny_access(data),
                FileSystemRuleAction::ReadOnly => return Self::create_read_only(data),
                FileSystemRuleAction::Bypass => {}
            }
        }

        FLT_PREOP_SUCCESS_NO_CALLBACK
    }

    /// Get the new filename to be set for the file.
    ///
    /// # Parameters
    /// - `data` - Pointer to the [`FLT_CALLBACK_DATA`] structure obtained in the minifilter callback for `IRP_MJ_SET_INFORMATION` major function.
    ///
    /// This function reads it's buffer and returns a [`NtUnicodeStr`] pointing to the new file name.
    fn new_name_for_rename(data: &FLT_CALLBACK_DATA) -> NtUnicodeStr<'_> {
        // SAFETY:
        // The caller ensures that the `data` parameter is a valid pointer to
        // FLT_CALLBACK_DATA obtained from minifilter `set file info` callback.
        let set_file_info_ptr =
            unsafe { &data.Iopb.as_ref_unchecked().Parameters.SetFileInformation };

        // SAFETY:
        // The system ensures that the `SetFileInformation::InfoBuffer` is a valid pointer to
        // `FILE_RENAME_INFORMATION` structure
        let rename_info_buffer = unsafe {
            &*set_file_info_ptr
                .InfoBuffer
                .cast::<FILE_RENAME_INFORMATION>()
        };

        // SAFETY:
        // Raw `rename_info_buffer` data used to create a NtUnicodeStr.
        // The system ensures that the `SetFileInformation::InfoBuffer` is a valid pointer to
        // `FILE_RENAME_INFORMATION` structure which contains UNICODE_STRING raw data
        unsafe {
            #[allow(clippy::cast_possible_truncation)]
            NtUnicodeStr::from_raw_parts(
                rename_info_buffer.FileName.as_ptr(),
                rename_info_buffer.FileNameLength as _,
                rename_info_buffer.FileNameLength as _,
            )
        }
    }

    fn set_file_info_class(data: &FLT_CALLBACK_DATA) -> FILE_INFORMATION_CLASS {
        // SAFETY:
        // The caller ensures that the `data` parameter is a valid pointer to
        // FLT_CALLBACK_DATA obtained from minifilter `set file info` callback.
        unsafe { &data.Iopb.as_ref_unchecked().Parameters.SetFileInformation }.FileInformationClass
    }

    /// Check if the [`RulesManager`] has any protection rules for the specified `process_name`
    /// and `file_path`.
    ///
    /// Performs searching via [`RulesManager::search_rule_action`] and checks if it either
    /// [`FileSystemRuleAction::Deny`] or [`FileSystemRuleAction::ReadOnly`]
    fn protection_rule_exists(process_name: &NtUnicodeStr, file_path: &NtUnicodeStr) -> bool {
        matches!(
            RulesManager::search_rule_action(process_name, file_path),
            FileSystemRuleAction::Deny | FileSystemRuleAction::ReadOnly
        )
    }

    /// The `Pre-set-info` handler which intercepts all the attempts to change file information and performs filtering.
    ///
    /// This callback only monitors attempts to rename a file.
    ///
    /// This callback gets the process ID of the file operation requestor from the `data` parameter.
    /// It tries to get information about this process from the [`ProcessManager`] using [`ProcessManager::get_or_add_process_info`]
    /// method.
    ///
    /// It tries to get a current full file path via [`FileNameInformation`] structure and `data` parameter.
    /// Then it obtains a new file path from the `data` parameter using [`Minifilter::new_name_for_rename`] method.
    ///
    /// Then it uses the information about the process, old file path and new file path to search for protection rules in the [`RulesManager`]
    /// If there is no protection rules in the [`RulesManager`] for requestor process and it's parent and for new file path and new file path
    /// and it returns [`FileSystemRuleAction::Bypass`] action, the callback just returns [`FLT_PREOP_SUCCESS_NO_CALLBACK`] which
    /// indicates that the minifilter is returning the I/O operation to `FltMgr` for further processing.
    ///
    /// If any protection rule was found and [`RulesManager`] returns it, this callback applies the [`FileSystemRuleAction`]
    /// to the file operation.
    ///
    /// It uses [`Minifilter::deny_access`] handler for both [`FileSystemRuleAction::Deny`] and [`FileSystemRuleAction::ReadOnly`] rule types.
    ///
    /// These steps apply not only to the requestor process, but also to its parent process (if it is still running).
    ///
    /// # Notes
    /// If it fails at any step it just returns the [`FLT_PREOP_SUCCESS_NO_CALLBACK`] status and doesn't perform
    /// filtering to avoid blocking legal operations and corrupting the system.
    ///
    /// # Safety
    /// This function is inherently unsafe because it's a pre-set-info filesystem callback called by filter manager.
    /// Parameters are provided by the operating system when some process tries to perform a file operation and it
    /// ensures that they are valid.
    unsafe extern "C" fn pre_set_info(
        data: PFLT_CALLBACK_DATA,
        _flt_objects: PCFLT_RELATED_OBJECTS,
        _completion_context: *mut PVOID,
    ) -> FLT_PREOP_CALLBACK_STATUS {
        // SAFETY:
        // Inherently unsafe as a system call. The system ensures that the the `data` parameter
        // is a valid pointer to `FLT_CALLBACK_DATA` structure
        let pid = unsafe { FltGetRequestorProcessId(data) };

        let Ok(process_info) = ProcessManager::get_or_add_process_info(pid).inspect_err(|err| {
            log::trace!("Failed to get process info in pre_set_info for pid {pid}: {err}");
        }) else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };

        let Ok(file_name_info) = FileNameInformation::try_from(data).inspect_err(|err| {
            log::trace!(
                "Failed to get file name information in pre_set_info for process {}: {err}",
                process_info.name
            );
        }) else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };

        let Ok(file_path) = file_name_info
            .path()
            .inspect_err(|err| log::trace!("Failed to get file name in pre_set_info: {err}"))
        else {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        };

        let data = if data.is_null() {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        } else {
            // SAFETY:
            // It's safe because we previously checked that the `data` pointer is not null
            unsafe { data.as_mut_unchecked() }
        };

        // We don't handle FileDispositionInformation, FileDispositionInformationEx info classes because we prevent opening file with DELETE access
        // and it isn't possible to delete a file without this right.
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex

        #[allow(non_upper_case_globals)]
        match Self::set_file_info_class(data) {
            FileRenameInformation | FileRenameInformationEx => {
                let new_file_path = Self::new_name_for_rename(data);

                let new_file_path = match dos_path_to_nt(&new_file_path) {
                    Ok(path) => path,
                    Err(err) => {
                        log::warn!(
                            "Failed to convert dos path {new_file_path} to nt path in rename handler: {err}"
                        );
                        return FLT_PREOP_SUCCESS_NO_CALLBACK;
                    }
                };

                // Check protection rules for requestor and old file path
                if Self::protection_rule_exists(&process_info.name, &file_path) {
                    return Self::deny_access(data);
                }

                // Check protection rules for requestor and new file path
                if Self::protection_rule_exists(&process_info.name, &new_file_path) {
                    return Self::deny_access(data);
                }

                let parent_process_info =
                    ProcessManager::get_or_add_parent_process_info(&process_info);
                if let Some(parent_process_info) = parent_process_info {
                    // Check protection rules for requestor's parent and old file path
                    if Self::protection_rule_exists(&parent_process_info.name, &file_path) {
                        return Self::deny_access(data);
                    }

                    // Check protection rules for requestor's parent and new file path
                    if Self::protection_rule_exists(&parent_process_info.name, &new_file_path) {
                        return Self::deny_access(data);
                    }
                }
            }
            _ => {}
        }

        FLT_PREOP_SUCCESS_NO_CALLBACK
    }
}

impl Drop for Minifilter {
    /// Unregister the minifilter using [`FltUnregisterFilter`] function.
    /// Does nothing if [`Minifilter::handle`] is null.
    fn drop(&mut self) {
        if !self.handle.is_null() {
            log::info!("Unregistering the minifilter...");
            // SAFETY:
            // Inherently unsafe as a system call. The caller ensures that the the `filter` parameter
            // is a valid pointer to `FLT_FILTER` structure
            unsafe {
                FltUnregisterFilter(self.handle);
            }
            self.handle = null_mut();
            log::info!("Successfully unregistered the minifilter!");
        }
    }
}

impl Default for Minifilter {
    /// Create an empty [`Minifilter`] structure.
    fn default() -> Self {
        Self {
            driver: null_mut(),
            handle: null_mut(),
        }
    }
}
