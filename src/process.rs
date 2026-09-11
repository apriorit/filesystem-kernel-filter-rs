use crate::{
    err_map::IntoNtResult,
    kernel_objects::{eprocess::EProcess, handle::Handle},
    string_utils::NtStrExt,
};
use alloc::vec::Vec;
use core::{
    mem::MaybeUninit,
    ptr::{from_mut, null_mut},
};
use nt_string::{
    nt_unicode_str,
    unicode_string::{NtUnicodeStr, NtUnicodeString},
};
use ntresult::{Error, IntoResult};
use wdk_sys::{
    ntddk::{ObOpenObjectByPointer, PsGetProcessId},
    _MODE::KernelMode,
    _PROCESSINFOCLASS::{ProcessBasicInformation, ProcessImageFileName},
    GENERIC_ALL, OBJ_KERNEL_HANDLE, PROCESS_BASIC_INFORMATION, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_UNSUCCESSFUL, UNICODE_STRING,
};
use windows_sys::Wdk::System::Threading::ZwQueryInformationProcess;

const SYSTEM_PROCESS_ID: u32 = 4;
const SYSTEM_PROCESS_PATH: NtUnicodeStr<'static> =
    nt_unicode_str!(r"C:\Windows\system32\ntoskrnl.exe");
const SYSTEM_PROCESS_NAME: NtUnicodeStr<'static> = nt_unicode_str!(r"ntoskrnl.exe");

/// Process structure that contains process associated data
pub struct Process {
    /// An [`EProcess`] structure that contains a pointer to the `EPROCESS` structure of this process.
    eprocess: EProcess,
    /// A [`Handle`] to this process.
    handle: Handle,
}

impl Process {
    /// Try to create a [`Process`] from the `pid`.
    ///
    /// Gets a pointer to the `EPROCESS` structure of this process.
    /// And opens a handle to this process for all processes except system process
    /// (pid = 4) because it leads to system freeze.
    pub fn try_from_pid(pid: u32) -> ntresult::Result<Self> {
        let eprocess = EProcess::from_pid(pid)?;
        let handle = if Self::is_system_process_id(pid) {
            Handle::new()
        } else {
            Self::open_handle(&eprocess)?
        };

        Ok(Self { eprocess, handle })
    }

    /// Try to open process handle by `eprocess` structure.
    ///
    /// Uses the [`ObOpenObjectByPointer`] call to get a handle.
    fn open_handle(eprocess: &EProcess) -> ntresult::Result<Handle> {
        let mut handle = null_mut();

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that the `object` parameter
        // is a valid pointer to EPROCESS structure and handle is a valid mutable handle pointer
        unsafe {
            ObOpenObjectByPointer(
                eprocess.eprocess().cast(),
                OBJ_KERNEL_HANDLE as _,
                null_mut(),
                GENERIC_ALL,
                null_mut(),
                KernelMode.try_into()?,
                &raw mut handle,
            )
        }
        .into_result()?;

        Ok(Handle::new().with_handle(handle))
    }

    /// Get a full process image path.
    ///
    /// This call tries to get a full process image path by querying the process information with
    /// [`ZwQueryInformationProcess`] call and [`ProcessImageFileName`] information class.
    pub fn path(&self) -> ntresult::Result<NtUnicodeString> {
        if self.is_system_process() {
            return NtUnicodeString::try_from(&SYSTEM_PROCESS_PATH).into_nt_result();
        }

        let mut buffer_size = 0;

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that process handle is a
        // valid handle
        let status = unsafe {
            ZwQueryInformationProcess(
                self.handle.handle(),
                ProcessImageFileName,
                null_mut(),
                0,
                &raw mut buffer_size,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            // `Vec::try_with_capacity` is unstable so we use `new` + `try_reserve`
            let mut buffer: Vec<u8> = Vec::new();
            buffer.try_reserve(usize::try_from(buffer_size)?)?;

            // SAFETY:
            // Inherently unsafe as a system call. The caller ensures that process handle is a
            // valid handle and `buffer` is large enough to obtain process image name
            unsafe {
                ZwQueryInformationProcess(
                    self.handle.handle(),
                    ProcessImageFileName,
                    buffer.as_mut_ptr().cast(),
                    buffer.capacity().try_into()?,
                    &raw mut buffer_size,
                )
            }
            .into_result()?;

            #[allow(clippy::cast_ptr_alignment)]
            let process_name_buff = buffer.as_ptr().cast::<UNICODE_STRING>();

            // SAFETY:
            // Raw data used to create a NtUnicodeStr. The system ensures that the `process_name_buff`,
            // obtained from the ZwQueryInformationProcess call is valid and points to a real UNICODE_STRING
            let process_name = unsafe {
                NtUnicodeStr::from_raw_parts(
                    (*process_name_buff).Buffer,
                    (*process_name_buff).Length,
                    (*process_name_buff).MaximumLength,
                )
            };

            Ok(NtUnicodeString::try_from(&process_name).into_nt_result()?)
        } else {
            Err(Error::from_ntstatus(status))
        }
    }

    /// Get a process image name.
    ///
    /// Uses the [`Process::path`] call to get the full process image path and returns the part of it
    /// following the last backslash character
    pub fn name(&self) -> ntresult::Result<NtUnicodeString> {
        if self.is_system_process() {
            return NtUnicodeString::try_from(&SYSTEM_PROCESS_NAME).into_nt_result();
        }

        let path = self.path()?;

        let last_backslash_idx = path
            .last_index_of(u16::from(b'\\'))
            .ok_or(Error::from_ntstatus(STATUS_UNSUCCESSFUL))?;

        path.substring(u16::try_from(last_backslash_idx)? + 1)
    }

    /// Get a [`PROCESS_BASIC_INFORMATION`] for this process
    ///
    /// This function uses the [`ZwQueryInformationProcess`] call with
    /// [`ProcessBasicInformation`] information class to get a result.
    pub fn basic_info(&self) -> ntresult::Result<PROCESS_BASIC_INFORMATION> {
        // SAFETY:
        // The caller initializes PROCESS_BASIC_INFORMATION structure with zeros to to
        // avoid using garbage data
        let mut basic_info =
            unsafe { MaybeUninit::<PROCESS_BASIC_INFORMATION>::zeroed().assume_init() };

        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that process handle is a
        // valid handle and `basic_info` is large enough to obtain basic process info
        unsafe {
            ZwQueryInformationProcess(
                self.handle.handle(),
                ProcessBasicInformation,
                from_mut(&mut basic_info).cast(),
                size_of::<PROCESS_BASIC_INFORMATION>().try_into()?,
                null_mut(),
            )
        }
        .into_result()?;

        Ok(basic_info)
    }

    /// Get a process id.
    ///
    /// Uses the [`PsGetProcessId`] call to get an id from the `EPROCESS` structure.
    #[inline]
    pub fn pid(&self) -> u32 {
        // SAFETY:
        // Inherently unsafe as a system call. The caller ensures that the value passed to the
        // `PsGetProcessId` function is a valid pointer to EPROCESS structure
        unsafe { PsGetProcessId(self.eprocess.eprocess()) as u32 }
    }

    /// Checks if the identifier of this process is system process identifier (4).
    #[inline]
    pub fn is_system_process_id(pid: u32) -> bool {
        pid == SYSTEM_PROCESS_ID
    }

    /// Checks if this process is system process.
    #[inline]
    pub fn is_system_process(&self) -> bool {
        Self::is_system_process_id(self.pid())
    }

    /// Get a parent process identifier, if any.
    ///
    /// Reads and returns the [`PROCESS_BASIC_INFORMATION::InheritedFromUniqueProcessId`] field.
    /// Always returns `None` for the system process (pid = 4).
    pub fn ppid(&self) -> ntresult::Result<Option<u32>> {
        if self.is_system_process() {
            return Ok(None);
        }

        Ok(Some(u32::try_from(
            self.basic_info()?.InheritedFromUniqueProcessId,
        )?))
    }
}
