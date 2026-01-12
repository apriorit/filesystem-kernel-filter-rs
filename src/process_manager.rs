use crate::{driver::Driver, kernel_objects::flt_resource::FltResource, process::Process};
use alloc::sync::Arc;
use hashbrown::HashMap;
use kerror::IntoResult;
use nt_string::unicode_string::NtUnicodeString;
use spin::RwLock;
use wdk_sys::{ntddk::PsSetCreateProcessNotifyRoutine, BOOLEAN, HANDLE};

/// Process information that contains info about process image name and parent pid
pub struct ProcessInfo {
    pub name: NtUnicodeString,
    pub ppid: RwLock<Option<u32>>,
}

// SAFETY:
// Thread safety is guaranteed by Arc
unsafe impl Send for ProcessInfo {}
// SAFETY:
// Thread safety is guaranteed by Arc
unsafe impl Sync for ProcessInfo {}

impl ProcessInfo {
    /// Try to create a [`ProcessInfo`] from process identifier.
    pub fn from_pid(pid: u32) -> kerror::Result<Self> {
        let process = Process::try_from_pid(pid)
            .inspect_err(|err| log::trace!("Failed to create Process from pid {pid}: {err}"))?;

        let name = process
            .name()
            .inspect_err(|err| log::trace!("Failed to get process {pid} image name: {err}"))?;

        let parent_pid = RwLock::new(process.ppid().inspect_err(|err| {
            log::trace!("Failed to get process {name}, pid - {pid} parent id: {err}");
        })?);

        Ok(Self {
            name,
            ppid: parent_pid,
        })
    }
}

impl core::fmt::Display for ProcessInfo {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::write!(
            fmt,
            "Process name: {}, ppid: {:?}",
            self.name,
            self.ppid.read()
        )
    }
}

/// Process manager structure that contains information about processes.
///
/// Contains process information as a [`HashMap`] of `pid` and [`ProcessInfo`].
/// Also contains a [`FltResource`] to synchronize access to process info storage.
///
/// Process information is added manually by other modules as needed. Deletion
/// of process information is performed by [`ProcessManager`]. To track the termination
/// of processes, [`ProcessManager`] registers the [`ProcessManager::process_callback`]
/// callback function using [`PsSetCreateProcessNotifyRoutine`] call that lets us know
/// the ID of the terminated process. Also, when a process that is a parent process
/// of one of the saved processes is terminated, [`ProcessManager`] removes information
/// about the parent process from such process, since the parent process has
/// already been stopped.
pub struct ProcessManager {
    processes: HashMap<u32, Arc<ProcessInfo>>,
    processes_lock: FltResource,
}

impl Drop for ProcessManager {
    /// Unregisters the [`ProcessManager::process_callback`] routine.
    fn drop(&mut self) {
        // SAFETY:
        // Inherently unsafe as a system call, `PsSetCreateProcessNotifyRoutine` unregisters the
        // `process_callback` function in system. The caller ensures that the `notifyroutine`
        // parameter is a valid CREATE_PROCESS_NOTIFY_ROUTINE pointer
        let _ =
            unsafe { PsSetCreateProcessNotifyRoutine(Some(Self::process_callback), true.into()) }
                .into_result()
                .inspect_err(|err| {
                    log::error!("Failed to remove the process create callback: {err}");
                });
    }
}

impl ProcessManager {
    /// Create an empty processes storage and initialize a [`FltResource`]
    /// used to synchronize access to this storage.
    ///
    /// Returns an error if [`FltResource`] initialization fails.
    pub fn new() -> kerror::Result<Self> {
        Ok(Self {
            processes: HashMap::default(),
            processes_lock: FltResource::new()?,
        })
    }

    /// Initialize the process manager.
    ///
    /// Sets the [`ProcessManager::process_callback`] routine to monitor processes termination.
    pub fn init() -> kerror::Result<()> {
        ProcessManager::set_process_callback()
            .inspect_err(|err| log::error!("Failed to set process create callback: {err}"))
    }

    /// Set the process notify routine using [`PsSetCreateProcessNotifyRoutine`] call that registers
    /// the [`ProcessManager::process_callback`] callback.
    ///
    /// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine>
    fn set_process_callback() -> kerror::Result<()> {
        // SAFETY:
        // Inherently unsafe as a system call, `PsSetCreateProcessNotifyRoutine` registers the
        // `process_callback` function in system. The caller ensures that the `notifyroutine`
        // parameter is a valid CREATE_PROCESS_NOTIFY_ROUTINE pointer
        unsafe { PsSetCreateProcessNotifyRoutine(Some(Self::process_callback), false.into()) }
            .into_result()
    }

    /// Process create/terminate notify routine.
    ///
    /// This callback is triggered by the system when some process starts or terminates (depending on `create` parameter value).
    ///
    /// [`ProcessManager`] deletes information about saved processes when this routine notifies that a saved process stopped.
    ///
    /// # Safety
    /// This function is inherently unsafe because it's a callback called by system.
    /// Parameters are provided by the operating system when some process starts or terminates and it
    /// ensures that they are valid.
    unsafe extern "C" fn process_callback(_parentid: HANDLE, processid: HANDLE, create: BOOLEAN) {
        // Remove information about the process if is stopped.
        if create == 0 {
            Self::remove_process(processid as _);
        }
    }

    /// Add `process_information` information about the process with the specified `pid` to process manager
    ///
    /// Acquires exclusive lock to modify process manager storage.
    ///
    /// Reserves memory for insertion and adds process information.
    ///
    /// # Notes
    /// When trying to add information about a process whose identifier is already saved,
    /// the process manager logs a warning and does nothing
    fn add_process(pid: u32, process_info: Arc<ProcessInfo>) -> kerror::Result<()> {
        let process_manager = Self::instance_mut();

        let _lock = process_manager.processes_lock.acquire_exclusive();

        process_manager.processes.try_reserve(1).inspect_err(|_| {
            log::error!("Failed to reserve memory for process info {pid} {process_info}");
        })?;

        let _ = process_manager
            .processes
            .try_insert(pid, process_info)
            .inspect_err(|err| {
                log::warn!(
                    "Process {pid} {} is already present in the process manager!",
                    err.value
                );
            });

        Ok(())
    }

    /// Remove process information associated with the specified `pid`.
    /// Also removes the parent process id from all the children of this process.
    ///
    /// Acquires exclusive lock to modify process manager storage.
    ///
    /// Also removes parent process information from those processes for which this process is the parent.
    fn remove_process(pid: u32) {
        let process_manager = Self::instance_mut();

        let _lock = process_manager.processes_lock.acquire_exclusive();

        process_manager
            .processes
            .remove(&pid)
            .inspect(|process| log::trace!("Process {pid}, {} stopped", process.name));

        process_manager
            .processes
            .iter_mut()
            .for_each(|(_, process_info)| {
                if process_info.ppid.read().is_some_and(|ppid| ppid == pid) {
                    *process_info.ppid.write() = None;
                }
            });
    }

    /// Try to get a [`ProcessInfo`] from the process infos storage by `pid`
    ///
    /// Returns `None` if process not found.
    fn process_info(pid: u32) -> Option<Arc<ProcessInfo>> {
        let process_manager = Self::instance_mut();

        let _lock = process_manager.processes_lock.acquire_shared();

        Some(Arc::clone(process_manager.processes.get(&pid)?))
    }

    /// Get a parent [`ProcessInfo`] from the process infos storage by
    /// child [`ProcessInfo`] which contains parent process id.
    ///
    /// Returns `None` if the child `process_info` has no parent process (`ppid` = `None`)
    ///
    /// If the parent process is still running, this call uses the [`ProcessManager::get_or_add_process_info`]
    /// call to get the parent process info or create and save it if it's absent.
    pub fn get_or_add_parent_process_info(
        process_info: &Arc<ProcessInfo>,
    ) -> Option<Arc<ProcessInfo>> {
        let process_manager = Self::instance_mut();

        let _lock = process_manager.processes_lock.acquire_exclusive();

        if let Some(ppid) = *process_info.ppid.read() {
            Self::get_or_add_process_info(ppid).ok()
        } else {
            None
        }
    }

    /// Get a [`ProcessInfo`] by `pid` from the process info storage or create it if it's absent and return.
    ///
    /// Searches for process info in the process infos store using [`ProcessManager::process_info`] call.
    /// If it succeeds it returns an `Arc<ProcessInfo>` pointing to process information.
    /// If the process information is absent it tries to create it via [`ProcessInfo::from_pid`]. And adds
    /// it to the [`ProcessManager`] process info storage.
    pub fn get_or_add_process_info(pid: u32) -> kerror::Result<Arc<ProcessInfo>> {
        if let Some(process_info) = Self::process_info(pid) {
            return Ok(process_info);
        }

        let process_info = ProcessInfo::from_pid(pid)?;
        let shared_process_info = Arc::try_new(process_info).inspect_err(|err| {
            log::error!("Failed to create an Arc for process with pid {pid}: {err}");
        })?;

        log::trace!(
            "Adding process info: pid - {pid}, name - {}",
            shared_process_info.name
        );
        Self::add_process(pid, Arc::clone(&shared_process_info))
            .inspect_err(|err| log::error!("Failed to add process info: {err}"))?;

        Ok(shared_process_info)
    }

    /// Get a mutable reference to the [`ProcessManager`] global instance
    /// stored in the [`Driver`] instance.
    pub fn instance_mut<'a>() -> &'a mut Self {
        Driver::instance_mut()
            .process_manager
            .as_mut()
            .expect("Process manager must exist to get a mutable instance reference.")
    }
}
