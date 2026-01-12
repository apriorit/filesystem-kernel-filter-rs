use crate::{
    minifilter::Minifilter, process_manager::ProcessManager, registry_manager::RegistryManager,
    rules_manager::RulesManager,
};
use nt_string::unicode_string::NtUnicodeStr;
use wdk_sys::{NTSTATUS, PDRIVER_OBJECT, STATUS_SUCCESS};

const BUILD_TIME: &str = env!("BUILD_TIME");

/// The [`Driver`] global variable that stores all the driver related information.
pub static mut G_DRIVER: Option<Driver> = None;

/// Driver structure that contains all the driver components.
#[derive(Default)]
pub struct Driver {
    pub process_manager: Option<ProcessManager>,
    pub rules_manager: Option<RulesManager>,
    pub registry_manager: Option<RegistryManager>,
    pub minifilter: Option<Minifilter>,
}

impl Driver {
    /// Create a [`Driver`] object and save it to the [`G_DRIVER`] global variable.
    /// Return a mutable reference to the created [`Driver`] object.
    ///
    /// # Notes
    /// Doesn't register or initialize the driver or it's components. Just creates the
    /// [`G_DRIVER`] global variable.
    pub fn create<'a>() -> &'a mut Driver {
        // SAFETY:
        // `G_DRIVER` is initialization happens only once on driver start.
        // There can't be two threads simultaneously initializing it. This object
        // is deinitialized at driver stop
        unsafe { G_DRIVER = Some(Self::default()) };

        Self::instance_mut()
    }

    /// Initialize the driver and all it's components.
    ///
    /// Initializes the [`ProcessManager`], [`RulesManager`], [`RegistryManager`] and
    /// [`Minifilter`] components sequentially.
    ///
    /// # Parameters
    ///
    /// - `driver` - Mutable pointer to the [`DRIVER_OBJECT`] that represents current driver.
    /// - `altitude` - A reference to [`NtUnicodeStr`] pointing to current driver altitude.
    ///
    /// # Returns
    /// Returns an error if some driver component initialization fails.
    ///
    /// # Notes
    /// Don't change the initialization sequence if you don't really need it because some
    /// components depend on other.
    pub fn init(&mut self, driver: PDRIVER_OBJECT, altitude: &NtUnicodeStr) -> kerror::Result<()> {
        log::info!("Driver started. Build time: {BUILD_TIME}");

        self.process_manager = Some(ProcessManager::new()?);
        ProcessManager::init()
            .inspect_err(|err| log::error!("Failed to initialize process manager: {err}"))?;
        log::info!("Process manager initialized successfully!");

        self.rules_manager = Some(RulesManager::new()?);
        self.rules_manager
            .as_mut()
            .expect("Rules manager was already created")
            .init()
            .inspect_err(|err| log::error!("Failed to initialize rules manager: {err}"))?;
        log::info!("Rules manager initialized successfully!");

        self.registry_manager = Some(RegistryManager::new());
        self.registry_manager
            .as_mut()
            .expect("Registry manager was already created")
            .init(driver, altitude)
            .inspect_err(|err| log::error!("Failed to initialize registry manager: {err}"))?;
        log::info!("Registry manager initialized successfully!");

        self.minifilter = Some(Minifilter::new());
        self.minifilter
            .as_mut()
            .expect("Minifilter was already created and can be initialized")
            .init(driver)
            .inspect_err(|err| log::error!("Failed to initialize minifilter driver: {err}"))?;
        log::info!("Minifilter initialized successfully!");

        self.minifilter
            .as_mut()
            .expect("Minifilter was already created")
            .start_filtering()?;
        log::info!("Minifilter started filtering successfully!");

        log::info!("Driver initialized successfully!");

        Ok(())
    }

    /// Deinitialize the driver components.
    ///
    /// Triggers the destructors of all the driver components.
    /// Performs deinitialization of components in the reverse order of their initialization.
    ///
    /// # Notes
    /// Deinitializes only those components that have already been initialized.
    /// If driver initialization failed and not all components have been initialized,
    /// it will attempt to deinitialize only the initialized components.
    pub fn deinit(&mut self) {
        log::info!("Driver deinitialization...");

        if self.minifilter.is_some() {
            self.minifilter = None;
            log::info!("Minifilter stopped.");
        }

        if self.registry_manager.is_some() {
            self.registry_manager = None;
            log::info!("Registry manager stopped.");
        }

        if self.rules_manager.is_some() {
            self.rules_manager = None;
            log::info!("Rules manager stopped.");
        }

        if self.process_manager.is_some() {
            self.process_manager = None;
            log::info!("Process manager stopped.");
        }

        log::info!("Driver successfully deinitialized!");
    }

    /// Driver unload callback.
    ///
    /// Called when the system unloads the driver. This routine deinitializes the [`Driver`] global instance.
    ///
    /// # Notes
    /// If a minifilter driver's `DriverEntry` routine returns a warning or
    /// error NTSTATUS value, the `FilterUnloadCallback` routine is not called; the
    /// filter manager simply unloads the minifilter driver.
    /// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/when-the-filterunloadcallback-routine-is-called>
    pub unsafe extern "C" fn driver_unload_callback(
        _flags: u32, /* FLT_FILTER_UNLOAD_FLAGS */
    ) -> NTSTATUS {
        log::info!("Driver unload callback.");

        Driver::instance_mut().deinit();

        log::info!("Driver successfully stopped!");

        STATUS_SUCCESS
    }

    /// Get a mutable reference to the [`Driver`] instance stored in
    /// the [`G_DRIVER`] global variable
    pub fn instance_mut<'a>() -> &'a mut Self {
        // SAFETY:
        // `G_DRIVER` is initialized at driver start and deinitialized when is stops.
        // The caller calls this method only between driver initialization and deinitialization
        unsafe {
            #[allow(static_mut_refs)]
            G_DRIVER
                .as_mut()
                .expect("Driver must exist to get a mutable instance reference.")
        }
    }
}
