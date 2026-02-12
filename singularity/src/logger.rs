use alloc::format;
use alloc::string::String;
use log::{Level, Log, Metadata, Record};
use wdk_sys::PCSTR;
use wdk_sys::ntddk::DbgPrint;

pub struct KernelLogger;

impl Log for KernelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // Log everything up to Debug level
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // We must format the string safely before passing to FFI.
            // DbgPrint expects a null-terminated C-string.
            let message = format!("[Singularity] {}: {}\0", record.level(), record.args());

            unsafe {
                // %s is the format specifier for a string in DbgPrint
                // We pass our formatted Rust string as the argument.
                let format_str = " %s\n\0";
                DbgPrint(format_str.as_ptr() as PCSTR, message.as_ptr() as PCSTR);
            }
        }
    }

    fn flush(&self) {
        // Kernel logging is usually immediate; no flush needed.
    }
}

// Global static instance required by the 'log' crate
static LOGGER: KernelLogger = KernelLogger;

/// Initializes the kernel logger.
///
/// # Errors
/// Returns an error if the logger is already initialized.
pub fn init() -> Result<(), log::SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(Level::Debug.to_level_filter()))
}
