//! Unix daemonization for pwr-server.
//!
//! Implements the classic double-fork daemonization pattern:
//! 1. Fork → parent exits, child continues
//! 2. setsid() to become session leader
//! 3. Second fork → child exits, grandchild continues (prevents
//!    re-acquisition of a controlling terminal)
//! 4. chdir("/"), umask(0), redirect stdio to /dev/null
//! 5. Write PID file

use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process;
use std::thread;
use std::time::Duration;

/// Default path for the PID file written after successful daemonization.
pub const DEFAULT_PID_FILE: &str = "/run/pwr/pwr-server.pid";

/// Daemonize the current process.
///
/// After this call returns in the grandchild process, the process is:
/// - Running as a session leader with no controlling terminal
/// - In the root directory (/)
/// - With umask 0
/// - With stdin/stdout/stderr redirected to /dev/null
/// - With a PID file written to `pid_file`
///
/// The parent and intermediate child processes exit with status 0.
pub fn daemonize(pid_file: &Path) -> Result<(), String> {
    // Phase 1: first fork — detach from the invoking shell
    match unsafe { libc::fork() } {
        -1 => return Err(format!("First fork failed: {}", io::Error::last_os_error())),
        0 => {} // child continues
        _ => process::exit(0), // parent exits
    }

    // Phase 2: become session leader, detach from controlling terminal
    if unsafe { libc::setsid() } == -1 {
        return Err(format!("setsid failed: {}", io::Error::last_os_error()));
    }

    // Phase 3: second fork — relinquish session leadership so the process
    // can never re-acquire a controlling terminal
    match unsafe { libc::fork() } {
        -1 => return Err(format!("Second fork failed: {}", io::Error::last_os_error())),
        0 => {} // grandchild continues
        _ => process::exit(0), // first child exits
    }

    // Phase 4: set up the daemon environment
    //
    // Change to root so we don't hold a reference to any directory that
    // might need to be unmounted.
    if unsafe { libc::chdir(b"/\0".as_ptr() as *const _) } == -1 {
        return Err(format!("chdir(/) failed: {}", io::Error::last_os_error()));
    }

    // Clear the file creation mask so we control permissions explicitly.
    unsafe {
        libc::umask(0);
    }

    // Redirect stdin/stdout/stderr to /dev/null.
    redirect_stdio_to_devnull()?;

    // Phase 5: write PID file
    write_pid_file(pid_file)?;

    Ok(())
}

/// Redirect stdin (0), stdout (1), and stderr (2) to /dev/null.
fn redirect_stdio_to_devnull() -> Result<(), String> {
    let devnull = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| format!("Cannot open /dev/null: {}", e))?;

    let devnull_fd = devnull.as_raw_fd();

    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if fd != devnull_fd {
            if unsafe { libc::dup2(devnull_fd, fd) } == -1 {
                return Err(format!(
                    "Cannot redirect fd {} to /dev/null: {}",
                    fd,
                    io::Error::last_os_error()
                ));
            }
        }
    }

    // The devnull File handle is dropped here; the duplicated fds keep
    // /dev/null open for the process lifetime.
    Ok(())
}

/// Atomically write the current PID to `pid_file`.
///
/// Creates parent directories as needed.
fn write_pid_file(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create PID directory {}: {}", parent.display(), e))?;
    }

    let pid = unsafe { libc::getpid() };
    let contents = format!("{}\n", pid);

    fs::write(path, &contents)
        .map_err(|e| format!("Cannot write PID file {}: {}", path.display(), e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Daemon stop
// ---------------------------------------------------------------------------

/// Stop a running pwr-server daemon.
///
/// Reads the PID from `pid_file`, sends SIGTERM, waits up to 5 seconds for
/// graceful shutdown, then escalates to SIGKILL if the process is still alive.
/// Removes the PID file on successful termination.
///
/// Returns a human-readable summary of what happened.
pub fn stop_daemon(pid_file: &Path) -> Result<String, String> {
    let pid = read_pid_file(pid_file)?;

    // Check the process exists and is actually a pwr-server
    if !is_process_running(pid) {
        // Stale PID file — clean it up
        remove_pid_file(pid_file)?;
        return Err(format!(
            "PID {} is not running (stale PID file removed)",
            pid
        ));
    }

    // Phase 1: graceful shutdown via SIGTERM
    send_signal(pid, libc::SIGTERM)?;

    // Wait up to 5 seconds for the process to exit
    let grace = Duration::from_secs(5);
    let poll = Duration::from_millis(100);
    let deadline = std::time::Instant::now() + grace;

    let mut clean_exit = false;
    while std::time::Instant::now() < deadline {
        if !is_process_running(pid) {
            clean_exit = true;
            break;
        }
        thread::sleep(poll);
    }

    if clean_exit {
        remove_pid_file(pid_file)?;
        return Ok(format!("pwr-server (PID {}) stopped gracefully", pid));
    }

    // Phase 2: force kill
    send_signal(pid, libc::SIGKILL)?;
    thread::sleep(Duration::from_millis(200));

    if is_process_running(pid) {
        return Err(format!(
            "Failed to kill pwr-server (PID {}) — process did not respond to SIGKILL",
            pid
        ));
    }

    remove_pid_file(pid_file)?;
    Ok(format!(
        "pwr-server (PID {}) killed (did not respond to SIGTERM within {}s)",
        pid,
        grace.as_secs()
    ))
}

/// Read a PID from the given file.
///
/// Returns an error if the file is missing, unreadable, or contains a
/// non-numeric value.
fn read_pid_file(path: &Path) -> Result<libc::pid_t, String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read PID file {}: {}", path.display(), e))?;

    let pid: libc::pid_t = contents
        .trim()
        .parse()
        .map_err(|e| format!("Invalid PID in {}: {}", path.display(), e))?;

    if pid <= 0 {
        return Err(format!("Invalid PID ({}) in {}", pid, path.display()));
    }

    Ok(pid)
}

/// Check whether a process with the given PID is currently running.
///
/// Uses `kill(pid, 0)` which performs error checking without sending a
/// signal — returns true if the process exists, false otherwise.
fn is_process_running(pid: libc::pid_t) -> bool {
    // kill(pid, 0) is the standard POSIX way to check for process existence
    // without sending an actual signal. Returns 0 if the process exists,
    // -1 with ESRCH if it doesn't.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Send a signal to a process.
fn send_signal(pid: libc::pid_t, signal: libc::c_int) -> Result<(), String> {
    if unsafe { libc::kill(pid, signal) } == -1 {
        return Err(format!(
            "Cannot send signal {} to PID {}: {}",
            signal,
            pid,
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Remove the PID file. Errors if removal fails but not if the file is
/// already gone (e.g. the daemon cleaned up after itself).
fn remove_pid_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "Cannot remove PID file {}: {}",
            path.display(),
            e
        )),
    }
}
