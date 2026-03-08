//! IPC transport abstraction: Unix domain socket + Windows named pipe.
//!
//! Provides platform-aware listener and stream types for the IPC server.
//! Transport is selected automatically based on platform and path format:
//! - Unix/macOS: Unix domain socket (default, existing behavior)
//! - Windows: Named pipe when path starts with `\\.\pipe\`
//!
//! The abstraction surface is intentionally minimal:
//! listen / accept / read / write / clone / timeout / cleanup.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

// ── Path Detection ──────────────────────────────────────────

/// Check if a path looks like a Windows named pipe path.
///
/// Used for transport selection when `--socket-path` provides a Windows pipe path.
/// Active on Windows; on Unix, used by tests and transport detection logic.
#[allow(dead_code)]
pub fn is_windows_pipe_path(path: &str) -> bool {
    path.starts_with(r"\\.\pipe\") || path.starts_with(r"\\.\PIPE\")
}

/// Default IPC endpoint path for the current platform.
#[cfg(not(windows))]
pub const DEFAULT_IPC_PATH: &str = "/tmp/bolt-daemon.sock";

/// Default IPC endpoint path for the current platform.
#[cfg(windows)]
pub const DEFAULT_IPC_PATH: &str = r"\\.\pipe\bolt-daemon";

// ── IPC Listener ────────────────────────────────────────────

/// Platform-aware IPC listener. Wraps Unix domain socket or Windows named pipe.
pub enum IpcListener {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
    #[cfg(windows)]
    NamedPipe(windows_pipe::NamedPipeListener),
}

impl IpcListener {
    /// Bind to the given path and start listening.
    ///
    /// On Unix: creates a Unix domain socket, chmod 600, non-blocking.
    /// On Windows with pipe path: creates a named pipe with current-user-only DACL.
    pub fn bind(path: &str) -> io::Result<(Self, PathBuf)> {
        #[cfg(windows)]
        if is_windows_pipe_path(path) {
            let listener = windows_pipe::NamedPipeListener::bind(path)?;
            return Ok((Self::NamedPipe(listener), PathBuf::from(path)));
        }

        #[cfg(unix)]
        {
            let pb = PathBuf::from(path);

            // Remove stale socket file if it exists.
            if pb.exists() {
                eprintln!("[IPC] removing stale socket: {}", pb.display());
                std::fs::remove_file(&pb)?;
            }

            let listener = std::os::unix::net::UnixListener::bind(&pb)?;

            // chmod 600 — owner-only access.
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&pb, perms)?;
            }

            // Set non-blocking so we can check for shutdown.
            listener.set_nonblocking(true)?;

            Ok((Self::Unix(listener), pb))
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPC transport not supported on this platform",
            ))
        }
    }

    /// Accept a new client connection.
    ///
    /// Returns `WouldBlock` if no client is waiting (non-blocking).
    pub fn accept(&self) -> io::Result<IpcStream> {
        match self {
            #[cfg(unix)]
            Self::Unix(listener) => {
                let (stream, _addr) = listener.accept()?;
                Ok(IpcStream::Unix(stream))
            }
            #[cfg(windows)]
            Self::NamedPipe(listener) => {
                let stream = listener.accept()?;
                Ok(IpcStream::NamedPipe(stream))
            }
        }
    }

    /// Prepare for the next client connection after one disconnects.
    ///
    /// On Unix: no-op (listener socket continues accepting).
    /// On Windows: disconnects the pipe instance for reuse.
    pub fn prepare_next(&self) {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => {} // no-op
            #[cfg(windows)]
            Self::NamedPipe(listener) => listener.disconnect_client(),
        }
    }
}

// ── IPC Stream ──────────────────────────────────────────────

/// Platform-aware IPC stream (connected client).
pub enum IpcStream {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    #[cfg(windows)]
    NamedPipe(windows_pipe::NamedPipeStream),
}

impl std::fmt::Debug for IpcStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => f.debug_tuple("Unix").field(s).finish(),
            #[cfg(windows)]
            Self::NamedPipe(_) => f.debug_tuple("NamedPipe").finish(),
        }
    }
}

impl IpcStream {
    /// Set the stream to blocking or non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.set_nonblocking(nonblocking),
            #[cfg(windows)]
            Self::NamedPipe(s) => s.set_nonblocking(nonblocking),
        }
    }

    /// Set read timeout. `None` means block indefinitely.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.set_read_timeout(timeout),
            #[cfg(windows)]
            Self::NamedPipe(s) => s.set_read_timeout(timeout),
        }
    }

    /// Clone the stream (for splitting into read/write halves).
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => Ok(Self::Unix(s.try_clone()?)),
            #[cfg(windows)]
            Self::NamedPipe(s) => Ok(Self::NamedPipe(s.try_clone()?)),
        }
    }
}

// ── Read / Write for IpcStream (owned) ──────────────────────

impl Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf),
            #[cfg(windows)]
            Self::NamedPipe(s) => s.read(buf),
        }
    }
}

impl Write for IpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.write(buf),
            #[cfg(windows)]
            Self::NamedPipe(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.flush(),
            #[cfg(windows)]
            Self::NamedPipe(s) => s.flush(),
        }
    }
}

// ── Read / Write for &IpcStream (shared ref) ────────────────
//
// Required for `BufWriter<&IpcStream>` and `BufReader` patterns
// where the underlying stream is borrowed. On Unix, &UnixStream
// implements Read+Write via the raw fd. On Windows, named pipe
// handles are similarly stateless for I/O.

impl Read for &IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match **self {
            #[cfg(unix)]
            IpcStream::Unix(ref s) => {
                let mut r: &std::os::unix::net::UnixStream = s;
                r.read(buf)
            }
            #[cfg(windows)]
            IpcStream::NamedPipe(ref s) => s.read_ref(buf),
        }
    }
}

impl Write for &IpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match **self {
            #[cfg(unix)]
            IpcStream::Unix(ref s) => {
                let mut w: &std::os::unix::net::UnixStream = s;
                w.write(buf)
            }
            #[cfg(windows)]
            IpcStream::NamedPipe(ref s) => s.write_ref(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match **self {
            #[cfg(unix)]
            IpcStream::Unix(ref s) => {
                let mut w: &std::os::unix::net::UnixStream = s;
                w.flush()
            }
            #[cfg(windows)]
            IpcStream::NamedPipe(ref s) => s.flush_ref(),
        }
    }
}

// ── Cleanup ─────────────────────────────────────────────────

/// Clean up the IPC endpoint on shutdown.
pub(crate) fn cleanup_ipc_endpoint(path: &std::path::Path) {
    #[cfg(unix)]
    {
        if path.exists() {
            let _ = std::fs::remove_file(path);
            eprintln!("[IPC] cleaned up socket: {}", path.display());
        }
    }
    #[cfg(windows)]
    {
        // Named pipes are kernel objects — cleanup happens when the last
        // handle is closed. No filesystem artifact to remove.
        let _ = path;
        eprintln!("[IPC] named pipe server closed");
    }
}

// ── Windows Named Pipe Implementation ───────────────────────

#[cfg(windows)]
pub(crate) mod windows_pipe {
    use std::io::{self, Read, Write};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::DuplicateHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA,
        ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, FALSE, HANDLE, INVALID_HANDLE_VALUE, TRUE,
    };
    use windows_sys::Win32::Security::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetTokenInformation, TokenUser,
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe,
        SetNamedPipeHandleState, PIPE_ACCESS_DUPLEX, PIPE_NOWAIT, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::DUPLICATE_SAME_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// SDDL revision constant.
    const SDDL_REVISION_1: u32 = 1;

    /// Convert a Rust &str to a null-terminated wide string (UTF-16).
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Get the current user's SID as a string (e.g. "S-1-5-21-...").
    ///
    /// Used to build an SDDL security descriptor that restricts pipe
    /// access to the current user only (0600-equivalent).
    fn current_user_sid_string() -> io::Result<String> {
        unsafe {
            // Open process token.
            let mut token_handle: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
                return Err(io::Error::last_os_error());
            }

            // Query token for user SID — first call to get required buffer size.
            let mut needed: u32 = 0;
            let _ = GetTokenInformation(
                token_handle,
                TokenUser,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
            if needed == 0 {
                CloseHandle(token_handle);
                return Err(io::Error::last_os_error());
            }

            // Allocate buffer and query again.
            let mut buffer = vec![0u8; needed as usize];
            if GetTokenInformation(
                token_handle,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) == 0
            {
                CloseHandle(token_handle);
                return Err(io::Error::last_os_error());
            }
            CloseHandle(token_handle);

            // Extract SID pointer from TOKEN_USER struct.
            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid = token_user.User.Sid;

            // Convert SID to string.
            let mut sid_string_ptr: *mut u16 = std::ptr::null_mut();
            // ConvertSidToStringSidW is in advapi32.
            // Using the windows-sys binding:
            if windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(
                sid,
                &mut sid_string_ptr,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }

            // Convert wide string to Rust String.
            let mut len = 0;
            while *sid_string_ptr.add(len) != 0 {
                len += 1;
            }
            let sid_str = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string_ptr, len));
            LocalFree(sid_string_ptr.cast());

            Ok(sid_str)
        }
    }

    /// Build a SECURITY_ATTRIBUTES restricting access to the current user only.
    ///
    /// SDDL: `D:P(A;;GA;;;<current_user_sid>)`
    /// - D:P = protected DACL (no inheritance)
    /// - A = allow
    /// - GA = Generic All (read, write, execute)
    /// - <sid> = current user's SID
    ///
    /// This is the Windows equivalent of Unix chmod 600.
    fn create_current_user_security() -> io::Result<(*mut SECURITY_ATTRIBUTES, PSECURITY_DESCRIPTOR)>
    {
        let sid = current_user_sid_string()?;
        let sddl = format!("D:P(A;;GA;;;{})", sid);
        let sddl_wide = to_wide(&sddl);

        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "failed to create security descriptor: {}",
                        io::Error::last_os_error()
                    ),
                ));
            }

            // Allocate SECURITY_ATTRIBUTES on the heap (must outlive CreateNamedPipeW).
            let sa = Box::into_raw(Box::new(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: FALSE,
            }));

            Ok((sa, sd))
        }
    }

    // ── Named Pipe Listener ─────────────────────────────────

    /// Windows named pipe listener (server-side).
    pub(crate) struct NamedPipeListener {
        handle: HANDLE,
        pipe_name: Vec<u16>,
    }

    // SAFETY: Named pipe HANDLEs are thread-safe for the operations
    // we perform (ConnectNamedPipe, DisconnectNamedPipe).
    unsafe impl Send for NamedPipeListener {}
    unsafe impl Sync for NamedPipeListener {}

    impl NamedPipeListener {
        /// Create a named pipe server endpoint.
        ///
        /// Security: pipe is restricted to the current user via SDDL DACL.
        /// Mode: PIPE_NOWAIT for non-blocking accept, PIPE_REJECT_REMOTE_CLIENTS.
        pub fn bind(path: &str) -> io::Result<Self> {
            let pipe_name = to_wide(path);

            // Build current-user-only security descriptor.
            let (sa_ptr, sd) = create_current_user_security()?;

            let handle = unsafe {
                let h = CreateNamedPipeW(
                    pipe_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,     // max instances (single-client)
                    65536, // output buffer size
                    65536, // input buffer size
                    0,     // default timeout
                    sa_ptr,
                );

                // Free security resources (pipe retains the DACL).
                LocalFree(sd.cast());
                let _ = Box::from_raw(sa_ptr);

                h
            };

            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }

            eprintln!(
                "[IPC] named pipe listening on {} (single-client, current-user-only)",
                path
            );

            Ok(Self { handle, pipe_name })
        }

        /// Accept a client connection (non-blocking).
        ///
        /// Returns `WouldBlock` if no client is waiting.
        pub fn accept(&self) -> io::Result<NamedPipeStream> {
            let connected = unsafe { ConnectNamedPipe(self.handle, std::ptr::null_mut()) };

            if connected != 0 {
                // Client connected synchronously.
                return self.make_stream();
            }

            let err = unsafe { GetLastError() };
            match err {
                ERROR_PIPE_CONNECTED => {
                    // Client was already connected before ConnectNamedPipe.
                    self.make_stream()
                }
                ERROR_PIPE_LISTENING => {
                    // No client waiting — non-blocking equivalent of WouldBlock.
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "no client connected",
                    ))
                }
                ERROR_IO_PENDING => {
                    // Overlapped I/O pending (shouldn't happen without OVERLAPPED).
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "connection pending",
                    ))
                }
                _ => Err(io::Error::from_raw_os_error(err as i32)),
            }
        }

        /// Create a stream by duplicating the pipe handle.
        fn make_stream(&self) -> io::Result<NamedPipeStream> {
            let dup = duplicate_handle(self.handle)?;

            // Switch the duplicate to blocking mode for I/O.
            let mut mode: u32 = PIPE_READMODE_BYTE | PIPE_WAIT;
            let ok = unsafe {
                SetNamedPipeHandleState(dup, &mut mode, std::ptr::null_mut(), std::ptr::null_mut())
            };
            if ok == 0 {
                unsafe { CloseHandle(dup) };
                return Err(io::Error::last_os_error());
            }

            Ok(NamedPipeStream {
                handle: dup,
                read_timeout_ms: AtomicU64::new(0),
            })
        }

        /// Disconnect the current client so the pipe instance can accept a new one.
        pub fn disconnect_client(&self) {
            unsafe {
                let _ = FlushFileBuffers(self.handle);
                DisconnectNamedPipe(self.handle);
            }
        }
    }

    impl Drop for NamedPipeListener {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.handle) };
        }
    }

    // ── Named Pipe Stream ───────────────────────────────────

    /// Windows named pipe stream (connected client handle).
    pub(crate) struct NamedPipeStream {
        handle: HANDLE,
        /// Read timeout in milliseconds. 0 = no timeout (blocking).
        read_timeout_ms: AtomicU64,
    }

    // SAFETY: Named pipe HANDLEs are thread-safe for ReadFile/WriteFile.
    unsafe impl Send for NamedPipeStream {}
    unsafe impl Sync for NamedPipeStream {}

    impl NamedPipeStream {
        /// Set blocking or non-blocking mode.
        pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            let mut mode: u32 =
                PIPE_READMODE_BYTE | if nonblocking { PIPE_NOWAIT } else { PIPE_WAIT };
            let ok = unsafe {
                SetNamedPipeHandleState(
                    self.handle,
                    &mut mode,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        /// Set read timeout. `None` = block indefinitely.
        ///
        /// Implementation: stores timeout value; `read()` uses PeekNamedPipe
        /// polling to enforce the deadline without requiring overlapped I/O.
        pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            let ms = timeout.map_or(0, |d| d.as_millis().min(u64::MAX as u128) as u64);
            self.read_timeout_ms.store(ms, Ordering::Relaxed);
            Ok(())
        }

        /// Clone by duplicating the handle.
        pub fn try_clone(&self) -> io::Result<Self> {
            let dup = duplicate_handle(self.handle)?;
            Ok(Self {
                handle: dup,
                read_timeout_ms: AtomicU64::new(self.read_timeout_ms.load(Ordering::Relaxed)),
            })
        }

        /// Raw ReadFile call.
        fn read_raw(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut bytes_read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr().cast(),
                    buf.len().min(u32::MAX as usize) as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA {
                    return Ok(0); // EOF
                }
                Err(io::Error::from_raw_os_error(err as i32))
            } else {
                Ok(bytes_read as usize)
            }
        }

        /// Raw WriteFile call.
        fn write_raw(&self, buf: &[u8]) -> io::Result<usize> {
            let mut bytes_written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle,
                    buf.as_ptr().cast(),
                    buf.len().min(u32::MAX as usize) as u32,
                    &mut bytes_written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(bytes_written as usize)
            }
        }

        /// Read with timeout enforcement via PeekNamedPipe polling.
        fn read_with_timeout(&self, buf: &mut [u8], timeout_ms: u64) -> io::Result<usize> {
            let deadline = Instant::now() + Duration::from_millis(timeout_ms);
            loop {
                // Check if data is available.
                let mut available: u32 = 0;
                let ok = unsafe {
                    PeekNamedPipe(
                        self.handle,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    let err = unsafe { GetLastError() };
                    if err == ERROR_BROKEN_PIPE {
                        return Ok(0); // EOF
                    }
                    return Err(io::Error::from_raw_os_error(err as i32));
                }
                if available > 0 {
                    return self.read_raw(buf);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "named pipe read timed out",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Read via shared reference (for BufReader<&IpcStream> patterns).
        pub fn read_ref(&self, buf: &mut [u8]) -> io::Result<usize> {
            let timeout_ms = self.read_timeout_ms.load(Ordering::Relaxed);
            if timeout_ms > 0 {
                self.read_with_timeout(buf, timeout_ms)
            } else {
                self.read_raw(buf)
            }
        }

        /// Write via shared reference (for BufWriter<&IpcStream> patterns).
        pub fn write_ref(&self, buf: &[u8]) -> io::Result<usize> {
            self.write_raw(buf)
        }

        /// Flush via shared reference.
        pub fn flush_ref(&self) -> io::Result<()> {
            let ok = unsafe { FlushFileBuffers(self.handle) };
            if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    impl Read for NamedPipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_ref(buf)
        }
    }

    impl Write for NamedPipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_raw(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_ref()
        }
    }

    impl Drop for NamedPipeStream {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.handle) };
        }
    }

    // ── Handle Duplication ──────────────────────────────────

    /// Duplicate a Windows HANDLE for the current process.
    fn duplicate_handle(handle: HANDLE) -> io::Result<HANDLE> {
        let mut dup: HANDLE = 0;
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut dup,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(dup)
        }
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Path detection tests (all platforms) ─────────────────

    #[test]
    fn detect_windows_pipe_path_backslash() {
        assert!(is_windows_pipe_path(r"\\.\pipe\bolt-daemon"));
    }

    #[test]
    fn detect_windows_pipe_path_uppercase() {
        assert!(is_windows_pipe_path(r"\\.\PIPE\bolt-daemon"));
    }

    #[test]
    fn detect_unix_socket_path() {
        assert!(!is_windows_pipe_path("/tmp/bolt-daemon.sock"));
    }

    #[test]
    fn detect_unix_relative_path() {
        assert!(!is_windows_pipe_path("bolt-daemon.sock"));
    }

    #[test]
    fn detect_empty_path() {
        assert!(!is_windows_pipe_path(""));
    }

    #[test]
    fn detect_pipe_path_with_subdirectory() {
        assert!(is_windows_pipe_path(r"\\.\pipe\bolt\daemon"));
    }

    #[test]
    fn default_ipc_path_is_not_empty() {
        assert!(!DEFAULT_IPC_PATH.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn default_ipc_path_is_unix_socket() {
        assert!(DEFAULT_IPC_PATH.ends_with(".sock"));
        assert!(!is_windows_pipe_path(DEFAULT_IPC_PATH));
    }

    // ── Unix transport tests ────────────────────────────────

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::io::{BufRead, BufReader, Write};

        fn temp_socket_path() -> String {
            let dir = std::env::temp_dir();
            format!(
                "{}/bolt-transport-test-{}.sock",
                dir.display(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
        }

        #[test]
        fn unix_bind_creates_socket_file() {
            let path = temp_socket_path();
            let (listener, pb) = IpcListener::bind(&path).unwrap();
            assert!(pb.exists());
            drop(listener);
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn unix_socket_permissions_are_0600() {
            use std::os::unix::fs::PermissionsExt;
            let path = temp_socket_path();
            let (_listener, pb) = IpcListener::bind(&path).unwrap();
            let meta = std::fs::metadata(&pb).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0600, got {:04o}", mode);
            drop(_listener);
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn unix_accept_returns_wouldblock_when_no_client() {
            let path = temp_socket_path();
            let (listener, _) = IpcListener::bind(&path).unwrap();
            let result = listener.accept();
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            drop(listener);
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn unix_stream_read_write_roundtrip() {
            let path = temp_socket_path();
            let (listener, _) = IpcListener::bind(&path).unwrap();

            // Connect a client via raw UnixStream.
            let mut client = std::os::unix::net::UnixStream::connect(&path).unwrap();

            // Accept on listener (may need a brief retry for non-blocking).
            let stream;
            loop {
                match listener.accept() {
                    Ok(s) => {
                        stream = s;
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept error: {e}"),
                }
            }

            // Write from server, read from client.
            let mut writer = io::BufWriter::new(&stream);
            writer.write_all(b"hello from server\n").unwrap();
            writer.flush().unwrap();

            let mut reader = BufReader::new(&mut client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "hello from server");

            drop(writer);
            drop(stream);
            drop(listener);
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn unix_stream_try_clone() {
            let path = temp_socket_path();
            let (listener, _) = IpcListener::bind(&path).unwrap();
            let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();

            let stream;
            loop {
                match listener.accept() {
                    Ok(s) => {
                        stream = s;
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept error: {e}"),
                }
            }

            let cloned = stream.try_clone().unwrap();
            // Both should be valid.
            assert!(cloned.set_nonblocking(false).is_ok());
            assert!(stream.set_nonblocking(false).is_ok());

            drop(cloned);
            drop(stream);
            drop(listener);
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn unix_cleanup_removes_socket() {
            let path = temp_socket_path();
            let (listener, pb) = IpcListener::bind(&path).unwrap();
            assert!(pb.exists());
            drop(listener);
            cleanup_ipc_endpoint(&pb);
            assert!(!pb.exists());
        }

        #[test]
        fn unix_prepare_next_is_noop() {
            let path = temp_socket_path();
            let (listener, _) = IpcListener::bind(&path).unwrap();
            // Should not panic or error.
            listener.prepare_next();
            drop(listener);
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn unix_stream_set_read_timeout() {
            let path = temp_socket_path();
            let (listener, _) = IpcListener::bind(&path).unwrap();
            let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();

            let stream;
            loop {
                match listener.accept() {
                    Ok(s) => {
                        stream = s;
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept error: {e}"),
                }
            }

            // Set and clear timeout without error.
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream.set_read_timeout(None).unwrap();

            drop(stream);
            drop(listener);
            let _ = std::fs::remove_file(&path);
        }
    }

    // ── Windows transport selection tests ────────────────────

    #[test]
    fn socket_path_flag_accepts_pipe_format() {
        // Verifies --socket-path with \\.\pipe\ prefix is detected as pipe.
        let path = r"\\.\pipe\bolt-daemon";
        assert!(is_windows_pipe_path(path));
    }

    #[test]
    fn socket_path_flag_rejects_unix_as_pipe() {
        let path = "/var/run/bolt-daemon.sock";
        assert!(!is_windows_pipe_path(path));
    }
}
