//! "This computer": a control server the GUI starts itself.
//!
//! The GUI runs the `ferotrx` next to its own executable (or the one on
//! PATH) as `ferotrx serve -l 127.0.0.1:0` with a token made up for this
//! session, so no other user or program on the machine can drive it. The
//! session's files live in a folder of their own under the temporary
//! directory:
//!
//! * `tokens.toml`: the token, as its SHA-256 only;
//! * `port`: the address the server listens on, written by the server
//!   (`--port-file`);
//! * `server.log`: what the server prints, and its audit log.
//!
//! The server stops when the GUI removes the port file (Disconnect), when the
//! GUI ends (`--parent`), and when the GUI kills it.
//!
//! On Windows, when Npcap was installed for administrators only, the server
//! starts elevated (a UAC prompt) so it can send; on Linux and macOS,
//! [`privilege_hint`] says what to do instead.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The name the GUI shows for a server it starts itself.
pub const LOCAL_NAME: &str = "This computer";

/// A running server of the GUI's own.
pub struct LocalServer {
    process: Process,
    /// The session's folder (see the module documentation).
    pub dir: PathBuf,
    pub port_file: PathBuf,
    pub log: PathBuf,
    /// The secret to log in with.
    pub token: String,
    pub elevated: bool,
    /// What to do so it may send, when it may not ([`privilege_hint`]).
    pub hint: Option<String>,
}

enum Process {
    Child(Child),
    #[cfg(windows)]
    Elevated(elevate::Handle),
    Gone,
}

/// The `ferotrx` to start: next to this program, else on PATH.
pub fn find_server() -> Option<PathBuf> {
    let name = format!("ferotrx{}", std::env::consts::EXE_SUFFIX);
    let beside = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(&name)))
        .filter(|p| p.is_file());
    beside.or_else(|| {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|d| d.join(&name))
                .find(|p| p.is_file())
        })
    })
}

/// The folders a local server lets the GUI use when none are set: the
/// home folder, the user's folders of Settings, and the installed examples (Windows installs them next to
/// the programs).
pub fn default_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .filter(|p| p.is_dir());
    v.extend(home);
    // The user's folders (Settings), when they are not in the home folder
    // already (another drive, say).
    let s = crate::settings::Settings::load();
    for f in [&s.profiles, &s.captures, &s.reports] {
        let p = PathBuf::from(f.trim());
        if !f.trim().is_empty() && p.is_dir() && !v.iter().any(|d| p.starts_with(d)) {
            v.push(p);
        }
    }
    if let Some(ex) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("examples")))
        .filter(|p| p.is_dir())
    {
        v.push(ex);
    }
    v
}

/// Folders typed in the server form: one per line, or separated by `;`.
pub fn parse_folders(text: &str) -> Vec<PathBuf> {
    text.split(['\n', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// A secret of 32 random bytes, as hex.
fn new_token() -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "no random numbers for the token".to_string())?;
    Ok(hex(&b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The tokens file for `token`: its SHA-256 only, so the file gives
/// nothing away.
pub fn tokens_toml(token: &str) -> String {
    let sum = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    format!(
        "[[token]]\nname = \"gui\"\nrole = \"operator\"\nsha256 = \"{}\"\n",
        hex(sum.as_ref())
    )
}

/// The `serve` arguments of a local server.
pub fn serve_args(dir: &Path, folders: &[PathBuf]) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "serve".into(),
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--tokens".into(),
        dir.join("tokens.toml").display().to_string(),
        "--port-file".into(),
        dir.join("port").display().to_string(),
        "--parent".into(),
        std::process::id().to_string(),
    ];
    for f in folders {
        a.push("--data-dir".into());
        a.push(f.display().to_string());
    }
    a
}

impl LocalServer {
    /// Starts a server that lets the GUI use `folders` (the defaults when
    /// empty). Returns at once; the server writes its port file when it
    /// listens ([`wait_for_address`]).
    pub fn start(folders: &[PathBuf]) -> Result<LocalServer, String> {
        let exe = find_server().ok_or_else(|| {
            format!(
                "ferotrx{} not found next to the GUI or on PATH",
                std::env::consts::EXE_SUFFIX
            )
        })?;
        Self::start_with(&exe, folders)
    }

    /// [`start`](Self::start) with this `ferotrx` program.
    pub fn start_with(exe: &Path, folders: &[PathBuf]) -> Result<LocalServer, String> {
        let token = new_token()?;
        let dir = session_dir()?;
        std::fs::write(dir.join("tokens.toml"), tokens_toml(&token))
            .map_err(|e| format!("cannot write the token file: {e}"))?;
        let folders = if folders.is_empty() {
            default_folders()
        } else {
            folders.to_vec()
        };
        #[cfg_attr(not(windows), allow(unused_mut))]
        let mut args = serve_args(&dir, &folders);
        let log = dir.join("server.log");
        let elevated = needs_elevation();
        let process = if elevated {
            #[cfg(windows)]
            {
                // Nothing to redirect standard error to: log the audit trail.
                args.push("--audit-log".into());
                args.push(log.display().to_string());
                Process::Elevated(elevate::run(exe, &args)?)
            }
            #[cfg(not(windows))]
            unreachable!("only Windows elevates")
        } else {
            let out = std::fs::File::create(&log)
                .map_err(|e| format!("cannot write {}: {e}", log.display()))?;
            let mut cmd = Command::new(exe);
            cmd.args(&args)
                .current_dir(&dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(out);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                // No console window for the server.
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            Process::Child(
                cmd.spawn()
                    .map_err(|e| format!("cannot start {}: {e}", exe.display()))?,
            )
        };
        Ok(LocalServer {
            process,
            port_file: dir.join("port"),
            log,
            dir,
            token,
            elevated,
            hint: privilege_hint(),
        })
    }

    /// Why the server ended, if it did: its exit status and the last lines
    /// it printed.
    pub fn ended(&mut self) -> Option<String> {
        let status = match &mut self.process {
            Process::Child(c) => match c.try_wait() {
                Ok(Some(s)) => s.to_string(),
                _ => return None,
            },
            #[cfg(windows)]
            Process::Elevated(h) => format!("exit code {}", h.exit_code()?),
            Process::Gone => return None,
        };
        self.process = Process::Gone;
        let tail = std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .rev()
            .filter(|l| !l.trim().is_empty())
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("; ");
        Some(if tail.is_empty() {
            format!("the local server ended ({status})")
        } else {
            format!("the local server ended ({status}): {tail}")
        })
    }

    /// Stops the server: it sees its port file go, and is killed besides.
    pub fn stop(&mut self) {
        let _ = std::fs::remove_file(&self.port_file);
        match std::mem::replace(&mut self.process, Process::Gone) {
            Process::Child(mut c) => {
                // Give it a moment to stop its runs, then make sure.
                let until = Instant::now() + Duration::from_millis(1500);
                while Instant::now() < until {
                    if let Ok(Some(_)) = c.try_wait() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = c.kill();
                let _ = c.wait();
            }
            #[cfg(windows)]
            Process::Elevated(h) => h.wait(Duration::from_millis(1500)),
            Process::Gone => {}
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Waits for the server's port file and reads the address in it.
pub fn wait_for_address(port_file: &Path, timeout: Duration) -> Result<String, String> {
    let until = Instant::now() + timeout;
    loop {
        if let Ok(t) = std::fs::read_to_string(port_file) {
            let a = t.trim();
            if !a.is_empty() {
                return Ok(a.to_string());
            }
        }
        if Instant::now() > until {
            return Err("the local server did not start listening".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn session_dir() -> Result<PathBuf, String> {
    sweep_old_sessions();
    let tag = &new_token()?[..8];
    let dir = std::env::temp_dir().join(format!("ferotrx-gui-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Removes the session folders of GUIs that ended without cleaning up.
fn sweep_old_sessions() {
    let Ok(dir) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for e in dir.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let pid = name
            .strip_prefix("ferotrx-gui-")
            .and_then(|r| r.split_once('-'))
            .and_then(|(p, _)| p.parse::<u32>().ok());
        if let Some(pid) = pid {
            if pid != std::process::id() && !process_alive(pid) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: signal 0 only checks that the process exists.
        let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        ferotrx_io::windows::process_alive(pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        true
    }
}

/// True when the server must run elevated to send: Windows, Npcap for
/// administrators only, and the GUI itself not elevated.
pub fn needs_elevation() -> bool {
    #[cfg(windows)]
    {
        ferotrx_io::windows::npcap_admin_only() && !ferotrx_io::windows::is_elevated()
    }
    #[cfg(not(windows))]
    false
}

/// What to do so a local server may send on network interfaces, when it
/// may not: Linux and macOS need root or capabilities.
pub fn privilege_hint() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return None;
        }
        let exe = find_server()?;
        if has_file_caps(&exe) {
            return None;
        }
        Some(format!(
            "To send on interfaces, give the server the rights once: sudo setcap cap_net_raw,cap_net_admin+eip {}",
            exe.display()
        ))
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return None;
        }
        let readable = std::fs::File::open("/dev/bpf0").is_ok()
            || std::fs::OpenOptions::new()
                .read(true)
                .open("/dev/bpf1")
                .is_ok();
        (!readable).then(|| {
            "To send on interfaces, give your user the BPF devices (Wireshark's ChmodBPF does), or run ferotrx serve with sudo".to_string()
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

/// Has the file capabilities set (`setcap`)?
#[cfg(target_os = "linux")]
fn has_file_caps(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(p) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let name = c"security.capability";
    // SAFETY: NUL-terminated strings; a null buffer asks for the size only.
    let n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    n > 0
}

#[cfg(windows)]
mod elevate {
    //! Starting the server as administrator, with Windows' UAC prompt.
    use std::path::Path;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    pub struct Handle(HANDLE);

    // SAFETY: a process handle may be used from any thread.
    unsafe impl Send for Handle {}

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// One command line argument, quoted the way programs split them.
    pub fn quote(a: &str) -> String {
        if !a.is_empty() && !a.contains([' ', '\t', '"']) {
            return a.to_string();
        }
        let mut out = String::from("\"");
        let mut slashes = 0;
        for c in a.chars() {
            match c {
                '\\' => slashes += 1,
                '"' => {
                    out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
                    out.push('"');
                    slashes = 0;
                }
                c => {
                    out.extend(std::iter::repeat_n('\\', slashes));
                    out.push(c);
                    slashes = 0;
                }
            }
        }
        out.extend(std::iter::repeat_n('\\', slashes * 2));
        out.push('"');
        out
    }

    pub fn run(exe: &Path, args: &[String]) -> Result<Handle, String> {
        let file = wide(&exe.display().to_string());
        let params = wide(&args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" "));
        let verb = wide("runas");
        // SAFETY: zeroed is a valid SHELLEXECUTEINFOW; the strings outlive the call.
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE;
        // SAFETY: `info` is filled in as the call expects.
        if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(1223) {
                "the server needs administrator rights to send (Npcap is for administrators only), and the prompt was declined".into()
            } else {
                format!("cannot start the server as administrator: {e}")
            });
        }
        Ok(Handle(info.hProcess))
    }

    impl Handle {
        /// The exit code, once the process ended.
        pub fn exit_code(&self) -> Option<u32> {
            // SAFETY: our process handle.
            unsafe {
                if WaitForSingleObject(self.0, 0) == WAIT_TIMEOUT {
                    return None;
                }
                let mut code = 0u32;
                (GetExitCodeProcess(self.0, &mut code) != 0).then_some(code)
            }
        }

        /// Waits up to `t` for the process to end, then ends it if Windows
        /// lets us (an elevated process may refuse).
        pub fn wait(self, t: Duration) {
            // SAFETY: our process handle.
            unsafe {
                if WaitForSingleObject(self.0, t.as_millis() as u32) == WAIT_TIMEOUT {
                    TerminateProcess(self.0, 1);
                }
            }
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: our process handle, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn arguments_are_quoted() {
            assert_eq!(super::quote("serve"), "serve");
            assert_eq!(super::quote("C:\\Users\\A B\\x"), "\"C:\\Users\\A B\\x\"");
            assert_eq!(super::quote("C:\\A B\\"), "\"C:\\A B\\\\\"");
            assert_eq!(super::quote("a\"b"), "\"a\\\"b\"");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_split_on_lines_and_semicolons() {
        assert_eq!(
            parse_folders("C:\\data; D:\\pcaps\n\n /home/x "),
            vec![
                PathBuf::from("C:\\data"),
                PathBuf::from("D:\\pcaps"),
                PathBuf::from("/home/x")
            ]
        );
    }

    #[test]
    fn the_token_file_holds_only_the_hash() {
        let t = tokens_toml("secret");
        assert!(!t.contains("\"secret\""));
        let tokens = ferotrx_ctl::Token::from_toml(&t).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(new_token().unwrap().len(), 64);
    }

    #[test]
    fn serve_arguments_watch_the_gui() {
        let a = serve_args(Path::new("/tmp/s"), &[PathBuf::from("/data")]);
        let s = a.join(" ");
        assert!(s.starts_with("serve --listen 127.0.0.1:0 --tokens "));
        assert!(s.contains(&format!("--parent {}", std::process::id())));
        assert!(s.ends_with("--data-dir /data"));
    }
}
