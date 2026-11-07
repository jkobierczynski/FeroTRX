//! Windows: Npcap's DLLs and the names Windows gives network adapters.
//!
//! Npcap names an interface `\Device\NPF_{GUID}`; people know it as
//! "Ethernet 2". [`adapters`] asks Windows (`GetAdaptersAddresses`) for every
//! adapter's GUID, name and MAC address, so interface lists can show the
//! name and `-i "Ethernet 2"` works ([`resolve`]).
//!
//! Npcap installs `wpcap.dll` in `System32\Npcap`, which is not on the DLL
//! search path unless it was installed in WinPcap compatible mode. The
//! binaries load it late (`/DELAYLOAD:wpcap.dll`, see ferotrx-cli's build.rs),
//! and [`load_npcap`] adds that folder and loads it before the first pcap
//! call, so a missing Npcap is an error message, not a program that won't
//! start.

/// What to tell someone without Npcap.
pub const NPCAP_MISSING: &str = "Npcap is not installed (wpcap.dll not found): install it from https://npcap.com to use network interfaces; the file and null outputs work without it";

/// One network adapter as Windows names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adapter {
    /// `{GUID}`, as in Npcap's `\Device\NPF_{GUID}`.
    pub guid: String,
    /// "Ethernet 2", "Wi-Fi": the name in Windows' settings.
    pub friendly_name: String,
    pub description: String,
    /// `aa:bb:cc:dd:ee:ff`, when the adapter has one.
    pub mac: Option<String>,
}

/// Loads Npcap's `wpcap.dll` (from `System32\Npcap` or the usual search
/// path). Only the first call does the work.
#[cfg(feature = "pcap")]
pub fn load_npcap() -> Result<(), String> {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, SetDllDirectoryW};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    static LOADED: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    LOADED
        .get_or_init(|| {
            let mut buf = [0u16; 512];
            // SAFETY: the buffer and its length match.
            let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
            if n > 0 && n < buf.len() {
                let mut dir: Vec<u16> = buf[..n].to_vec();
                dir.extend("\\Npcap".encode_utf16());
                dir.push(0);
                // SAFETY: a NUL-terminated wide string. Packet.dll, which
                // wpcap.dll loads in turn, is found there too.
                unsafe { SetDllDirectoryW(dir.as_ptr()) };
            }
            let name: Vec<u16> = "wpcap.dll\0".encode_utf16().collect();
            // SAFETY: a NUL-terminated wide string; the DLL stays loaded.
            let h = unsafe { LoadLibraryW(name.as_ptr()) };
            if h.is_null() {
                Err(NPCAP_MISSING.to_string())
            } else {
                Ok(())
            }
        })
        .clone()
}

/// True when Npcap was installed with "Restrict Npcap driver's access to
/// Administrators only": then only an elevated process can send or capture.
pub fn npcap_admin_only() -> bool {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD,
    };
    let key: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\npcap\\Parameters\0"
        .encode_utf16()
        .collect();
    let name: Vec<u16> = "AdminOnly\0".encode_utf16().collect();
    let mut value: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: NUL-terminated wide strings; a DWORD buffer of `size` bytes.
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            &mut value as *mut u32 as *mut _,
            &mut size,
        )
    };
    r == 0 && value != 0
}

/// True when this process runs elevated (as administrator).
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle of this process; `token` receives a handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: a TOKEN_ELEVATION buffer of the size given.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut e as *mut TOKEN_ELEVATION as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    // SAFETY: the handle OpenProcessToken gave.
    unsafe { CloseHandle(token) };
    ok != 0 && e.TokenIsElevated != 0
}

/// True while process `pid` runs.
pub fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
    };
    // SAFETY: plain calls; the handle is closed below.
    unsafe {
        let h = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if h.is_null() {
            return false;
        }
        let r = WaitForSingleObject(h, 0);
        CloseHandle(h);
        r == WAIT_TIMEOUT
    }
}

/// Every network adapter Windows knows, with its name and MAC address.
pub fn adapters() -> Vec<Adapter> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    const AF_UNSPEC: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_INCLUDE_ALL_INTERFACES;
    let mut size: u32 = 32 * 1024;
    // u64 so the buffer is aligned for the structures written into it.
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..4 {
        buf.resize((size as usize).div_ceil(8), 0);
        // SAFETY: the buffer holds `size` bytes; Windows writes a list of
        // IP_ADAPTER_ADDRESSES_LH into it, linked by pointers inside it.
        let r = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match r {
            0 => break,
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return Vec::new(),
        }
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        // SAFETY: a node of the list Windows wrote into `buf`, alive until
        // `buf` is dropped at the end of this function.
        let a = unsafe { &*p };
        let guid = unsafe { c_str(a.AdapterName) };
        let mac = (a.PhysicalAddressLength == 6).then(|| {
            a.PhysicalAddress[..6]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        });
        out.push(Adapter {
            guid,
            friendly_name: unsafe { wide_str(a.FriendlyName) },
            description: unsafe { wide_str(a.Description) },
            mac,
        });
        p = a.Next;
    }
    out
}

/// The GUID in an Npcap device name (`\Device\NPF_{GUID}`), or the name
/// itself when it is a bare `{GUID}`.
pub fn guid_of(device: &str) -> Option<&str> {
    let g = device.rsplit_once("NPF_").map_or(device, |(_, g)| g);
    (g.starts_with('{') && g.ends_with('}')).then_some(g)
}

/// The adapter of an Npcap device name.
pub fn adapter_of<'a>(adapters: &'a [Adapter], device: &str) -> Option<&'a Adapter> {
    let g = guid_of(device)?;
    adapters.iter().find(|a| a.guid.eq_ignore_ascii_case(g))
}

/// The Npcap device for a name someone typed: a Windows adapter name
/// ("Ethernet 2", any case) or a bare `{GUID}` becomes
/// `\Device\NPF_{GUID}`; anything else is left as it is.
pub fn resolve(name: &str) -> String {
    resolve_in(&adapters(), name)
}

pub fn resolve_in(adapters: &[Adapter], name: &str) -> String {
    if name.starts_with("\\Device\\") || name.eq_ignore_ascii_case("any") {
        return name.to_string();
    }
    let hit = adapters
        .iter()
        .find(|a| a.friendly_name.eq_ignore_ascii_case(name) || a.guid.eq_ignore_ascii_case(name));
    match hit {
        Some(a) => format!("\\Device\\NPF_{}", a.guid),
        None => name.to_string(),
    }
}

/// SAFETY: `p` is null or a NUL-terminated string.
unsafe fn c_str(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    std::ffi::CStr::from_ptr(p as *const std::ffi::c_char)
        .to_string_lossy()
        .into_owned()
}

/// SAFETY: `p` is null or a NUL-terminated wide string.
unsafe fn wide_str(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> Vec<Adapter> {
        vec![Adapter {
            guid: "{1234ABCD-0000-1111-2222-333344445555}".into(),
            friendly_name: "Ethernet 2".into(),
            description: "Realtek Gaming 5GbE Family Controller".into(),
            mac: Some("00:11:22:33:44:55".into()),
        }]
    }

    #[test]
    fn windows_names_become_npcap_devices() {
        let a = lab();
        let dev = "\\Device\\NPF_{1234ABCD-0000-1111-2222-333344445555}";
        assert_eq!(resolve_in(&a, "Ethernet 2"), dev);
        assert_eq!(resolve_in(&a, "ethernet 2"), dev);
        assert_eq!(
            resolve_in(&a, "{1234abcd-0000-1111-2222-333344445555}"),
            dev
        );
        assert_eq!(resolve_in(&a, dev), dev);
        assert_eq!(resolve_in(&a, "Wi-Fi"), "Wi-Fi");
        assert_eq!(adapter_of(&a, dev).unwrap().friendly_name, "Ethernet 2");
        assert_eq!(guid_of("\\Device\\NPF_Loopback"), None);
    }

    #[test]
    fn this_process_is_alive() {
        assert!(process_alive(std::process::id()));
        let _ = is_elevated();
        let _ = npcap_admin_only();
    }

    #[test]
    fn this_computer_has_adapters() {
        // Every Windows machine has at least the loopback pseudo adapter.
        assert!(!adapters().is_empty());
    }
}
