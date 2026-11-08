//! Which files the control server may read and write for its clients.

use std::io;
use std::path::{Component, Path, PathBuf};

use std::sync::Arc;

use crate::protocol::{FileInfo, RpcError};
use crate::safe_open::{others_may_write, split_existing, Root, Write};

/// Longest profile a client may upload as `toml` text unless set otherwise.
pub const DEFAULT_MAX_UPLOAD: usize = 1024 * 1024;

/// Largest file a client may write with `file.put` unless set otherwise.
pub const DEFAULT_MAX_FILE: u64 = 256 * 1024 * 1024;

/// Where the files that clients name may be: profiles, the pcaps they play,
/// and the pcap files runs write.
///
/// [`FilePolicy::none`] (what [`Controller::new`](crate::Controller::new)
/// and `FilePolicy::default()` use) allows no paths at all: clients can still
/// send profiles as text, but not name files. With [`FilePolicy::dirs`], every
/// path must be inside one of the directories once symbolic links are
/// followed, and relative paths start from the first one.
/// [`FilePolicy::unrestricted`] allows any path the process can open,
/// relative paths from the current directory; a [`Server`](crate::Server)
/// refuses to listen beyond loopback with it unless
/// [`ServerConfig::unrestricted_files`](crate::ServerConfig::unrestricted_files)
/// says so. `ferotrx serve` always restricts, to the directory it was started
/// in unless `--data-dir` says otherwise.
#[derive(Clone, Debug)]
pub struct FilePolicy {
    dirs: Option<Vec<PathBuf>>,
    /// The data directories, held open, in the order of `dirs`.
    roots: Arc<Vec<Root>>,
    max_upload: usize,
    max_file: u64,
}

impl Default for FilePolicy {
    fn default() -> Self {
        Self::none()
    }
}

impl FilePolicy {
    /// No paths: every file a client names is refused. Profiles sent as
    /// text still work as long as they name no files.
    pub fn none() -> Self {
        Self {
            dirs: Some(Vec::new()),
            roots: Arc::default(),
            max_upload: DEFAULT_MAX_UPLOAD,
            max_file: DEFAULT_MAX_FILE,
        }
    }

    /// Any path the process can open, uploads up to [`DEFAULT_MAX_UPLOAD`]
    /// bytes. Give it only to a server on loopback, or one whose operators
    /// may read and write anything the process can.
    pub fn unrestricted() -> Self {
        Self {
            dirs: None,
            roots: Arc::default(),
            max_upload: DEFAULT_MAX_UPLOAD,
            max_file: DEFAULT_MAX_FILE,
        }
    }

    /// Only paths inside `dirs`, which must exist.
    pub fn dirs<P: AsRef<Path>>(dirs: impl IntoIterator<Item = P>) -> io::Result<Self> {
        let mut list = Vec::new();
        let mut roots = Vec::new();
        for d in dirs {
            let d = d.as_ref();
            let c = d.canonicalize().map_err(|e| {
                io::Error::new(e.kind(), format!("data directory {}: {e}", d.display()))
            })?;
            if !c.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("data directory {} is not a directory", d.display()),
                ));
            }
            roots.push(Root::open(&c).map_err(|e| {
                io::Error::new(e.kind(), format!("data directory {}: {e}", d.display()))
            })?);
            list.push(c);
        }
        if list.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no data directories given",
            ));
        }
        Ok(Self {
            dirs: Some(list),
            roots: Arc::new(roots),
            max_upload: DEFAULT_MAX_UPLOAD,
            max_file: DEFAULT_MAX_FILE,
        })
    }

    /// Profiles sent as text may be at most `bytes` long.
    pub fn with_max_upload(mut self, bytes: usize) -> Self {
        self.max_upload = bytes;
        self
    }

    /// The directories paths must be in (canonical), or `None` for anywhere.
    /// Empty for [`FilePolicy::none`].
    pub fn allowed_dirs(&self) -> Option<&[PathBuf]> {
        self.dirs.as_deref()
    }

    /// True for [`FilePolicy::unrestricted`].
    pub fn is_unrestricted(&self) -> bool {
        self.dirs.is_none()
    }

    /// True for [`FilePolicy::none`].
    pub fn is_none(&self) -> bool {
        self.dirs.as_ref().is_some_and(Vec::is_empty)
    }

    fn no_files(&self, p: &Path) -> Result<(), RpcError> {
        if self.is_none() {
            return Err(RpcError::forbidden(format!(
                "{}: this server has no data directories and takes no file names",
                p.display()
            )));
        }
        Ok(())
    }

    pub fn max_upload(&self) -> usize {
        self.max_upload
    }

    /// Files written with `file.put` may be at most `bytes` long; 0 refuses
    /// them.
    pub fn with_max_file(mut self, bytes: u64) -> Self {
        self.max_file = bytes;
        self
    }

    pub fn max_file(&self) -> u64 {
        self.max_file
    }

    /// A path a client may write with `file.put`: relative, without `..`,
    /// inside the first data directory (or the current one).
    fn check_put_path(&self, p: &Path) -> Result<(), RpcError> {
        let plain =
            !p.as_os_str().is_empty() && p.components().all(|c| matches!(c, Component::Normal(_)));
        if !plain {
            return Err(RpcError::invalid_params(format!(
                "{}: give a relative path without '..'",
                p.display()
            )));
        }
        Ok(())
    }

    /// Where `p` lands: the data directory it is in, the path below it,
    /// and the whole path, with symbolic links resolved as far as the path
    /// exists. A path outside every data directory is refused.
    fn place(&self, p: &Path) -> Result<(&Root, PathBuf, PathBuf), RpcError> {
        let dirs = self.dirs.as_deref().unwrap_or_default();
        let path = self.resolve(p);
        let (base, rest) = split_existing(&path);
        let mut full = base
            .canonicalize()
            .map_err(|e| RpcError::failed(format!("{}: {e}", p.display())))?;
        for n in rest {
            full.push(n);
        }
        let best = dirs
            .iter()
            .enumerate()
            .filter(|(_, d)| full.starts_with(d))
            .max_by_key(|(_, d)| d.as_os_str().len());
        let Some((i, dir)) = best else {
            return Err(self.outside(p));
        };
        let rel = full
            .strip_prefix(dir)
            .unwrap_or(Path::new(""))
            .to_path_buf();
        Ok((&self.roots[i], rel, full))
    }

    /// An error from opening `p` inside a data directory: a link or a file
    /// of the wrong kind is refused, anything else failed.
    fn open_error(p: &Path, verb: &str, e: io::Error) -> RpcError {
        if e.kind() == io::ErrorKind::PermissionDenied && e.raw_os_error().is_none() {
            RpcError::forbidden(format!("{}: {e}", p.display()))
        } else {
            RpcError::failed(format!("cannot {verb} {}: {e}", p.display()))
        }
    }

    /// Makes the folders on the way to a relative path without `..` in the
    /// first data directory, as `file.put` and captures that write files
    /// need. Other paths are left as they are. The path is checked first,
    /// and the folders are made one by one without following links, so a
    /// link inside a data directory cannot make folders outside it.
    pub fn make_folders(&self, p: &Path) -> Result<(), RpcError> {
        let plain =
            !p.as_os_str().is_empty() && p.components().all(|c| matches!(c, Component::Normal(_)));
        if !plain || self.is_none() {
            return Ok(());
        }
        if self.dirs.is_none() {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RpcError::failed(format!("cannot write {}: {e}", p.display())))?;
            }
            return Ok(());
        }
        let (root, rel, _) = self.place(p)?;
        match rel.parent() {
            Some(parent) => root
                .make_dirs(parent)
                .map_err(|e| Self::open_error(p, "write", e)),
            None => Ok(()),
        }
    }

    /// Opens a file to write: inside a data directory without following
    /// links, folders made on the way for a relative path.
    fn create(&self, p: &Path, how: Write) -> Result<std::fs::File, RpcError> {
        if self.dirs.is_none() {
            if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RpcError::failed(format!("cannot write {}: {e}", p.display())))?;
            }
            let mut o = std::fs::OpenOptions::new();
            o.create(true);
            match how {
                Write::Truncate => o.write(true).truncate(true),
                Write::Append => o.append(true),
            };
            return o
                .open(p)
                .map_err(|e| RpcError::failed(format!("cannot write {}: {e}", p.display())));
        }
        let (root, rel, _) = self.place(p)?;
        root.write(&rel, how, true)
            .map_err(|e| Self::open_error(p, "write", e))
    }

    /// Writes a piece of a file (`file.put`): offset 0 starts it afresh,
    /// any other offset must be its length so far. Returns the file as it
    /// is now.
    pub fn put(&self, p: &Path, data: &[u8], offset: u64) -> Result<FileInfo, RpcError> {
        use std::io::Write as _;
        if self.max_file == 0 {
            return Err(RpcError::forbidden(
                "this server takes no files (--max-file 0)",
            ));
        }
        let end = offset.saturating_add(data.len() as u64);
        if end > self.max_file {
            return Err(RpcError::invalid_params(format!(
                "{} would be {end} bytes; this server takes files of at most {}",
                p.display(),
                self.max_file
            )));
        }
        self.no_files(p)?;
        // The path is checked before any folder is made for it.
        self.check_put_path(p)?;
        let fail = |e: io::Error| RpcError::failed(format!("cannot write {}: {e}", p.display()));
        let mut file = if offset == 0 {
            self.create(p, Write::Truncate)?
        } else {
            let file = self.create(p, Write::Append)?;
            let len = file.metadata().map(|m| m.len()).map_err(fail)?;
            if len != offset {
                return Err(RpcError::invalid_params(format!(
                    "{} is {len} bytes long, not {offset}: send the pieces in order",
                    p.display()
                )));
            }
            file
        };
        file.write_all(data).map_err(fail)?;
        drop(file);
        self.stat(p)
    }

    /// A file's size and SHA-256 (`file.stat`); `exists` is false for one
    /// that is not there. The file is hashed as it is read, a piece at a
    /// time.
    pub fn stat(&self, p: &Path) -> Result<FileInfo, RpcError> {
        use std::io::Read;
        let missing = FileInfo {
            path: p.to_path_buf(),
            ..Default::default()
        };
        let mut file = match self.open(p) {
            Ok((f, _)) => f,
            Err(e) if e.code == RpcError::FORBIDDEN => return Err(e),
            Err(_) => return Ok(missing),
        };
        let fail = |e: io::Error| RpcError::failed(format!("cannot read {}: {e}", p.display()));
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buf = vec![0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(fail(e)),
            };
            hash.update(&buf[..n]);
            size += n as u64;
        }
        Ok(FileInfo {
            path: p.to_path_buf(),
            exists: true,
            size,
            sha256: Some(hex(hash.finish().as_ref())),
        })
    }

    /// A piece of a file (`file.get`): at most `length` bytes from
    /// `offset`, and the file's size.
    pub fn get(&self, p: &Path, offset: u64, length: u64) -> Result<(Vec<u8>, u64), RpcError> {
        use std::io::{Read, Seek, SeekFrom};
        let (mut file, _) = self.open(p)?;
        let fail = |e: io::Error| RpcError::failed(format!("cannot read {}: {e}", p.display()));
        let size = file.metadata().map_err(fail)?.len();
        if offset > size {
            return Err(RpcError::invalid_params(format!(
                "{} is {size} bytes long; offset {offset} is beyond its end",
                p.display()
            )));
        }
        file.seek(SeekFrom::Start(offset)).map_err(fail)?;
        let want = length.min(size - offset);
        let mut data = Vec::with_capacity(want as usize);
        file.take(want).read_to_end(&mut data).map_err(fail)?;
        Ok((data, size))
    }

    /// A path as the client gave it, relative ones from the first directory.
    fn resolve(&self, p: &Path) -> PathBuf {
        match &self.dirs {
            Some(dirs) if p.is_relative() && !dirs.is_empty() => dirs[0].join(p),
            _ => p.to_path_buf(),
        }
    }

    fn outside(&self, p: &Path) -> RpcError {
        let dirs = self
            .dirs
            .iter()
            .flatten()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        RpcError::forbidden(format!(
            "{} is outside the server's data directories ({dirs})",
            p.display()
        ))
    }

    /// Opens a file (or with `dirs` a folder) inside a data directory
    /// without following links that were not there when the path was
    /// resolved, and returns it with its canonical path.
    fn open_inside(&self, p: &Path, dirs: bool) -> Result<(std::fs::File, PathBuf), RpcError> {
        self.no_files(p)?;
        let (root, rel, full) = self.place(p)?;
        if !full.exists() {
            // `place` keeps the names that are not there yet.
            let e = io::Error::from(io::ErrorKind::NotFound);
            return Err(RpcError::failed(format!(
                "cannot read {}: {e}",
                p.display()
            )));
        }
        let f = root
            .read(&rel, dirs)
            .map_err(|e| Self::open_error(p, "read", e))?;
        Ok((f, full))
    }

    /// Opens a file a client names to read, and returns it with the path
    /// it was found at. Inside data directories nothing is followed that
    /// was not a link when the path was checked, and only regular files
    /// open.
    pub fn open(&self, p: &Path) -> Result<(std::fs::File, PathBuf), RpcError> {
        if self.dirs.is_none() {
            let fail = |e: io::Error| RpcError::failed(format!("cannot read {}: {e}", p.display()));
            let f = std::fs::File::open(p).map_err(fail)?;
            if !f.metadata().map_err(fail)?.is_file() {
                return Err(RpcError::invalid_params(format!(
                    "{} is not a file",
                    p.display()
                )));
            }
            return Ok((f, p.to_path_buf()));
        }
        self.open_inside(p, false)
    }

    /// Reads a text file a client names (a profile), opened as
    /// [`open`](FilePolicy::open) does; returns the text and its path.
    pub fn read_text(&self, p: &Path) -> Result<(String, PathBuf), RpcError> {
        use std::io::Read;
        let (mut f, path) = self.open(p)?;
        let mut text = String::new();
        f.read_to_string(&mut text)
            .map_err(|e| RpcError::failed(format!("cannot read {}: {e}", p.display())))?;
        Ok((text, path))
    }

    /// Checks a file (or folder) to read and returns the path to open it
    /// by. Inside data directories the file is opened once without
    /// following links, so a link put in its place after it was resolved is
    /// refused; programs that open it again by this path later (pcap
    /// readers) do not have that protection.
    pub fn readable(&self, p: &Path) -> Result<PathBuf, RpcError> {
        if self.dirs.is_none() {
            return Ok(p.to_path_buf());
        }
        self.open_inside(p, true).map(|(_, path)| path)
    }

    /// Checks a directory that relative paths in uploaded text start from
    /// (`base_dir`); `None` is the first data directory (or `.`).
    pub fn base_dir(&self, p: Option<&Path>) -> Result<PathBuf, RpcError> {
        if self.is_none() {
            // Relative paths in the text still have to pass `readable`,
            // which refuses them all.
            return match p {
                None => Ok(PathBuf::from(".")),
                Some(p) => self.no_files(p).map(|_| PathBuf::new()),
            };
        }
        let p = p.unwrap_or(Path::new("."));
        if self.dirs.is_none() {
            return Ok(p.to_path_buf());
        }
        let c = self.readable(p)?;
        if !c.is_dir() {
            return Err(RpcError::invalid_params(format!(
                "base_dir {} is not a directory",
                p.display()
            )));
        }
        Ok(c)
    }

    /// Checks a file to write (it need not exist) and returns the path to
    /// create it by: inside a data directory, its folders reached without
    /// links, and if it is there a regular file.
    pub fn writable(&self, p: &Path) -> Result<PathBuf, RpcError> {
        if self.dirs.is_none() {
            return Ok(p.to_path_buf());
        }
        self.no_files(p)?;
        let path = self.resolve(p);
        if !matches!(path.components().next_back(), Some(Component::Normal(_))) {
            return Err(RpcError::invalid_params("output file has no file name"));
        }
        let (root, rel, full) = self.place(p)?;
        if full.is_dir() {
            return Err(self.outside(p));
        }
        root.check_write(&rel)
            .map_err(|e| Self::open_error(p, "write", e))?;
        Ok(full)
    }

    /// Data directories that users other than their owner may write in,
    /// where they could swap files under the server (Unix).
    pub fn shared_dirs(&self) -> Vec<PathBuf> {
        self.dirs
            .iter()
            .flatten()
            .filter(|d| others_may_write(d))
            .cloned()
            .collect()
    }

    /// Checks the size of a profile sent as text.
    pub fn upload(&self, text: &str) -> Result<(), RpcError> {
        if text.len() > self.max_upload {
            return Err(RpcError::invalid_params(format!(
                "the profile is {} bytes; this server takes at most {}",
                text.len(),
                self.max_upload
            )));
        }
        Ok(())
    }
}

/// SHA-256 of `data`, in lower-case hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ferotrx-files-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("data/sub")).unwrap();
        std::fs::write(d.join("data/a.toml"), "").unwrap();
        std::fs::write(d.join("secret"), "").unwrap();
        d
    }

    #[test]
    fn paths_must_stay_inside() {
        let d = tmp("inside");
        let p = FilePolicy::dirs([d.join("data")]).unwrap();
        assert!(p.readable(Path::new("a.toml")).is_ok());
        assert!(p.readable(&d.join("data/a.toml")).is_ok());
        let e = p.readable(Path::new("../secret")).unwrap_err();
        assert_eq!(e.code, RpcError::FORBIDDEN);
        assert_eq!(
            p.readable(&d.join("secret")).unwrap_err().code,
            RpcError::FORBIDDEN
        );
        assert_eq!(
            p.readable(Path::new("missing")).unwrap_err().code,
            RpcError::FAILED
        );
        assert!(p.writable(Path::new("sub/out.pcap")).is_ok());
        assert_eq!(
            p.writable(Path::new("../out.pcap")).unwrap_err().code,
            RpcError::FORBIDDEN
        );
        assert_eq!(
            p.writable(Path::new("sub")).unwrap_err().code,
            RpcError::FORBIDDEN
        );
        assert!(p.base_dir(None).unwrap().ends_with("data"));
        assert!(p.base_dir(Some(Path::new("sub"))).is_ok());
        assert_eq!(
            p.base_dir(Some(Path::new(".."))).unwrap_err().code,
            RpcError::FORBIDDEN
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_out_are_refused() {
        let d = tmp("symlink");
        std::os::unix::fs::symlink(d.join("secret"), d.join("data/link")).unwrap();
        let p = FilePolicy::dirs([d.join("data")]).unwrap();
        assert_eq!(
            p.readable(Path::new("link")).unwrap_err().code,
            RpcError::FORBIDDEN
        );
        assert_eq!(
            p.writable(Path::new("link")).unwrap_err().code,
            RpcError::FORBIDDEN
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_inside_does_not_make_folders_outside() {
        let d = tmp("mkdir");
        std::os::unix::fs::symlink(&d, d.join("data/out")).unwrap();
        let p = FilePolicy::dirs([d.join("data")]).unwrap();
        let e = p.put(Path::new("out/made/x.pcap"), b"x", 0).unwrap_err();
        assert_eq!(e.code, RpcError::FORBIDDEN, "{}", e.message);
        assert!(!d.join("made").exists(), "a folder was made outside");
        assert!(p.make_folders(Path::new("out/made/x.pcap")).is_err());
        assert!(!d.join("made").exists());
        // Folders inside are made one by one.
        p.put(Path::new("a/b/c.pcap"), b"abc", 0).unwrap();
        assert_eq!(std::fs::read(d.join("data/a/b/c.pcap")).unwrap(), b"abc");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn writes_do_not_follow_links_or_hard_links() {
        let d = tmp("write");
        std::os::unix::fs::symlink(d.join("secret"), d.join("data/to-secret")).unwrap();
        std::fs::hard_link(d.join("secret"), d.join("data/hard")).unwrap();
        let p = FilePolicy::dirs([d.join("data")]).unwrap();
        assert!(p.put(Path::new("to-secret"), b"x", 0).is_err());
        assert!(p.put(Path::new("hard"), b"x", 0).is_err());
        assert_eq!(std::fs::read(d.join("secret")).unwrap(), b"");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_swapped_for_a_link_is_never_read() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let d = tmp("race");
        std::fs::write(d.join("secret"), "SECRET").unwrap();
        std::fs::write(d.join("data/plain"), "plain").unwrap();
        let p = FilePolicy::dirs([d.join("data")]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let swapper = {
            let (d, stop) = (d.clone(), stop.clone());
            std::thread::spawn(move || {
                let (file, link) = (d.join("data/f"), d.join("data/f.link"));
                let _ = std::os::unix::fs::symlink(d.join("secret"), &link);
                let mut flips = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::fs::copy(d.join("data/plain"), d.join("data/f.new"));
                    let _ = std::fs::rename(d.join("data/f.new"), &file);
                    let _ = std::fs::remove_file(d.join("data/f.l2"));
                    let _ = std::os::unix::fs::symlink(d.join("secret"), d.join("data/f.l2"));
                    let _ = std::fs::rename(d.join("data/f.l2"), &file);
                    flips += 1;
                }
                flips
            })
        };
        let (mut read, mut refused) = (0, 0);
        let until = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while std::time::Instant::now() < until {
            match p.read_text(Path::new("f")) {
                Ok((text, _)) => {
                    assert_eq!(text, "plain", "read through a link to a file outside");
                    read += 1;
                }
                Err(_) => refused += 1,
            }
            if let Ok((data, _)) = p.get(Path::new("f"), 0, 100) {
                assert_eq!(data, b"plain");
            }
            if let Ok(info) = p.stat(Path::new("f")) {
                assert!(!info.exists || info.size == 5);
            }
        }
        stop.store(true, Ordering::Relaxed);
        let flips = swapper.join().unwrap();
        assert!(
            flips > 10 && refused > 0,
            "{flips} swaps, {read} read, {refused} refused"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn stat_hashes_large_files_in_pieces() {
        let d = tmp("stat");
        let data: Vec<u8> = (0..3 * 1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
        std::fs::write(d.join("data/big.pcap"), &data).unwrap();
        let p = FilePolicy::dirs([d.join("data")]).unwrap();
        let info = p.stat(Path::new("big.pcap")).unwrap();
        assert!(info.exists);
        assert_eq!(info.size, data.len() as u64);
        assert_eq!(info.sha256.as_deref(), Some(sha256_hex(&data).as_str()));
        assert!(!p.stat(Path::new("none")).unwrap().exists);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn uploads_are_size_limited() {
        let p = FilePolicy::unrestricted().with_max_upload(4);
        assert!(p.upload("abcd").is_ok());
        assert_eq!(
            p.upload("abcde").unwrap_err().code,
            RpcError::INVALID_PARAMS
        );
    }
}
