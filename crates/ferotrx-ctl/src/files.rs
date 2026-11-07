//! Which files the control server may read and write for its clients.

use std::io;
use std::path::{Component, Path, PathBuf};

use crate::protocol::{FileInfo, RpcError};

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
            max_upload: DEFAULT_MAX_UPLOAD,
            max_file: DEFAULT_MAX_FILE,
        }
    }

    /// Only paths inside `dirs`, which must exist.
    pub fn dirs<P: AsRef<Path>>(dirs: impl IntoIterator<Item = P>) -> io::Result<Self> {
        let mut list = Vec::new();
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
    fn put_path(&self, p: &Path) -> Result<PathBuf, RpcError> {
        let plain =
            !p.as_os_str().is_empty() && p.components().all(|c| matches!(c, Component::Normal(_)));
        if !plain {
            return Err(RpcError::invalid_params(format!(
                "{}: give a relative path without '..'",
                p.display()
            )));
        }
        let path = self.resolve(p);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RpcError::failed(format!("cannot write {}: {e}", p.display())))?;
        }
        self.writable(p)
    }

    /// Writes a piece of a file (`file.put`): offset 0 starts it afresh,
    /// any other offset must be its length so far. Returns the file as it
    /// is now.
    pub fn put(&self, p: &Path, data: &[u8], offset: u64) -> Result<FileInfo, RpcError> {
        use std::io::Write;
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
        let path = self.put_path(p)?;
        let fail = |e: io::Error| RpcError::failed(format!("cannot write {}: {e}", p.display()));
        let mut file = if offset == 0 {
            std::fs::File::create(&path).map_err(fail)?
        } else {
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if len != offset {
                return Err(RpcError::invalid_params(format!(
                    "{} is {len} bytes long, not {offset}: send the pieces in order",
                    p.display()
                )));
            }
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .map_err(fail)?
        };
        file.write_all(data).map_err(fail)?;
        drop(file);
        self.stat(p)
    }

    /// A file's size and SHA-256 (`file.stat`); `exists` is false for one
    /// that is not there.
    pub fn stat(&self, p: &Path) -> Result<FileInfo, RpcError> {
        let missing = FileInfo {
            path: p.to_path_buf(),
            ..Default::default()
        };
        let path = match self.readable(p) {
            Ok(path) => path,
            Err(e) if e.code == RpcError::FORBIDDEN => return Err(e),
            Err(_) => return Ok(missing),
        };
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(missing),
            Err(e) => {
                return Err(RpcError::failed(format!(
                    "cannot read {}: {e}",
                    p.display()
                )))
            }
        };
        Ok(FileInfo {
            path: p.to_path_buf(),
            exists: true,
            size: data.len() as u64,
            sha256: Some(sha256_hex(&data)),
        })
    }

    /// A piece of a file (`file.get`): at most `length` bytes from
    /// `offset`, and the file's size.
    pub fn get(&self, p: &Path, offset: u64, length: u64) -> Result<(Vec<u8>, u64), RpcError> {
        use std::io::{Read, Seek, SeekFrom};
        let path = self.readable(p)?;
        let fail = |e: io::Error| RpcError::failed(format!("cannot read {}: {e}", p.display()));
        let mut file = std::fs::File::open(&path).map_err(fail)?;
        let meta = file.metadata().map_err(fail)?;
        if !meta.is_file() {
            return Err(RpcError::invalid_params(format!(
                "{} is not a file",
                p.display()
            )));
        }
        let size = meta.len();
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

    fn inside(&self, canonical: &Path) -> bool {
        match &self.dirs {
            None => true,
            Some(dirs) => dirs.iter().any(|d| canonical.starts_with(d)),
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

    /// Checks a file to read and returns the path to open it by.
    pub fn readable(&self, p: &Path) -> Result<PathBuf, RpcError> {
        if self.dirs.is_none() {
            return Ok(p.to_path_buf());
        }
        self.no_files(p)?;
        let path = self.resolve(p);
        let canonical = path
            .canonicalize()
            .map_err(|e| RpcError::failed(format!("cannot read {}: {e}", p.display())))?;
        if !self.inside(&canonical) {
            return Err(self.outside(p));
        }
        Ok(canonical)
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
    /// create it by.
    pub fn writable(&self, p: &Path) -> Result<PathBuf, RpcError> {
        if self.dirs.is_none() {
            return Ok(p.to_path_buf());
        }
        self.no_files(p)?;
        let path = self.resolve(p);
        if path.exists() {
            let c = path
                .canonicalize()
                .map_err(|e| RpcError::failed(format!("{}: {e}", p.display())))?;
            if !self.inside(&c) || c.is_dir() {
                return Err(self.outside(p));
            }
            return Ok(c);
        }
        let name = match path.components().next_back() {
            Some(Component::Normal(n)) => n.to_os_string(),
            _ => return Err(RpcError::invalid_params("output file has no file name")),
        };
        let parent = path.parent().unwrap_or(Path::new("."));
        let c = parent
            .canonicalize()
            .map_err(|e| RpcError::failed(format!("cannot write {}: {e}", p.display())))?;
        if !self.inside(&c) {
            return Err(self.outside(p));
        }
        Ok(c.join(name))
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
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
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
