//! Which files the control server may read and write for its clients.

use std::io;
use std::path::{Component, Path, PathBuf};

use crate::protocol::RpcError;

/// Longest profile a client may upload as `toml` text unless set otherwise.
pub const DEFAULT_MAX_UPLOAD: usize = 1024 * 1024;

/// Where the files that clients name may be: profiles, the pcaps they play,
/// and the pcap files runs write.
///
/// [`FilePolicy::unrestricted`] (what [`Controller::new`](crate::Controller::new)
/// uses) allows any path the process can open, relative paths from the
/// current directory. With [`FilePolicy::dirs`], every path must be inside
/// one of the directories once symbolic links are followed, and relative
/// paths start from the first one. `ferotrx serve` always restricts, to the
/// directory it was started in unless `--data-dir` says otherwise.
#[derive(Clone, Debug)]
pub struct FilePolicy {
    dirs: Option<Vec<PathBuf>>,
    max_upload: usize,
}

impl Default for FilePolicy {
    fn default() -> Self {
        Self::unrestricted()
    }
}

impl FilePolicy {
    /// Any path, uploads up to [`DEFAULT_MAX_UPLOAD`] bytes.
    pub fn unrestricted() -> Self {
        Self {
            dirs: None,
            max_upload: DEFAULT_MAX_UPLOAD,
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
        })
    }

    /// Profiles sent as text may be at most `bytes` long.
    pub fn with_max_upload(mut self, bytes: usize) -> Self {
        self.max_upload = bytes;
        self
    }

    /// The directories paths must be in (canonical), or `None` for anywhere.
    pub fn allowed_dirs(&self) -> Option<&[PathBuf]> {
        self.dirs.as_deref()
    }

    pub fn max_upload(&self) -> usize {
        self.max_upload
    }

    /// A path as the client gave it, relative ones from the first directory.
    fn resolve(&self, p: &Path) -> PathBuf {
        match &self.dirs {
            Some(dirs) if p.is_relative() => dirs[0].join(p),
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
