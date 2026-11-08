//! Opening files inside a data directory without following symbolic links
//! that appear after the path was checked.
//!
//! A [`Root`] is a data directory, opened once. Paths below it are walked
//! one component at a time: on Unix with `openat` and `O_NOFOLLOW` from the
//! directory's own descriptor, so a component swapped for a symbolic link
//! between the check and the open makes the open fail instead of leaving
//! the directory; on Windows each component is checked not to be a reparse
//! point (symbolic link, junction) and the file is opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT`, so a reparse point is opened itself,
//! seen and refused.

use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

/// What [`Root::write`] does with a file that is there already.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Write {
    /// Empties it (or creates it).
    Truncate,
    /// Writes at its end (or creates it).
    Append,
}

fn refused(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what.to_string())
}

/// The names of a relative path, every one a plain name.
fn names(rel: &Path) -> io::Result<Vec<&std::ffi::OsStr>> {
    rel.components()
        .map(|c| match c {
            Component::Normal(n) => Ok(n),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a plain relative path", rel.display()),
            )),
        })
        .collect()
}

pub(crate) use imp::Root;

#[cfg(unix)]
mod imp {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    /// A data directory, held open.
    pub(crate) struct Root {
        dir: File,
    }

    impl std::fmt::Debug for Root {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Root")
                .field("fd", &self.dir.as_raw_fd())
                .finish()
        }
    }

    fn cstr(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL byte in the path"))
    }

    /// `openat` that never follows a symbolic link in `name`.
    fn openat(dir: &File, name: &OsStr, flags: libc::c_int) -> io::Result<File> {
        let c = cstr(name)?;
        let flags = flags | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        // SAFETY: `c` is a valid C string and `dir` an open descriptor; the
        // descriptor returned is new and owned by the File.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, 0o644 as libc::c_uint) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            // ELOOP (Linux, macOS) or EMLINK (FreeBSD): the name is a link.
            if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK)) {
                return Err(refused("a symbolic link on the way"));
            }
            return Err(e);
        }
        // SAFETY: fd is a fresh descriptor nobody else owns.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn mkdirat(dir: &File, name: &OsStr) -> io::Result<()> {
        let c = cstr(name)?;
        // SAFETY: as for openat.
        if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
        Ok(())
    }

    fn subdir(dir: &File, name: &OsStr, make: bool) -> io::Result<File> {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY;
        match openat(dir, name, flags) {
            Err(e) if make && e.kind() == io::ErrorKind::NotFound => {
                mkdirat(dir, name)?;
                openat(dir, name, flags)
            }
            // A symbolic link with O_DIRECTORY gives ENOTDIR on some systems.
            Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                Err(refused("not a directory, or a symbolic link on the way"))
            }
            r => r,
        }
    }

    impl Root {
        /// Opens a data directory (a canonical path, so no links in it).
        pub(crate) fn open(dir: &Path) -> io::Result<Root> {
            let dir = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(dir)?;
            Ok(Root { dir })
        }

        /// The directory `rel` names, made on the way with `make`.
        fn walk(&self, rel: &[&OsStr], make: bool) -> io::Result<File> {
            let mut dir = self.dir.try_clone()?;
            for n in rel {
                dir = subdir(&dir, n, make)?;
            }
            Ok(dir)
        }

        /// Opens `rel` to read: a regular file, or with `dirs` also a
        /// directory; anything else (a device, a pipe, a socket) is refused.
        pub(crate) fn read(&self, rel: &Path, dirs: bool) -> io::Result<File> {
            let n = names(rel)?;
            let Some((last, parents)) = n.split_last() else {
                return if dirs {
                    self.dir.try_clone()
                } else {
                    Err(refused("a directory, not a file"))
                };
            };
            let dir = self.walk(parents, false)?;
            // O_NONBLOCK: opening a pipe must not wait for a writer.
            let f = openat(&dir, last, libc::O_RDONLY | libc::O_NONBLOCK)?;
            let meta = f.metadata()?;
            if meta.is_file() || (dirs && meta.is_dir()) {
                clear_nonblock(&f);
                Ok(f)
            } else if meta.is_dir() {
                Err(refused("a directory, not a file"))
            } else {
                Err(refused("not a regular file"))
            }
        }

        /// Opens `rel` to write, creating it, and with `make` the folders on
        /// the way. An existing file must be a regular file with no other
        /// names (hard links), so writing cannot reach a file elsewhere.
        pub(crate) fn write(&self, rel: &Path, how: Write, make: bool) -> io::Result<File> {
            let n = names(rel)?;
            let Some((last, parents)) = n.split_last() else {
                return Err(refused("a directory, not a file"));
            };
            let dir = self.walk(parents, make)?;
            let mut flags = libc::O_WRONLY | libc::O_CREAT | libc::O_NONBLOCK;
            if how == Write::Append {
                flags |= libc::O_APPEND;
            }
            let f = openat(&dir, last, flags)?;
            let meta = f.metadata()?;
            if !meta.is_file() {
                return Err(refused("not a regular file"));
            }
            if meta.nlink() > 1 {
                return Err(refused("a file with other names (hard links)"));
            }
            clear_nonblock(&f);
            if how == Write::Truncate {
                f.set_len(0)?;
            }
            Ok(f)
        }

        /// Makes the folders of `rel` (all of it a folder path).
        pub(crate) fn make_dirs(&self, rel: &Path) -> io::Result<()> {
            self.walk(&names(rel)?, true).map(drop)
        }

        /// Checks that `rel` could be written: its folders are there without
        /// links, and the file, if it is there, is a regular file.
        pub(crate) fn check_write(&self, rel: &Path) -> io::Result<()> {
            let n = names(rel)?;
            let Some((last, parents)) = n.split_last() else {
                return Err(refused("a directory, not a file"));
            };
            let dir = self.walk(parents, false)?;
            match openat(&dir, last, libc::O_RDONLY | libc::O_NONBLOCK) {
                Ok(f) if f.metadata()?.is_file() => Ok(()),
                Ok(_) => Err(refused("not a regular file")),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        }
    }

    fn clear_nonblock(f: &File) {
        // SAFETY: fcntl on a descriptor we own.
        unsafe {
            let fl = libc::fcntl(f.as_raw_fd(), libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(f.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK);
            }
        }
    }

    /// True when users other than the owner may write in `dir`.
    pub(crate) fn others_may_write(dir: &Path) -> bool {
        std::fs::metadata(dir).is_ok_and(|m| m.mode() & 0o022 != 0)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    /// A data directory.
    #[derive(Debug)]
    pub(crate) struct Root {
        dir: PathBuf,
    }

    fn is_reparse(m: &std::fs::Metadata) -> bool {
        m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    impl Root {
        pub(crate) fn open(dir: &Path) -> io::Result<Root> {
            Ok(Root {
                dir: dir.to_path_buf(),
            })
        }

        /// The folder `rel` names, each step checked not to be a reparse
        /// point, made on the way with `make`.
        fn walk(&self, rel: &[&std::ffi::OsStr], make: bool) -> io::Result<PathBuf> {
            let mut dir = self.dir.clone();
            for n in rel {
                dir.push(n);
                match std::fs::symlink_metadata(&dir) {
                    Ok(m) if is_reparse(&m) => {
                        return Err(refused("a symbolic link or junction on the way"))
                    }
                    Ok(m) if !m.is_dir() => return Err(refused("not a directory")),
                    Ok(_) => {}
                    Err(e) if make && e.kind() == io::ErrorKind::NotFound => {
                        match std::fs::create_dir(&dir) {
                            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                            _ => {}
                        }
                        if is_reparse(&std::fs::symlink_metadata(&dir)?) {
                            return Err(refused("a symbolic link or junction on the way"));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(dir)
        }

        fn checked(f: File, dirs: bool) -> io::Result<File> {
            let meta = f.metadata()?;
            if is_reparse(&meta) {
                return Err(refused("a symbolic link or junction"));
            }
            if meta.is_file() || (dirs && meta.is_dir()) {
                Ok(f)
            } else if meta.is_dir() {
                Err(refused("a directory, not a file"))
            } else {
                Err(refused("not a regular file"))
            }
        }

        pub(crate) fn read(&self, rel: &Path, dirs: bool) -> io::Result<File> {
            let n = names(rel)?;
            let path = match n.split_last() {
                Some((last, parents)) => self.walk(parents, false)?.join(last),
                None if dirs => self.dir.clone(),
                None => return Err(refused("a directory, not a file")),
            };
            let f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)?;
            Self::checked(f, dirs)
        }

        pub(crate) fn write(&self, rel: &Path, how: Write, make: bool) -> io::Result<File> {
            let n = names(rel)?;
            let Some((last, parents)) = n.split_last() else {
                return Err(refused("a directory, not a file"));
            };
            let path = self.walk(parents, make)?.join(last);
            let mut o = std::fs::OpenOptions::new();
            o.create(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            match how {
                Write::Truncate => o.write(true),
                Write::Append => o.append(true),
            };
            let f = Self::checked(o.open(path)?, false)?;
            if how == Write::Truncate {
                f.set_len(0)?;
            }
            Ok(f)
        }

        pub(crate) fn make_dirs(&self, rel: &Path) -> io::Result<()> {
            self.walk(&names(rel)?, true).map(drop)
        }

        pub(crate) fn check_write(&self, rel: &Path) -> io::Result<()> {
            let n = names(rel)?;
            let Some((last, parents)) = n.split_last() else {
                return Err(refused("a directory, not a file"));
            };
            let path = self.walk(parents, false)?.join(last);
            match std::fs::symlink_metadata(&path) {
                Ok(m) if is_reparse(&m) => Err(refused("a symbolic link or junction")),
                Ok(m) if !m.is_file() => Err(refused("not a regular file")),
                Ok(_) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        }
    }

    pub(crate) fn others_may_write(_dir: &Path) -> bool {
        false
    }
}

pub(crate) use imp::others_may_write;

/// The deepest part of `path` that exists, and the names after it.
pub(crate) fn split_existing(path: &Path) -> (PathBuf, Vec<std::ffi::OsString>) {
    let mut base = path.to_path_buf();
    let mut rest = Vec::new();
    while std::fs::symlink_metadata(&base).is_err() {
        match (base.file_name().map(|n| n.to_os_string()), base.parent()) {
            (Some(n), Some(p)) => {
                rest.push(n);
                base = p.to_path_buf();
            }
            _ => break,
        }
    }
    rest.reverse();
    (base, rest)
}
