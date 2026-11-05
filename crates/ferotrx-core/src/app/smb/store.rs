//! The server's shares: directories and files in memory, shared by all
//! connections of a template, so that one connection reads what another
//! wrote.

use std::collections::BTreeMap;

use super::msg::{
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND,
};

pub const ATTR_READONLY: u32 = 0x01;
pub const ATTR_DIRECTORY: u32 = 0x10;
pub const ATTR_ARCHIVE: u32 = 0x20;

#[derive(Clone, Debug)]
pub struct Node {
    /// The last part of the path, as it was created.
    pub name: String,
    pub dir: bool,
    pub data: Vec<u8>,
    /// Windows times (100 ns since 1601).
    pub created: u64,
    pub written: u64,
    /// A number of its own (FileId, IndexNumber).
    pub id: u64,
}

impl Node {
    pub fn attributes(&self, read_only: bool) -> u32 {
        let a = if self.dir {
            ATTR_DIRECTORY
        } else {
            ATTR_ARCHIVE
        };
        if read_only && !self.dir {
            a | ATTR_READONLY
        } else {
            a
        }
    }
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }
    /// Allocation: the size in whole 4 KiB clusters.
    pub fn allocation(&self) -> u64 {
        self.size().div_ceil(4096) * 4096
    }
}

#[derive(Clone, Debug)]
pub struct Share {
    pub name: String,
    pub read_only: bool,
    /// By path in lower case, `""` for the root.
    nodes: BTreeMap<String, Node>,
}

/// A path as SMB names it (`dir\file.txt`, no leading backslash), checked
/// and made a key: `Err` for `..` and other names that leave the share.
pub fn key(path: &str) -> Result<String, u32> {
    let p = path.replace('/', "\\");
    let mut parts = Vec::new();
    for part in p.split('\\') {
        match part {
            "" | "." => {}
            ".." => return Err(STATUS_OBJECT_NAME_INVALID),
            x if x.contains(['\0', ':', '*', '?', '"', '<', '>', '|']) => {
                return Err(STATUS_OBJECT_NAME_INVALID)
            }
            x => parts.push(x.to_lowercase()),
        }
    }
    Ok(parts.join("\\"))
}

fn parent(key: &str) -> &str {
    key.rsplit_once('\\').map_or("", |(p, _)| p)
}

/// The last part of a path, as written.
pub fn last(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .to_string()
}

impl Share {
    pub fn new(name: &str, read_only: bool, now: u64, id: u64) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            String::new(),
            Node {
                name: String::new(),
                dir: true,
                data: Vec::new(),
                created: now,
                written: now,
                id,
            },
        );
        Self {
            name: name.to_string(),
            read_only,
            nodes,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Node> {
        self.nodes.get(key)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Node> {
        self.nodes.get_mut(key)
    }

    /// Makes a file or directory; its parent has to be there.
    pub fn create(&mut self, path: &str, dir: bool, now: u64, id: u64) -> Result<String, u32> {
        let k = key(path)?;
        if k.is_empty() || self.nodes.contains_key(&k) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        match self.nodes.get(parent(&k)) {
            Some(p) if p.dir => {}
            Some(_) => return Err(STATUS_NOT_A_DIRECTORY),
            None => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
        }
        self.nodes.insert(
            k.clone(),
            Node {
                name: last(path),
                dir,
                data: Vec::new(),
                created: now,
                written: now,
                id,
            },
        );
        Ok(k)
    }

    /// Makes the directories of `path` that are missing, and the file.
    pub fn put(&mut self, path: &str, data: Vec<u8>, now: u64, next_id: &mut u64) {
        let Ok(k) = key(path) else { return };
        let shown: Vec<String> = path
            .replace('/', "\\")
            .split('\\')
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect();
        for i in 1..shown.len() {
            let dir = shown[..i].join("\\");
            if self.get(&key(&dir).unwrap_or_default()).is_none() {
                *next_id += 1;
                let _ = self.create(&dir, true, now, *next_id);
            }
        }
        *next_id += 1;
        if self.create(path, false, now, *next_id).is_ok() {
            if let Some(n) = self.nodes.get_mut(&k) {
                n.data = data;
            }
        }
    }

    /// Removes a file or an empty directory.
    pub fn remove(&mut self, key: &str) -> Result<(), u32> {
        if key.is_empty() {
            return Err(STATUS_ACCESS_DENIED);
        }
        if !self.is_empty_dir_or_file(key)? {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        self.nodes.remove(key);
        Ok(())
    }

    /// `Ok(true)` for a file or an empty directory.
    pub fn is_empty_dir_or_file(&self, key: &str) -> Result<bool, u32> {
        let n = self.nodes.get(key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !n.dir {
            return Ok(true);
        }
        let prefix = format!("{key}\\");
        Ok(!self.nodes.keys().any(|k| {
            if key.is_empty() {
                !k.is_empty()
            } else {
                k.starts_with(&prefix)
            }
        }))
    }

    /// What a directory holds, by name.
    pub fn children(&self, key: &str) -> Vec<&Node> {
        let mut v: Vec<&Node> = self
            .nodes
            .iter()
            .filter(|(k, _)| !k.is_empty() && parent(k) == key)
            .map(|(_, n)| n)
            .collect();
        v.sort_by_key(|n| n.name.to_lowercase());
        v
    }

    /// Renames `from` (and, for a directory, what is in it) to `to`.
    pub fn rename(&mut self, from: &str, to: &str, replace: bool) -> Result<String, u32> {
        let tk = key(to)?;
        if tk == from {
            return Ok(tk);
        }
        if let Some(t) = self.nodes.get(&tk) {
            if !replace || t.dir {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
        }
        match self.nodes.get(parent(&tk)) {
            Some(p) if p.dir => {}
            _ => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
        }
        let mut n = self
            .nodes
            .remove(from)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        n.name = last(to);
        self.nodes.insert(tk.clone(), n);
        let prefix = format!("{from}\\");
        let moved: Vec<String> = self
            .nodes
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for k in moved {
            if let Some(n) = self.nodes.remove(&k) {
                self.nodes
                    .insert(format!("{tk}\\{}", &k[prefix.len()..]), n);
            }
        }
        Ok(tk)
    }

    /// Bytes in all files.
    pub fn used(&self) -> u64 {
        self.nodes.values().map(Node::size).sum()
    }
}

/// `*` and `?` as in a directory search, without regard to case.
pub fn matches(pattern: &str, name: &str) -> bool {
    fn m(p: &[char], n: &[char]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some('*'), _) => m(&p[1..], n) || (!n.is_empty() && m(p, &n[1..])),
            (Some('?'), Some(_)) => m(&p[1..], &n[1..]),
            (Some(a), Some(b)) => a == b && m(&p[1..], &n[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    pattern.is_empty() || pattern == "*" || pattern == "*.*" || m(&p, &n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_renames_and_removes() {
        let mut s = Share::new("lab", false, 1, 1);
        let mut id = 1;
        s.put("docs/Manual.txt", b"hello".to_vec(), 2, &mut id);
        assert_eq!(s.get("docs\\manual.txt").unwrap().data, b"hello");
        assert_eq!(s.children("").len(), 1);
        assert_eq!(s.children("docs")[0].name, "Manual.txt");
        assert_eq!(
            s.create("missing\\x", false, 0, 9),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            s.create("docs\\manual.txt", false, 0, 9),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(key("..\\etc"), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(s.remove("docs"), Err(STATUS_DIRECTORY_NOT_EMPTY));
        assert_eq!(s.rename("docs", "papers", false), Ok("papers".into()));
        assert!(s.get("papers\\manual.txt").is_some());
        assert_eq!(s.remove("papers\\manual.txt"), Ok(()));
        assert_eq!(s.remove("papers"), Ok(()));
        assert!(s.children("").is_empty());
        assert!(matches("*.TXT", "a.txt") && matches("a?c", "abc") && !matches("a*z", "abc"));
    }
}
