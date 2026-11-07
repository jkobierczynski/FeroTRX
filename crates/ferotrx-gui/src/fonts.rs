//! Fonts: the text and monospace fonts the Appearance window picks (this
//! computer's interface fonts by default, which read better than egui's
//! thin built-in one), plus a system font with wide coverage as a
//! fallback, since egui's built-in fonts lack arrows and some symbols the
//! decoder and the GUI use.

use std::path::{Path, PathBuf};

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

const FALLBACKS: &[&str] = &[
    // Linux
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    // Windows
    "C:\\Windows\\Fonts\\seguisym.ttf",
    "C:\\Windows\\Fonts\\segoeui.ttf",
    // macOS
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
    "/System/Library/Fonts/Apple Symbols.ttf",
];

/// The setting that keeps egui's own fonts.
pub const BUILTIN: &str = "builtin";

/// The interface fonts tried, in order, when no font is chosen.
const SYSTEM_TEXT: &[&str] = &[
    "C:\\Windows\\Fonts\\segoeui.ttf",
    "/System/Library/Fonts/SFNS.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
];
const SYSTEM_MONOSPACE: &[&str] = &[
    "C:\\Windows\\Fonts\\consola.ttf",
    "C:\\Windows\\Fonts\\CascadiaMono.ttf",
    "/System/Library/Fonts/SFNSMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
];

/// The font a setting means: a file, the first system font found when
/// empty, or none for egui's own.
fn chosen(setting: &str, system: &[&str]) -> Option<String> {
    match setting.trim() {
        BUILTIN => None,
        "" => system
            .iter()
            .find(|p| load(Path::new(p)).is_ok())
            .map(|p| p.to_string()),
        p => Some(p.to_string()),
    }
}

/// Reads a font file and checks that it is one egui can use (TrueType or
/// OpenType, the first font of a collection): egui stops the program on a
/// file it cannot read as a font.
pub fn load(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    skrifa::FontRef::from_index(&bytes, 0)
        .map_err(|_| format!("{}: not a TrueType or OpenType font", path.display()))?;
    Ok(bytes)
}

/// egui's fonts with `text` and `monospace` (font files; empty for this
/// computer's interface font, [`BUILTIN`] for egui's own) in front, and the system fallback behind. A file that
/// cannot be used is left out and reported.
pub fn definitions(text: &str, monospace: &str) -> (FontDefinitions, Vec<String>) {
    let mut fonts = FontDefinitions::default();
    let mut errors = Vec::new();
    for (key, setting, system, family) in [
        ("chosen-text", text, SYSTEM_TEXT, FontFamily::Proportional),
        (
            "chosen-monospace",
            monospace,
            SYSTEM_MONOSPACE,
            FontFamily::Monospace,
        ),
    ] {
        let Some(path) = chosen(setting, system) else {
            continue;
        };
        match load(Path::new(&path)) {
            Ok(bytes) => {
                fonts
                    .font_data
                    .insert(key.into(), FontData::from_owned(bytes).into());
                fonts
                    .families
                    .entry(family)
                    .or_default()
                    .insert(0, key.into());
            }
            Err(e) => errors.push(e),
        }
    }
    if let Some(bytes) = FALLBACKS.iter().find_map(|p| load(Path::new(p)).ok()) {
        fonts
            .font_data
            .insert("system-fallback".into(), FontData::from_owned(bytes).into());
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("system-fallback".into());
        }
    }
    (fonts, errors)
}

/// Sets the fonts of `ctx`; see [`definitions`].
pub fn apply(ctx: &egui::Context, text: &str, monospace: &str) -> Result<(), String> {
    let (fonts, errors) = definitions(text, monospace);
    ctx.set_fonts(fonts);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// The default fonts (this computer's) and the fallback.
pub fn install(ctx: &egui::Context) {
    let _ = apply(ctx, "", "");
}

/// The folders this computer keeps its fonts in.
fn font_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if cfg!(windows) {
        let windir =
            std::env::var_os("WINDIR").map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
        v.push(windir.join("Fonts"));
        // Fonts installed for one user only.
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            v.push(PathBuf::from(local).join("Microsoft\\Windows\\Fonts"));
        }
    } else if cfg!(target_os = "macos") {
        v.push("/System/Library/Fonts".into());
        v.push("/Library/Fonts".into());
        if let Some(h) = home {
            v.push(h.join("Library/Fonts"));
        }
    } else {
        v.push("/usr/share/fonts".into());
        v.push("/usr/local/share/fonts".into());
        if let Some(h) = home {
            v.push(h.join(".local/share/fonts"));
            v.push(h.join(".fonts"));
        }
    }
    v
}

/// The font files on this computer, as (name, path), sorted by name. The
/// name is the file name without its extension.
pub fn system_fonts() -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    for dir in font_folders() {
        collect(&dir, 0, &mut found);
    }
    found.sort_by(|a, b| {
        a.0.to_lowercase()
            .cmp(&b.0.to_lowercase())
            .then(a.1.cmp(&b.1))
    });
    found.dedup_by(|a, b| a.0 == b.0);
    found
}

fn collect(dir: &Path, depth: u32, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.is_dir() {
            if depth < 4 {
                collect(&path, depth + 1, out);
            }
            continue;
        }
        let ext = path
            .extension()
            .and_then(|x| x.to_str())
            .map(str::to_ascii_lowercase);
        if matches!(ext.as_deref(), Some("ttf" | "otf" | "ttc")) {
            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                out.push((name.to_string(), path.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_is_not_a_font_is_refused() {
        let dir = std::env::temp_dir().join(format!("ferotrx-font-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.ttf");
        std::fs::write(&bad, b"not a font").unwrap();
        assert!(load(&bad).unwrap_err().contains("not a TrueType"));
        let (fonts, errors) = definitions(bad.to_str().unwrap(), "");
        assert_eq!(errors.len(), 1);
        assert!(!fonts.font_data.contains_key("chosen-text"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn builtin_keeps_eguis_fonts_in_front() {
        let (fonts, errors) = definitions(BUILTIN, BUILTIN);
        assert!(errors.is_empty());
        assert!(!fonts.font_data.contains_key("chosen-text"));
        assert!(!fonts.font_data.contains_key("chosen-monospace"));
    }

    #[test]
    fn a_chosen_font_goes_first() {
        // egui's own font files are not on disk; use a system one when there is.
        let Some((_, path)) = system_fonts().into_iter().find(|(_, p)| load(p).is_ok()) else {
            return;
        };
        let p = path.to_str().unwrap();
        let (fonts, errors) = definitions(p, p);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(fonts.families[&FontFamily::Proportional][0], "chosen-text");
        assert_eq!(
            fonts.families[&FontFamily::Monospace][0],
            "chosen-monospace"
        );
        // The built-in fonts stay behind it for what it lacks.
        assert!(fonts.families[&FontFamily::Proportional].len() > 1);
    }
}
