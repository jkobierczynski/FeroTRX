//! Fonts: egui's built-in fonts lack arrows and some symbols the decoder
//! and the GUI use, so a system font with wide coverage is added as a
//! fallback when one is found.

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

const CANDIDATES: &[&str] = &[
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

/// Adds the first system font found as a fallback for both families.
pub fn install(ctx: &egui::Context) {
    let Some(bytes) = CANDIDATES.iter().find_map(|p| std::fs::read(p).ok()) else {
        return;
    };
    let mut fonts = FontDefinitions::default();
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
    ctx.set_fonts(fonts);
}
