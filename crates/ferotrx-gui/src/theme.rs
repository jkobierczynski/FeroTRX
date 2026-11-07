//! Appearance: theme colours, widget style and text sizes.
//!
//! A [`Theme`] has a colour [`Palette`] for light mode and one for dark mode,
//! and a [`WidgetStyle`] shared by both (mode, zoom, corner radius, borders,
//! density, text sizes, shadows, animations, scroll bars). [`apply`] turns it
//! into egui styles; the Appearance window edits it live. Themes are saved
//! with the GUI's state and can be written to and read from TOML files
//! (`format = 1`), so a lab can share one.

use std::collections::BTreeMap;

use eframe::egui::{self, Color32, CornerRadius, FontId, Shadow, Stroke, TextStyle, Visuals};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Version of the theme file format.
pub const FORMAT_VERSION: u32 = 1;

/// An sRGB colour, written as `"#rrggbb"` (or `"#rrggbbaa"`) in files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub Color32);

impl Rgb {
    pub const fn hex(v: u32) -> Self {
        Rgb(Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8))
    }

    pub fn to_hex(self) -> String {
        let [r, g, b, a] = self.0.to_srgba_unmultiplied();
        if a == 255 {
            format!("#{r:02x}{g:02x}{b:02x}")
        } else {
            format!("#{r:02x}{g:02x}{b:02x}{a:02x}")
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let h = s.trim().trim_start_matches('#');
        let byte = |i: usize| {
            h.get(i..i + 2)
                .and_then(|x| u8::from_str_radix(x, 16).ok())
                .ok_or_else(|| format!("{s:?} is not a colour (#rrggbb)"))
        };
        match h.len() {
            6 => Ok(Rgb(Color32::from_rgb(byte(0)?, byte(2)?, byte(4)?))),
            8 => Ok(Rgb(Color32::from_rgba_unmultiplied(
                byte(0)?,
                byte(2)?,
                byte(4)?,
                byte(6)?,
            ))),
            _ => Err(format!("{s:?} is not a colour (#rrggbb)")),
        }
    }
}

impl Serialize for Rgb {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Rgb {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Rgb::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// The colours of one mode (light or dark).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Palette {
    /// Hyperlinks, the outline of a hovered widget, the text cursor, and
    /// the text of selected items.
    pub accent: Rgb,
    /// Behind selected items and selected text.
    pub selection: Rgb,
    /// Panels: the main background.
    pub background: Rgb,
    /// Windows and menus.
    pub window: Rgb,
    /// Text fields, plots and code.
    pub input: Rgb,
    /// Every other row of a striped table.
    pub stripe: Rgb,
    /// Buttons and other widgets.
    pub widget: Rgb,
    /// A widget under the mouse.
    pub hovered: Rgb,
    /// Borders and separators.
    pub border: Rgb,
    /// Text, when not the mode's own.
    pub text: Option<Rgb>,
    /// Passed, running fine, connected.
    pub good: Rgb,
    /// Something in progress.
    pub running: Rgb,
    /// Warnings.
    pub warn: Rgb,
    /// Errors and failures.
    pub error: Rgb,
}

impl Default for Palette {
    fn default() -> Self {
        Preset::FeroTrx.theme().light
    }
}

impl Palette {
    /// egui's own colours for a mode.
    pub fn from_visuals(v: &Visuals) -> Self {
        let w = &v.widgets;
        // egui has translucent and additive colours; themes keep opaque ones.
        let o = |c: Color32| Rgb(over(c, v.panel_fill));
        Palette {
            accent: o(v.hyperlink_color),
            selection: o(v.selection.bg_fill),
            background: o(v.panel_fill),
            window: o(v.window_fill),
            input: o(v.extreme_bg_color),
            stripe: o(v.faint_bg_color),
            widget: o(w.inactive.weak_bg_fill),
            hovered: o(w.hovered.weak_bg_fill),
            border: o(w.noninteractive.bg_stroke.color),
            text: None,
            good: Rgb::hex(0x2ea043),
            running: Rgb::hex(0x3a7bd5),
            warn: o(v.warn_fg_color),
            error: o(v.error_fg_color),
        }
    }

    /// Every colour with its name and what it is for, for forms.
    pub fn entries(&mut self) -> [(&'static str, &'static str, &mut Rgb); 13] {
        [
            (
                "Accent",
                "Links, hovered outlines, the cursor, the text of selected items",
                &mut self.accent,
            ),
            (
                "Selection",
                "Behind selected items and selected text",
                &mut self.selection,
            ),
            ("Background", "Panels", &mut self.background),
            ("Windows", "Windows and menus", &mut self.window),
            (
                "Input fields",
                "Text fields, plots and code",
                &mut self.input,
            ),
            (
                "Table stripes",
                "Every other row of a table",
                &mut self.stripe,
            ),
            ("Widgets", "Buttons, check boxes, sliders", &mut self.widget),
            (
                "Hovered widgets",
                "A widget under the mouse",
                &mut self.hovered,
            ),
            ("Borders", "Borders and separators", &mut self.border),
            ("Passed", "Passed, connected, running fine", &mut self.good),
            ("Running", "Runs and checks in progress", &mut self.running),
            ("Warnings", "Warnings", &mut self.warn),
            ("Errors", "Errors and failures", &mut self.error),
        ]
    }
}

/// Light, dark, or whatever the system uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    System,
    Light,
    Dark,
}

/// Shapes, sizes and behaviour, the same in both modes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WidgetStyle {
    pub mode: Mode,
    /// Scale of the whole window (Ctrl +/- changes it too).
    pub zoom: f32,
    /// Corner radius of buttons, fields and other widgets, in points.
    pub corner_radius: f32,
    /// Corner radius of windows and menus.
    pub window_radius: f32,
    /// Width of borders and separators.
    pub border_width: f32,
    /// Buttons and fields get a border even when not hovered.
    pub outlined: bool,
    /// Spacing and widget heights: below 1 denser, above 1 roomier.
    pub density: f32,
    /// Text sizes in points.
    pub body_size: f32,
    pub monospace_size: f32,
    pub heading_size: f32,
    pub small_size: f32,
    /// Shadows under windows and menus.
    pub shadows: bool,
    /// Animated opening and closing.
    pub animations: bool,
    /// Scroll bars always shown beside the content, not floating over it.
    pub solid_scrollbars: bool,
}

impl Default for WidgetStyle {
    fn default() -> Self {
        WidgetStyle {
            mode: Mode::System,
            zoom: 1.0,
            corner_radius: 2.0,
            window_radius: 6.0,
            border_width: 1.0,
            outlined: false,
            density: 1.0,
            body_size: 12.5,
            monospace_size: 12.0,
            heading_size: 18.0,
            small_size: 9.0,
            shadows: true,
            animations: true,
            solid_scrollbars: false,
        }
    }
}

/// Colours for both modes and the widget style: everything the Appearance
/// window sets.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Theme {
    pub format: u32,
    pub name: String,
    pub style: WidgetStyle,
    pub light: Palette,
    pub dark: Palette,
}

impl Default for Theme {
    fn default() -> Self {
        Preset::FeroTrx.theme()
    }
}

impl Theme {
    pub fn to_toml(&self) -> String {
        let mut t = self.clone();
        t.format = FORMAT_VERSION;
        toml::to_string(&t).unwrap_or_default()
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        let t: Theme = toml::from_str(text).map_err(|e| e.to_string())?;
        if t.format > FORMAT_VERSION {
            return Err(format!(
                "theme format {} is newer than this GUI's ({FORMAT_VERSION})",
                t.format
            ));
        }
        Ok(t)
    }

    pub fn palette(&self, dark: bool) -> &Palette {
        if dark {
            &self.dark
        } else {
            &self.light
        }
    }

    pub fn palette_mut(&mut self, dark: bool) -> &mut Palette {
        if dark {
            &mut self.dark
        } else {
            &mut self.light
        }
    }
}

/// Built-in themes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    FeroTrx,
    Egui,
    HighContrast,
    Compact,
}

impl Preset {
    pub const ALL: [Preset; 4] = [
        Preset::FeroTrx,
        Preset::Egui,
        Preset::HighContrast,
        Preset::Compact,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Preset::FeroTrx => "FeroTRX",
            Preset::Egui => "egui",
            Preset::HighContrast => "High contrast",
            Preset::Compact => "Compact",
        }
    }

    pub fn theme(self) -> Theme {
        let fero_light = Palette {
            accent: Rgb::hex(0x03628a),
            selection: Rgb::hex(0xc4e3ef),
            background: Rgb::hex(0xf3f5f7),
            window: Rgb::hex(0xfbfcfd),
            input: Rgb::hex(0xffffff),
            stripe: Rgb::hex(0xebeff3),
            widget: Rgb::hex(0xe1e7ed),
            hovered: Rgb::hex(0xd0dbe5),
            border: Rgb::hex(0xc5ced8),
            text: None,
            good: Rgb::hex(0x1a7f37),
            running: Rgb::hex(0x2f6fb5),
            warn: Rgb::hex(0xa85400),
            error: Rgb::hex(0xc62828),
        };
        let fero_dark = Palette {
            accent: Rgb::hex(0x5cc0e6),
            selection: Rgb::hex(0x1d4a5e),
            background: Rgb::hex(0x141a21),
            window: Rgb::hex(0x182029),
            input: Rgb::hex(0x0c1117),
            stripe: Rgb::hex(0x1b232c),
            widget: Rgb::hex(0x27313c),
            hovered: Rgb::hex(0x34414f),
            border: Rgb::hex(0x323d4a),
            text: None,
            good: Rgb::hex(0x7cc63a),
            running: Rgb::hex(0x58a6ff),
            warn: Rgb::hex(0xe3a008),
            error: Rgb::hex(0xf26b63),
        };
        let name = self.name().to_string();
        match self {
            Preset::FeroTrx => Theme {
                format: FORMAT_VERSION,
                name,
                style: WidgetStyle {
                    corner_radius: 4.0,
                    window_radius: 8.0,
                    ..Default::default()
                },
                light: fero_light,
                dark: fero_dark,
            },
            Preset::Egui => Theme {
                format: FORMAT_VERSION,
                name,
                style: WidgetStyle::default(),
                light: Palette::from_visuals(&Visuals::light()),
                dark: Palette::from_visuals(&Visuals::dark()),
            },
            Preset::HighContrast => Theme {
                format: FORMAT_VERSION,
                name,
                style: WidgetStyle {
                    corner_radius: 0.0,
                    window_radius: 0.0,
                    border_width: 1.5,
                    outlined: true,
                    body_size: 14.0,
                    monospace_size: 13.5,
                    heading_size: 20.0,
                    small_size: 11.0,
                    shadows: false,
                    animations: false,
                    solid_scrollbars: true,
                    ..Default::default()
                },
                light: Palette {
                    accent: Rgb::hex(0x0000b8),
                    selection: Rgb::hex(0xc8d6ff),
                    background: Rgb::hex(0xffffff),
                    window: Rgb::hex(0xffffff),
                    input: Rgb::hex(0xffffff),
                    stripe: Rgb::hex(0xeeeeee),
                    widget: Rgb::hex(0xe2e2e2),
                    hovered: Rgb::hex(0xc8c8c8),
                    border: Rgb::hex(0x000000),
                    text: Some(Rgb::hex(0x000000)),
                    good: Rgb::hex(0x005c1a),
                    running: Rgb::hex(0x00008b),
                    warn: Rgb::hex(0x803c00),
                    error: Rgb::hex(0xa00000),
                },
                dark: Palette {
                    accent: Rgb::hex(0xffd700),
                    selection: Rgb::hex(0x4d3f00),
                    background: Rgb::hex(0x000000),
                    window: Rgb::hex(0x000000),
                    input: Rgb::hex(0x000000),
                    stripe: Rgb::hex(0x1a1a1a),
                    widget: Rgb::hex(0x222222),
                    hovered: Rgb::hex(0x3a3a3a),
                    border: Rgb::hex(0xffffff),
                    text: Some(Rgb::hex(0xffffff)),
                    good: Rgb::hex(0x5cff5c),
                    running: Rgb::hex(0x7fbfff),
                    warn: Rgb::hex(0xffb000),
                    error: Rgb::hex(0xff6060),
                },
            },
            Preset::Compact => Theme {
                format: FORMAT_VERSION,
                name,
                style: WidgetStyle {
                    corner_radius: 2.0,
                    window_radius: 4.0,
                    density: 0.75,
                    body_size: 11.5,
                    monospace_size: 11.0,
                    heading_size: 15.0,
                    small_size: 9.0,
                    shadows: false,
                    animations: false,
                    ..Default::default()
                },
                light: fero_light,
                dark: fero_dark,
            },
        }
    }
}

/// The colours views ask for that egui has no name for, per mode.
#[derive(Clone, Copy, Debug)]
struct StatusColors {
    light: [Color32; 2],
    dark: [Color32; 2],
}

fn status_id() -> egui::Id {
    egui::Id::new("ferotrx-theme-status")
}

fn status(ui: &egui::Ui) -> [Color32; 2] {
    let dark = ui.visuals().dark_mode;
    ui.ctx()
        .data(|d| d.get_temp::<StatusColors>(status_id()))
        .map(|s| if dark { s.dark } else { s.light })
        .unwrap_or([
            Color32::from_rgb(0x2e, 0xa0, 0x43),
            Color32::from_rgb(0x3a, 0x7b, 0xd5),
        ])
}

/// Colour of passed checks, connected servers, runs that went well.
pub fn good(ui: &egui::Ui) -> Color32 {
    status(ui)[0]
}

/// Colour of runs and checks in progress.
pub fn running(ui: &egui::Ui) -> Color32 {
    status(ui)[1]
}

fn radius(r: f32) -> CornerRadius {
    CornerRadius::same(r.round().clamp(0.0, 255.0) as u8)
}

/// `c` (premultiplied, maybe translucent) drawn over the opaque `bg`.
fn over(c: Color32, bg: Color32) -> Color32 {
    let keep = 255 - c.a() as u16;
    let f = |x: u8, y: u8| (x as u16 + y as u16 * keep / 255).min(255) as u8;
    Color32::from_rgb(f(c.r(), bg.r()), f(c.g(), bg.g()), f(c.b(), bg.b()))
}

/// Mixes `a` into `b`: 0 is all `b`, 1 all `a`.
fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let f = |x: u8, y: u8| (x as f32 * t + y as f32 * (1.0 - t)).round() as u8;
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

/// The egui style of one mode of `theme`.
pub fn style_for(theme: &Theme, dark: bool) -> egui::Style {
    let p = theme.palette(dark);
    let s = &theme.style;
    let mut style = egui::Style {
        visuals: if dark {
            Visuals::dark()
        } else {
            Visuals::light()
        },
        ..Default::default()
    };

    let v = &mut style.visuals;
    v.hyperlink_color = p.accent.0;
    v.selection.bg_fill = p.selection.0;
    v.selection.stroke = Stroke::new(1.0_f32, p.accent.0);
    v.text_cursor.stroke.color = p.accent.0;
    v.panel_fill = p.background.0;
    v.window_fill = p.window.0;
    v.extreme_bg_color = p.input.0;
    v.text_edit_bg_color = Some(p.input.0);
    v.code_bg_color = p.stripe.0;
    v.faint_bg_color = p.stripe.0;
    v.warn_fg_color = p.warn.0;
    v.error_fg_color = p.error.0;
    v.override_text_color = p.text.map(|c| c.0);
    v.window_stroke = Stroke::new(s.border_width, p.border.0);
    v.window_corner_radius = radius(s.window_radius);
    v.menu_corner_radius = radius(s.window_radius);
    if !s.shadows {
        v.window_shadow = Shadow::NONE;
        v.popup_shadow = Shadow::NONE;
    }
    let w = &mut v.widgets;
    w.noninteractive.bg_stroke = Stroke::new(s.border_width, p.border.0);
    w.noninteractive.bg_fill = p.window.0;
    w.noninteractive.weak_bg_fill = p.window.0;
    w.inactive.bg_fill = p.widget.0;
    w.inactive.weak_bg_fill = p.widget.0;
    w.inactive.bg_stroke = if s.outlined {
        Stroke::new(s.border_width, p.border.0)
    } else {
        Stroke::NONE
    };
    w.hovered.bg_fill = p.hovered.0;
    w.hovered.weak_bg_fill = p.hovered.0;
    w.hovered.bg_stroke = Stroke::new(s.border_width.max(1.0), p.accent.0);
    w.active.bg_fill = p.selection.0;
    w.active.weak_bg_fill = p.selection.0;
    w.active.bg_stroke = Stroke::new(s.border_width.max(1.0), p.accent.0);
    w.open.bg_fill = p.hovered.0;
    w.open.weak_bg_fill = p.hovered.0;
    w.open.bg_stroke = Stroke::new(s.border_width, p.border.0);
    if let Some(t) = p.text {
        // Strong text a little stronger than the rest, as egui does.
        let strong = if dark {
            mix(Color32::WHITE, t.0, 0.3)
        } else {
            mix(Color32::BLACK, t.0, 0.3)
        };
        w.noninteractive.fg_stroke.color = t.0;
        w.inactive.fg_stroke.color = t.0;
        w.hovered.fg_stroke.color = strong;
        w.active.fg_stroke.color = strong;
        w.open.fg_stroke.color = strong;
    }
    for wv in [
        &mut w.noninteractive,
        &mut w.inactive,
        &mut w.hovered,
        &mut w.active,
        &mut w.open,
    ] {
        wv.corner_radius = radius(s.corner_radius);
    }

    let d = s.density.clamp(0.5, 2.0);
    let sp = &mut style.spacing;
    sp.item_spacing *= d;
    sp.button_padding *= d;
    sp.interact_size.y = (sp.interact_size.y * d).max(12.0);
    sp.indent *= d;
    sp.window_margin = egui::Margin::same((6.0 * d).round() as i8);
    sp.menu_margin = egui::Margin::same((6.0 * d).round() as i8);
    sp.scroll = if s.solid_scrollbars {
        egui::style::ScrollStyle::solid()
    } else {
        egui::style::ScrollStyle::floating()
    };
    style.animation_time = if s.animations { 1.0 / 12.0 } else { 0.0 };

    let sizes: BTreeMap<TextStyle, FontId> = [
        (TextStyle::Small, FontId::proportional(s.small_size)),
        (TextStyle::Body, FontId::proportional(s.body_size)),
        (TextStyle::Button, FontId::proportional(s.body_size)),
        (TextStyle::Heading, FontId::proportional(s.heading_size)),
        (TextStyle::Monospace, FontId::monospace(s.monospace_size)),
    ]
    .into();
    style.text_styles = sizes;
    style
}

/// Sets `theme` as the style of `ctx`, for both modes.
pub fn apply(ctx: &egui::Context, theme: &Theme) {
    ctx.set_theme(match theme.style.mode {
        Mode::System => egui::ThemePreference::System,
        Mode::Light => egui::ThemePreference::Light,
        Mode::Dark => egui::ThemePreference::Dark,
    });
    ctx.set_style_of(egui::Theme::Light, style_for(theme, false));
    ctx.set_style_of(egui::Theme::Dark, style_for(theme, true));
    let colors = StatusColors {
        light: [theme.light.good.0, theme.light.running.0],
        dark: [theme.dark.good.0, theme.dark.running.0],
    };
    ctx.data_mut(|d| d.insert_temp(status_id(), colors));
}

/// The Appearance window and the theme in use.
#[derive(Default)]
pub struct Appearance {
    pub theme: Theme,
    /// The window is open.
    pub open: bool,
    /// Which mode's colours the window edits; `None` follows the window.
    pub editing_dark: Option<bool>,
    /// What the last open or save did.
    pub status: Option<Result<String, String>>,
    /// What was last applied, to apply again only after a change.
    applied: Option<Theme>,
}

impl Appearance {
    pub fn new(theme: Theme) -> Self {
        Appearance {
            theme,
            ..Default::default()
        }
    }

    /// Applies the theme when it changed; call once per frame.
    pub fn update(&mut self, ctx: &egui::Context) {
        // Ctrl +/- zoom: keep it, so it is saved with the theme.
        let z = ctx.zoom_factor();
        if let Some(a) = &self.applied {
            if (z - a.style.zoom).abs() > 1e-3
                && (a.style.zoom - self.theme.style.zoom).abs() < 1e-3
            {
                self.theme.style.zoom = z;
                if let Some(a) = &mut self.applied {
                    a.style.zoom = z;
                }
            }
        }
        if self.applied.as_ref() == Some(&self.theme) {
            return;
        }
        apply(ctx, &self.theme);
        if (ctx.zoom_factor() - self.theme.style.zoom).abs() > 1e-3 {
            ctx.set_zoom_factor(self.theme.style.zoom.clamp(0.5, 3.0));
        }
        self.applied = Some(self.theme.clone());
    }

    pub fn open_file(&mut self, path: &std::path::Path) {
        let shown = path.display();
        self.status = Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("{shown}: {e}"))
                .and_then(|t| Theme::from_toml(&t).map_err(|e| format!("{shown}: {e}")))
                .map(|t| {
                    self.theme = t;
                    format!("opened {shown}")
                }),
        );
    }

    pub fn save_file(&mut self, path: &std::path::Path) {
        let shown = path.display();
        self.status = Some(
            std::fs::write(path, self.theme.to_toml())
                .map(|_| format!("saved {shown}"))
                .map_err(|e| format!("{shown}: {e}")),
        );
    }

    /// Draws the window. Returns `Some(save)` when a file dialog is wanted.
    pub fn window(&mut self, ctx: &egui::Context) -> Option<bool> {
        let mut open = self.open;
        let mut file = None;
        egui::Window::new("Appearance")
            .open(&mut open)
            .default_width(560.0)
            .default_height(640.0)
            .resizable(true)
            .show(ctx, |ui| {
                file = self.form(ui);
            });
        self.open = open;
        file
    }

    fn form(&mut self, ui: &mut egui::Ui) -> Option<bool> {
        let mut file = None;
        let t = &mut self.theme;
        ui.horizontal(|ui| {
            ui.label("Theme");
            egui::ComboBox::from_id_salt("theme-preset")
                .selected_text(&t.name)
                .show_ui(ui, |ui| {
                    for p in Preset::ALL {
                        if ui.selectable_label(t.name == p.name(), p.name()).clicked() {
                            // Keep the mode and zoom: they are the user's, not the theme's.
                            let (mode, zoom) = (t.style.mode, t.style.zoom);
                            *t = p.theme();
                            t.style.mode = mode;
                            t.style.zoom = zoom;
                        }
                    }
                });
            ui.add(egui::TextEdit::singleline(&mut t.name).desired_width(140.0))
                .on_hover_text("The name saved in the theme file");
            if ui
                .button("Open…")
                .on_hover_text("Read a theme file (TOML)")
                .clicked()
            {
                file = Some(false);
            }
            if ui
                .button("Save as…")
                .on_hover_text("Write this theme to a file (TOML) to share or keep")
                .clicked()
            {
                file = Some(true);
            }
        });
        match &self.status {
            Some(Ok(m)) => {
                ui.colored_label(ui.visuals().weak_text_color(), m);
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            None => {}
        }
        ui.horizontal(|ui| {
            ui.label("Mode");
            ui.radio_value(&mut t.style.mode, Mode::System, "Follow the system");
            ui.radio_value(&mut t.style.mode, Mode::Light, "Light");
            ui.radio_value(&mut t.style.mode, Mode::Dark, "Dark");
        });
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::CollapsingHeader::new("Colours")
                .default_open(true)
                .show(ui, |ui| {
                    let dark_now = ui.visuals().dark_mode;
                    let mut dark = self.editing_dark.unwrap_or(dark_now);
                    ui.horizontal(|ui| {
                        ui.label("Edit the colours of");
                        ui.selectable_value(&mut dark, false, "☀ light mode");
                        ui.selectable_value(&mut dark, true, "🌙 dark mode");
                    });
                    if dark != dark_now || self.editing_dark.is_some() {
                        self.editing_dark = Some(dark);
                    }
                    if dark != dark_now {
                        ui.small("(not the mode shown now: switch Mode to see them)");
                    }
                    let p = self.theme.palette_mut(dark);
                    egui::Grid::new("theme-colours")
                        .num_columns(4)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            let mut entries = p.entries().into_iter();
                            // Two columns of colour buttons.
                            loop {
                                let mut any = false;
                                for _ in 0..2 {
                                    if let Some((name, hover, c)) = entries.next() {
                                        any = true;
                                        egui::color_picker::color_edit_button_srgba(
                                            ui,
                                            &mut c.0,
                                            egui::color_picker::Alpha::Opaque,
                                        )
                                        .on_hover_text(c.to_hex());
                                        ui.label(name).on_hover_text(hover);
                                    }
                                }
                                ui.end_row();
                                if !any {
                                    break;
                                }
                            }
                        });
                    let p = self.theme.palette_mut(dark);
                    ui.horizontal(|ui| {
                        let mut custom = p.text.is_some();
                        if ui.checkbox(&mut custom, "Own text colour").changed() {
                            p.text = custom.then(|| Rgb(ui.visuals().text_color()));
                        }
                        if let Some(c) = &mut p.text {
                            egui::color_picker::color_edit_button_srgba(
                                ui,
                                &mut c.0,
                                egui::color_picker::Alpha::Opaque,
                            );
                        }
                    });
                });

            let s = &mut self.theme.style;
            egui::CollapsingHeader::new("Widgets")
                .default_open(true)
                .show(ui, |ui| {
                    egui::Grid::new("theme-widgets")
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.label("Corner radius");
                            ui.add(
                                egui::Slider::new(&mut s.corner_radius, 0.0..=12.0).suffix(" pt"),
                            );
                            ui.end_row();
                            ui.label("Window corners");
                            ui.add(
                                egui::Slider::new(&mut s.window_radius, 0.0..=20.0).suffix(" pt"),
                            );
                            ui.end_row();
                            ui.label("Border width");
                            ui.add(
                                egui::Slider::new(&mut s.border_width, 0.0..=3.0)
                                    .step_by(0.5)
                                    .suffix(" pt"),
                            );
                            ui.end_row();
                            ui.label("Density");
                            ui.add(egui::Slider::new(&mut s.density, 0.6..=1.6).step_by(0.05))
                                .on_hover_text("Spacing and widget heights: lower is denser");
                            ui.end_row();
                            ui.label("");
                            ui.checkbox(&mut s.outlined, "Borders on buttons and fields");
                            ui.end_row();
                            ui.label("");
                            ui.checkbox(&mut s.shadows, "Shadows under windows and menus");
                            ui.end_row();
                            ui.label("");
                            ui.checkbox(&mut s.animations, "Animations");
                            ui.end_row();
                            ui.label("");
                            ui.checkbox(
                                &mut s.solid_scrollbars,
                                "Scroll bars beside the content (not floating)",
                            );
                            ui.end_row();
                        });
                });

            egui::CollapsingHeader::new("Text")
                .default_open(true)
                .show(ui, |ui| {
                    egui::Grid::new("theme-text").num_columns(2).show(ui, |ui| {
                        ui.label("Zoom");
                        ui.add(egui::Slider::new(&mut s.zoom, 0.6..=2.0).step_by(0.05))
                            .on_hover_text("The whole window; Ctrl + and Ctrl - too");
                        ui.end_row();
                        for (label, v) in [
                            ("Body", &mut s.body_size),
                            ("Monospace", &mut s.monospace_size),
                            ("Headings", &mut s.heading_size),
                            ("Small", &mut s.small_size),
                        ] {
                            ui.label(label);
                            ui.add(egui::Slider::new(v, 7.0..=28.0).step_by(0.5).suffix(" pt"));
                            ui.end_row();
                        }
                    });
                });

            egui::CollapsingHeader::new("Preview")
                .default_open(true)
                .show(ui, preview);
        });
        file
    }
}

/// A few widgets in the current style.
fn preview(ui: &mut egui::Ui) {
    let id = ui.id().with("preview");
    let mut state: (bool, f32, String, usize) =
        ui.data(|d| d.get_temp(id))
            .unwrap_or((true, 40.0, "edit me".into(), 0));
    ui.horizontal(|ui| {
        let _ = ui.button("Button");
        ui.checkbox(&mut state.0, "Check box");
        for (n, l) in ["One", "Two", "Three"].iter().enumerate() {
            ui.selectable_value(&mut state.3, n, *l);
        }
    });
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut state.2).desired_width(120.0));
        ui.add(egui::Slider::new(&mut state.1, 0.0..=100.0));
        ui.hyperlink_to("a link", "https://github.com/jkobierczynski/FeroTRX");
    });
    ui.horizontal(|ui| {
        ui.colored_label(good(ui), "✔ passed");
        ui.colored_label(running(ui), "● running");
        ui.colored_label(ui.visuals().warn_fg_color, "⚠ warning");
        ui.colored_label(ui.visuals().error_fg_color, "✖ failed");
        ui.label(egui::RichText::new("monospace 0x0800").monospace());
        ui.small("small text");
    });
    egui::Grid::new(id.with("grid"))
        .striped(true)
        .show(ui, |ui| {
            for r in 0..3 {
                ui.label(format!("row {r}"));
                ui.label(format!("{} pkt/s", 1000 * (r + 1)));
                ui.end_row();
            }
        });
    ui.add(egui::ProgressBar::new(state.1 / 100.0).show_percentage());
    ui.data_mut(|d| d.insert_temp(id, state));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_round_trip_through_hex() {
        for s in ["#03628a", "#ffffff", "#00000080"] {
            assert_eq!(Rgb::parse(s).unwrap().to_hex(), s);
        }
        assert_eq!(Rgb::parse("03628A").unwrap(), Rgb::hex(0x03628a));
        assert!(Rgb::parse("#123").is_err());
        assert!(Rgb::parse("#gg0000").is_err());
    }

    #[test]
    fn every_preset_round_trips_through_toml() {
        for p in Preset::ALL {
            let t = p.theme();
            let text = t.to_toml();
            assert!(text.contains("format = 1"), "{text}");
            assert_eq!(Theme::from_toml(&text).unwrap(), t, "{}", p.name());
        }
    }

    #[test]
    fn theme_files_may_leave_things_out() {
        let t = Theme::from_toml(
            "format = 1\nname = \"mine\"\n[style]\nmode = \"dark\"\ncorner_radius = 0\n[dark]\naccent = \"#ff8800\"\n",
        )
        .unwrap();
        assert_eq!(t.name, "mine");
        assert_eq!(t.style.mode, Mode::Dark);
        assert_eq!(t.style.corner_radius, 0.0);
        assert_eq!(t.style.zoom, 1.0);
        assert_eq!(t.dark.accent, Rgb::hex(0xff8800));
        assert!(Theme::from_toml("format = 2").is_err());
        assert!(Theme::from_toml("[light]\naccent = \"blue\"").is_err());
    }

    #[test]
    fn styles_take_the_theme() {
        let mut t = Preset::FeroTrx.theme();
        t.style.corner_radius = 7.0;
        t.style.body_size = 15.0;
        t.style.animations = false;
        t.dark.text = Some(Rgb::hex(0xeeeeee));
        let light = style_for(&t, false);
        let dark = style_for(&t, true);
        assert!(!light.visuals.dark_mode);
        assert!(dark.visuals.dark_mode);
        assert_eq!(light.visuals.panel_fill, t.light.background.0);
        assert_eq!(dark.visuals.panel_fill, t.dark.background.0);
        assert_eq!(dark.visuals.hyperlink_color, t.dark.accent.0);
        assert_eq!(
            light.visuals.widgets.inactive.corner_radius,
            CornerRadius::same(7)
        );
        assert_eq!(light.text_styles[&TextStyle::Body].size, 15.0);
        assert_eq!(light.animation_time, 0.0);
        assert_eq!(
            dark.visuals.override_text_color,
            Some(Color32::from_rgb(0xee, 0xee, 0xee))
        );
        assert_eq!(light.visuals.override_text_color, None);
    }

    #[test]
    fn applying_sets_both_modes_and_the_status_colours() {
        let ctx = egui::Context::default();
        let mut a = Appearance::new(Preset::HighContrast.theme());
        a.theme.style.mode = Mode::Dark;
        a.update(&ctx);
        assert_eq!(
            ctx.options(|o| o.theme_preference),
            egui::ThemePreference::Dark
        );
        assert_eq!(
            ctx.style_of(egui::Theme::Light).visuals.panel_fill,
            Color32::WHITE
        );
        assert_eq!(
            ctx.style_of(egui::Theme::Dark).visuals.panel_fill,
            Color32::BLACK
        );
        let mut out = ctx.run_ui(Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                assert_eq!(good(ui), a.theme.dark.good.0);
                assert_eq!(running(ui), a.theme.dark.running.0);
            });
        });
        // Nothing paints here: egui 0.36 asserts the font atlas was handled.
        out.textures_delta.clear();
    }
}
