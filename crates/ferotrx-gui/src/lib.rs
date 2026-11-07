//! FeroTRX desktop GUI.
//!
//! A client of the control API ([`ferotrx_ctl`]): it connects to one or more
//! `ferotrx serve` servers, on this machine or across the lab, and shows
//! their interfaces as ports. Each port has streams, built layer by layer in
//! the stream editor with a live packet view, or replayed from captures; the
//! port's streams are sent as an ordinary profile with `profile.load` and
//! `run.start`. TCP and UDP runs start from their profiles, and every run's
//! counters show in a grid and in rate charts.
//!
//! The parts that do not draw anything are usable on their own:
//!
//! * [`model`]: streams, ports and the profiles they become;
//! * [`conn`]: a connection worker per server, polling run lists;
//! * [`local`]: the server the GUI starts on this computer;
//! * [`protocols`]: the protocol editor registry, where new protocols and
//!   application layers plug in;
//! * [`theme`]: themes (colours per mode, widget style, text sizes) and how
//!   they become egui styles.

pub mod app;
pub mod conn;
pub mod files;
pub mod fonts;
pub mod local;
pub mod model;
pub mod packet_view;
pub mod protocols;
pub mod theme;
pub mod views;
pub mod workspace;

pub use app::{FeroApp, Options};
