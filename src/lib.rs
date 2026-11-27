pub mod app;
pub mod editor;
pub mod network_tools;
pub mod session;
pub mod sftp;
pub mod terminal;
pub mod tunneling;
pub mod snippets;
pub mod telemetry;

use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

static UI_REPAINT_CTX: OnceLock<parking_lot::Mutex<Option<eframe::egui::Context>>> = OnceLock::new();
static UI_MINIMIZED: AtomicBool = AtomicBool::new(false);

/// Registers the primary `egui::Context` so background PTY and SFTP worker threads
/// can wake the UI loop immediately on incoming data without high-frequency idle polling.
pub fn register_ui_repaint_context(ctx: eframe::egui::Context) {
    let slot = UI_REPAINT_CTX.get_or_init(|| parking_lot::Mutex::new(None));
    *slot.lock() = Some(ctx);
}

/// Updates whether the main application window is currently minimized / zero-sized.
pub fn set_ui_minimized(minimized: bool) {
    UI_MINIMIZED.store(minimized, Ordering::Relaxed);
}

/// Requests an immediate UI repaint unless the window is minimized (avoiding occluded GPU swap churn).
pub fn request_ui_repaint() {
    if UI_MINIMIZED.load(Ordering::Relaxed) {
        return;
    }
    if let Some(slot) = UI_REPAINT_CTX.get()
        && let Some(ref ctx) = *slot.lock()
    {
        ctx.request_repaint();
    }
}
