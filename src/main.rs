#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rust_remote_toolbox::app::RustyBoxApp;
use eframe::egui::ViewportBuilder;

#[cfg(target_os = "linux")]
fn ensure_linux_desktop_integration() {
    let Ok(exe_path) = std::env::current_exe() else { return; };
    let Some(data_dir) = dirs::data_local_dir() else { return; };

    // 1. Install standard 8-bit RGBA icon with an absolute path for instant desktop loading
    let icon_dir = data_dir.join("icons");
    let icon_file = icon_dir.join("rustybox.png");
    if std::fs::create_dir_all(&icon_dir).is_ok() {
        let png_bytes = include_bytes!("../assets/icon.png");
        let _ = std::fs::write(&icon_file, png_bytes);
    }

    // Also mirror to hicolor standard theme directory
    let hicolor_dir = data_dir.join("icons/hicolor/512x512/apps");
    if std::fs::create_dir_all(&hicolor_dir).is_ok() {
        let png_bytes = include_bytes!("../assets/icon.png");
        let _ = std::fs::write(hicolor_dir.join("rustybox.png"), png_bytes);
    }

    // 2. Clean up any redundant desktop files to prevent duplicate entries in app launcher
    let apps_dir = data_dir.join("applications");
    let duplicate_desktop = apps_dir.join("rust-remote-toolbox.desktop");
    if duplicate_desktop.exists() {
        let _ = std::fs::remove_file(duplicate_desktop);
    }

    // 3. Register the single official desktop entry
    let desktop_file = apps_dir.join("rustybox.desktop");
    if std::fs::create_dir_all(&apps_dir).is_ok() {
        let exe_str = exe_path.to_string_lossy();
        let icon_str = icon_file.to_string_lossy();
        let exe_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rustybox");

        let content = format!(
            "[Desktop Entry]\n\
            Version=1.0\n\
            Type=Application\n\
            Name=RustyBox\n\
            Comment=Remote Toolbox & Terminal\n\
            Exec=\"{}\" %U\n\
            Icon={}\n\
            Terminal=false\n\
            Categories=Utility;Network;\n\
            StartupWMClass={}\n",
            exe_str, icon_str, exe_name
        );
        let _ = std::fs::write(&desktop_file, content);
    }
}

fn install_crash_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        let log_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("data")))
            .unwrap_or_else(std::env::temp_dir);
        let _ = std::fs::create_dir_all(&log_dir);
        let crash_file = log_dir.join("crash.log");

        // Cap crash.log at 512 KB so long-lived installations never accumulate unbounded logs
        if let Ok(meta) = std::fs::metadata(&crash_file)
            && meta.len() > 512 * 1024
        {
            let bak = log_dir.join("crash.log.old");
            let _ = std::fs::rename(&crash_file, bak);
        }

        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let thread_name = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let payload = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "non-string panic payload".to_string()
        };
        let bt = std::backtrace::Backtrace::force_capture();

        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&crash_file)
        {
            use std::io::Write;
            let _ = writeln!(
                f,
                "=== RustyBox v1.4.14 Panic @ {} ===\nThread: {}\nLocation: {}\nReason: {}\nBacktrace:\n{}\n",
                ts, thread_name, location, payload, bt
            );
            let _ = f.flush();
        }
    }));
}

#[cfg(target_os = "windows")]
fn build_windows_wgpu_options() -> eframe::egui_wgpu::WgpuConfiguration {
    use eframe::egui_wgpu::{SurfaceErrorAction, WgpuConfiguration, WgpuSetup};
    use eframe::wgpu;
    use std::sync::Arc;

    WgpuConfiguration {
        present_mode: wgpu::PresentMode::AutoVsync,
        desired_maximum_frame_latency: Some(1),
        wgpu_setup: WgpuSetup::CreateNew {
            // Strictly prefer native DirectX 12 / Vulkan on Windows and avoid legacy OpenGL ICDs
            // (such as Intel igxelpicd64.dll, whose background wglSwapBuffers worker thread
            // crashes with 0xC0000005 after hours of uptime / display power-off transitions).
            supported_backends: wgpu::util::backend_bits_from_env()
                .unwrap_or(wgpu::Backends::DX12 | wgpu::Backends::VULKAN),
            power_preference: wgpu::util::power_preference_from_env()
                .unwrap_or(wgpu::PowerPreference::LowPower),
            device_descriptor: Arc::new(|adapter| {
                let base_limits = if adapter.get_info().backend == wgpu::Backend::Gl {
                    wgpu::Limits::downlevel_webgl2_defaults()
                } else {
                    wgpu::Limits::default()
                };
                wgpu::DeviceDescriptor {
                    label: Some("rustybox wgpu device"),
                    required_features: wgpu::Features::default(),
                    required_limits: wgpu::Limits {
                        max_texture_dimension_2d: 8192,
                        ..base_limits
                    },
                    memory_hints: wgpu::MemoryHints::Performance,
                }
            }),
        },
        on_surface_error: Arc::new(|err| match err {
            // Automatically recreate DXGI/Vulkan swapchain after monitor sleep, lock screen, DPI/HDR change
            wgpu::SurfaceError::Lost | wgpu::SurfaceError::OutOfMemory => {
                SurfaceErrorAction::RecreateSurface
            }
            // Normal when window is minimized or temporarily occluded on Windows
            wgpu::SurfaceError::Outdated | wgpu::SurfaceError::Timeout => {
                SurfaceErrorAction::SkipFrame
            }
        }),
    }
}

fn build_viewport(app_icon: egui::IconData) -> ViewportBuilder {
    ViewportBuilder::default()
        .with_app_id("rustybox")
        .with_title("RustyBox v1.4.14 - Remote Toolbox & Terminal")
        .with_icon(app_icon)
        .with_drag_and_drop(true)
        .with_maximized(true)
        .with_transparent(false)
        .with_min_inner_size([700.0, 480.0])
}

fn main() -> eframe::Result<()> {
    // If invoked as an SSH_ASKPASS helper by OpenSSH, output the password and exit immediately
    if let Ok(pwd) = std::env::var("RUSTYBOX_SSH_PASS") {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = out.write_all(pwd.trim().as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
        return Ok(());
    }

    install_crash_panic_hook();

    #[cfg(target_os = "linux")]
    ensure_linux_desktop_integration();

    let icon_bytes = include_bytes!("../assets/icon_rgba_128.bin");
    let app_icon = egui::IconData {
        rgba: icon_bytes.to_vec(),
        width: 128,
        height: 128,
    };

    #[cfg(target_os = "windows")]
    {
        let force_glow = std::env::var("RUSTYBOX_RENDERER")
            .map(|v| v.eq_ignore_ascii_case("glow") || v.eq_ignore_ascii_case("opengl"))
            .unwrap_or(false);

        if !force_glow {
            let wgpu_native_options = eframe::NativeOptions {
                viewport: build_viewport(app_icon.clone()),
                renderer: eframe::Renderer::Wgpu,
                wgpu_options: build_windows_wgpu_options(),
                ..Default::default()
            };
            let res = eframe::run_native(
                "RustyBox",
                wgpu_native_options,
                Box::new(|cc| Ok(Box::new(RustyBoxApp::new(cc)))),
            );
            if res.is_ok() {
                return res;
            }
        }

        // Automatic fallback for legacy Windows VMs without DX12 / Vulkan hardware or WARP support
        let glow_fallback_options = eframe::NativeOptions {
            viewport: build_viewport(app_icon),
            renderer: eframe::Renderer::Glow,
            ..Default::default()
        };
        eframe::run_native(
            "RustyBox",
            glow_fallback_options,
            Box::new(|cc| Ok(Box::new(RustyBoxApp::new(cc)))),
        )
    }

    #[cfg(not(target_os = "windows"))]
    {
        let use_wgpu = std::env::var("RUSTYBOX_RENDERER")
            .map(|v| v.eq_ignore_ascii_case("wgpu"))
            .unwrap_or(false);
        let native_options = eframe::NativeOptions {
            viewport: build_viewport(app_icon),
            renderer: if use_wgpu {
                eframe::Renderer::Wgpu
            } else {
                eframe::Renderer::Glow
            },
            ..Default::default()
        };

        eframe::run_native(
            "RustyBox",
            native_options,
            Box::new(|cc| Ok(Box::new(RustyBoxApp::new(cc)))),
        )
    }
}
