use crate::network_tools::NetworkTools;
use crate::session::storage::{
    create_vault, decrypt_str, is_encrypted, tr, unlock_vault, AppLanguage, Credential,
    StorageManager,
};
use crate::session::ui::{render_new_session_dialog, NewSessionDialog};
use crate::session::{Session, SessionType};
use crate::sftp::ui::render_sftp_sidebar;
use crate::sftp::FileExplorer;
use crate::terminal::vt_screen::TerminalTheme;
use crate::terminal::widget::{copy_text_to_clipboard, TerminalAction, TerminalWidget};
use crate::terminal::PtySession;
use crate::tunneling::TunnelManager;
use std::sync::mpsc::{channel, Receiver, Sender};
use crate::telemetry::TabTelemetry;
use egui::{
    menu, pos2, vec2, Align, Align2, Color32, Layout, Margin, RichText, ScrollArea,
    TextEdit, TopBottomPanel, Vec2,
};
use std::collections::BTreeMap;

/// Extracts a working directory path from terminal window titles (e.g. OSC 0/2 set by bash `\u@\h: \w` or Windows cmd/PowerShell).
pub fn extract_cwd_from_title(title: &str) -> Option<String> {
    let raw = title.trim();
    if raw.is_empty() {
        return None;
    }

    // 1. Windows drive path in title (e.g. "C:\Users\Long" or "cmd - C:\Users\Long\Projects")
    if let Some(pos) = raw.find(":\\")
        && let Some(drive_char) = raw[..pos].chars().next_back()
            && drive_char.is_ascii_alphabetic() {
                let start = pos - 1;
                let candidate = raw[start..].split(" - ").next().unwrap_or(&raw[start..]).trim();
                let clean = candidate.trim_end_matches(['>', '$', '#', ' ']);
                if !clean.is_empty() {
                    return Some(clean.to_string());
                }
            }

    // 2. Unix / SSH path in title (e.g. "user@host: /var/log" or "user@host:/var/log" or "root@srv: ~/app - bash")
    if let Some((_user_host, rest)) = raw.split_once(':') {
        let candidate = rest.trim();
        // Remove trailing shell suffix if present e.g. " - bash" or " (bash)"
        let candidate = candidate.split(" - ").next().unwrap_or(candidate);
        let candidate = candidate.split(" (").next().unwrap_or(candidate).trim();
        if candidate.starts_with('/') || candidate.starts_with('~') {
            return Some(candidate.to_string());
        }
    }

    // 3. Title is direct path
    if (raw.starts_with('/') || raw.starts_with('~')) && !raw.contains(' ') {
        return Some(raw.to_string());
    }

    None
}

/// Extracts the current working directory from the active shell prompt on the visible terminal screen.
pub fn extract_cwd_from_screen(screen_text: &str) -> Option<String> {
    for line in screen_text.lines().rev().take(15) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // 1. Windows CMD / PowerShell: C:\Users\Long\Projects> or PS D:\temp>
        if let Some(gt_idx) = trimmed.rfind('>') {
            let before_gt = trimmed[..gt_idx].trim();
            if let Some(pos) = before_gt.find(":\\")
                && let Some(drive_char) = before_gt[..pos].chars().next_back()
                    && drive_char.is_ascii_alphabetic() {
                        let path_cand = before_gt[pos - 1..].trim();
                        let path_cand = path_cand.trim_start_matches("PS ").trim();
                        if !path_cand.is_empty() {
                            return Some(path_cand.to_string());
                        }
                    }
        }

        // 2. Linux / SSH prompt:
        // Format A: user@host:/path[$#% ] or user@host: /path[$#% ] or user@host:~$
        if let Some(at_idx) = trimmed.rfind('@') {
            let after_at = &trimmed[at_idx + 1..];
            if let Some(colon_idx) = after_at.find(':') {
                let after_colon = after_at[colon_idx + 1..].trim();
                let end_idx = after_colon.find(['$', '#', '%', '>']);
                let candidate = if let Some(e) = end_idx {
                    after_colon[..e].trim()
                } else {
                    after_colon.split_whitespace().next().unwrap_or("").trim()
                };

                if (candidate.starts_with('/') || candidate.starts_with('~'))
                    && !candidate.contains(['<', '>', '"', '|', '?', '*']) {
                        return Some(candidate.to_string());
                    }
            }
        }

        // Format B: [user@host /var/log]# or [user@host ~]$
        if trimmed.starts_with('[')
            && let Some(bracket_end) = trimmed.find(']') {
                let inside = trimmed[1..bracket_end].trim();
                if let Some((_user_host, path_cand)) = inside.split_once(' ') {
                    let path_cand = path_cand.trim();
                    if path_cand.starts_with('/') || path_cand.starts_with('~') {
                        return Some(path_cand.to_string());
                    }
                }
            }

        // Format C: user@host (~/app) $
        if let Some(paren_start) = trimmed.find('(')
            && let Some(paren_end) = trimmed[paren_start + 1..].find(')') {
                let inside = trimmed[paren_start + 1..paren_start + 1 + paren_end].trim();
                if inside.starts_with('/') || inside.starts_with('~') {
                    return Some(inside.to_string());
                }
            }
    }
    None
}

/// Detects the active terminal tab's current working directory using OSC 7, /proc filesystem, title, or prompt text.
pub fn detect_terminal_cwd(tab: &OpenTab) -> Option<String> {
    // 1. Direct OSC 7 path (if shell supports OSC 7)
    if let Some(ref p) = *tab.session.last_osc7_path.lock()
        && !p.trim().is_empty() {
            return Some(p.trim().to_string());
        }

    // 2. If local shell on Unix/WSL, check /proc/{pid}/cwd (or lsof on macOS)
    #[cfg(all(unix, not(target_os = "macos")))]
    if !tab.session.is_ssh
        && let Some(pid) = tab.session.child_pid
            && let Ok(target) = std::fs::read_link(format!("/proc/{}/cwd", pid))
                && target.is_dir() {
                    return Some(target.to_string_lossy().to_string());
                }
    #[cfg(target_os = "macos")]
    if !tab.session.is_ssh {
        if let Some(pid) = tab.session.child_pid {
            if let Ok(out) = std::process::Command::new("lsof")
                .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
                .output()
            {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout);
                    for line in s.lines() {
                        if let Some(p) = line.strip_prefix('n') {
                            let path = std::path::PathBuf::from(p.trim());
                            if path.is_dir() {
                                return Some(p.trim().to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Inspect terminal title (set by bash/zsh/fish via OSC 0/2 e.g. "user@host: /path" or "/path")
    let title = tab.session.title.lock().clone();
    let clean_title = title.trim();
    if !clean_title.is_empty()
        && let Some(extracted) = extract_cwd_from_title(clean_title) {
            return Some(extracted);
        }

    // 4. Inspect active prompt on the terminal screen
    let screen_text = tab.session.parser.lock().screen().contents();
    extract_cwd_from_screen(&screen_text)
}

pub struct OpenTab {
    pub id: String,
    pub title: String,
    pub session: PtySession,
    pub session_def: Option<Session>,
    pub custom_cmd: Option<String>,
    pub workdir: Option<String>,
    pub telemetry: TabTelemetry,
    pub last_synced_cwd: Option<String>,
    pub last_sftp_path: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SplitMode {
    Single,
    Horizontal,
    Vertical,
    Grid2x2,
}

pub struct RustyBoxApp {
    // Session state
    storage: StorageManager,
    sessions: Vec<Session>,
    session_search: String,
    // Open tabs
    open_tabs: Vec<OpenTab>,
    active_tab_idx: usize,
    split_mode: SplitMode,
    // Multi-Execution
    multi_exec_enabled: bool,
    broadcast_tx: Sender<Vec<u8>>,
    broadcast_rx: Receiver<Vec<u8>>,
    // Components
    explorer: FileExplorer,
    network_tools: NetworkTools,
    tunnel_manager: TunnelManager,
    // Dialogs & Modals
    new_session_dialog: NewSessionDialog,
    show_sftp_sidebar: bool,
    sidebar_tab: usize, // 0: Sessions, 1: SFTP Explorer
    show_network_tools: bool,
    net_tools_tab: usize, // 0: Port Scan, 1: Subnet Scan, 2: Ping, 3: Netstat
    show_tunnels: bool,
    tunnel_filter_mode: usize,
    editing_tunnel_idx: Option<usize>,
    tunnel_ssh_key_path: String,
    selected_session_fill: String,
    // Snippets Manager (Termius Snippet Library)
    snippets: Vec<crate::snippets::Snippet>,
    show_snippets: bool,
    snippet_search: String,
    snippet_category_filter: String,
    show_snippet_edit: bool,
    editing_snippet_idx: Option<usize>,
    snippet_form_name: String,
    snippet_form_command: String,
    snippet_form_category: String,
    snippet_form_desc: String,
    show_snippet_vars: bool,
    active_var_snippet: Option<crate::snippets::Snippet>,
    active_var_fields: Vec<(String, String)>,
    active_var_is_run: bool,
    // Auto-Highlight Keyword Rules (ZOC Terminal Feature)
    highlight_rules: Vec<crate::terminal::HighlightRule>,
    highlight_rules_enabled: bool,
    show_highlight_modal: bool,
    highlight_kw_input: String,
    highlight_color_idx: usize,
    highlight_whole_word: bool,
    highlight_match_case: bool,
    editing_highlight_idx: Option<usize>,
    highlight_preview_text: String,
    show_vault: bool,
    show_about: bool,
    show_services_modal: bool,
    services_tab: usize, // 0: HTTP, 1: Syslog
    // Master Password Vault
    master_password: String,
    master_password_confirm: String,
    vault_status: Option<(String, bool)>,
    // Terminal Customization, Theme & Search
    language: AppLanguage,
    theme: TerminalTheme,
    ui_scale: f32,
    font_size: f32,
    terminal_font_family: String,
    search_open: bool,
    search_query: String,
    // Multi-line paste confirmation (MobaXterm TFORMCHECKCLIPBOARD)
    pending_paste_text: Option<String>,
    paste_protection_enabled: bool,
    copy_on_select: bool,
    auto_log_sessions: bool,
    default_log_directory: String,
    // Settings & Hotkeys Dialogs (MobaXterm TFORMPARAMS & TFORMHOTKEYS)
    show_settings_dialog: bool,
    show_hotkeys_dialog: bool,
    // Password Settings Dialog (MobaXterm TFormManagePasswords)
    show_manage_passwords: bool,
    manage_passwords_search: String,
    manage_passwords_show_all: bool,
    manage_passwords_save_mode: usize,
    manage_passwords_save_ssh_keys: bool,
    manage_passwords_tab: usize,
    manage_passwords_unmasked_ids: Vec<String>,
    // Shared Credentials (MobaXterm User Credentials Profiles)
    credentials: Vec<Credential>,
    show_new_cred_modal: bool,
    new_cred_name: String,
    new_cred_user: String,
    new_cred_password: String,
    // Quick Macros (MobaXterm TFORMMANAGEMACROS)
    quick_macros: Vec<(String, String)>,
    show_macro_manager: bool,
    new_macro_name: String,
    new_macro_cmd: String,
    // Quick Connect & Home Tab
    quick_connect_input: String,
    home_session_filter: String,
    is_home_active: bool,
    scroll_active_tab_into_view: bool,
    // Live System Telemetry Dashboard
    last_telemetry_time: std::time::Instant,
    local_telemetry: TabTelemetry,
    last_local_net_bytes: Option<(u64, u64)>,
    last_local_net_time: Option<std::time::Instant>,
    // Context Actions & Modals
    selected_sidebar_session_id: Option<String>,
    last_synced_tab_id: Option<String>,
    last_synced_is_home: bool,
    last_synced_tab_idx: usize,
    is_maximized_requested: bool,
    connect_as_target: Option<(Session, String)>,
    rename_session_target: Option<(String, String)>,
    rename_folder_target: Option<(String, String)>,
    rename_tab_target: Option<(usize, String)>,
    tab_context_menu: Option<(usize, egui::Pos2)>,
    status_toast: Option<(String, std::time::Instant)>,
    // SSH Key Generator (RustyBox KeyGen)
    show_keygen: bool,
    keygen_type: usize, // 0: Ed25519, 1: RSA 4096
    keygen_comment: String,
    keygen_public: String,
    keygen_private: String,
    keygen_fingerprint: String,
    // Random Password Generator (MobaXterm TFormPassGen)
    show_pwdgen: bool,
    pwdgen_len: usize,
    pwdgen_upper: bool,
    pwdgen_lower: bool,
    pwdgen_digits: bool,
    pwdgen_symbols: bool,
    pwdgen_output: String,
    // File Comparison (RustyBox Diff / MobaDiff)
    show_diff: bool,
    diff_text_a: String,
    diff_text_b: String,
    diff_result: Vec<String>,
    // RustyBox Apt Package Manager
    show_mobapt: bool,
    mobapt_search: String,
    // SSH Tunnels & New Tunnel Creation
    show_tunnel_edit: bool,
    tunnel_edit_mode: usize,
    new_tunnel_name: String,
    new_tunnel_local_port: u16,
    tunnel_ssh_srv: String,
    tunnel_ssh_port: u16,
    tunnel_ssh_user: String,
    new_tunnel_remote_host: String,
    new_tunnel_remote_port: u16,
    // Configuration tabs
    settings_tab: usize,
    // MobaXterm Session Import Dialog
    show_import_dialog: bool,
    import_raw_text: String,
    import_file_path: String,
    import_default_folder: String,
    import_status_msg: Option<(String, bool)>,
    focus_search: bool,
    // Tokio Runtime
    tokio_runtime: tokio::runtime::Runtime,
}

impl RustyBoxApp {
    pub fn is_any_modal_open(&self) -> bool {
        self.show_network_tools
            || self.show_services_modal
            || self.show_tunnels
            || self.show_tunnel_edit
            || self.show_keygen
            || self.show_pwdgen
            || self.show_diff
            || self.show_mobapt
            || self.show_macro_manager
            || self.show_vault
            || self.show_settings_dialog
            || self.show_hotkeys_dialog
            || self.show_about
            || self.show_manage_passwords
            || self.show_import_dialog
            || self.new_session_dialog.is_open
            || self.connect_as_target.is_some()
            || self.rename_session_target.is_some()
            || self.rename_folder_target.is_some()
            || self.pending_paste_text.is_some()
            || self.show_new_cred_modal
            || self.show_highlight_modal
            || self.explorer.is_any_modal_open()
    }

    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let storage = StorageManager::new();
        let config = storage.load_config();
        let terminal_font_family = if !config.terminal_font_family.is_empty() {
            config.terminal_font_family.clone()
        } else {
            "noto_sans_mono".to_string()
        };

        // Configure embedded Unicode fonts for full Vietnamese diacritics & international symbols
        crate::terminal::fonts::setup_terminal_fonts(&cc.egui_ctx, &terminal_font_family);
        crate::register_ui_repaint_context(cc.egui_ctx.clone());

        let mut sessions = config.sessions.clone();
        let credentials = config.credentials.clone();
        let ui_scale = if config.ui_scale >= 0.7 && config.ui_scale <= 2.5 { config.ui_scale } else { 1.0 };
        let font_size = if config.font_size >= 8.0 && config.font_size <= 36.0 { config.font_size } else { 14.0 };
        let theme = TerminalTheme::from_name(&config.theme_name).unwrap_or(TerminalTheme::RustyBoxDark);
        let paste_protection_enabled = config.paste_protection_enabled;
        let copy_on_select = config.copy_on_select;
        let (broadcast_tx, broadcast_rx) = channel();

        // Ensure every session has a unique UUID (auto-repair any historical duplicate IDs)
        let mut seen_ids = std::collections::HashSet::new();
        let mut id_repaired = false;
        for s in &mut sessions {
            if s.id.is_empty() || seen_ids.contains(&s.id) {
                s.id = uuid::Uuid::new_v4().to_string();
                id_repaired = true;
            }
            seen_ids.insert(s.id.clone());
        }
        if id_repaired {
            let _ = storage.save_sessions(&sessions);
        }

        let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("Failed to initialize Tokio runtime");

        let default_macros = vec![
            ("htop".into(), "htop\n".into()),
            ("docker ps".into(), "docker ps\n".into()),
            ("df -h".into(), "df -h\n".into()),
            ("free -m".into(), "free -m\n".into()),
            ("netstat".into(), "netstat -tlpn\n".into()),
            ("systemctl".into(), "systemctl status\n".into()),
            ("uptime".into(), "uptime\n".into()),
            ("clear".into(), "clear\n".into()),
        ];

        let mut explorer = FileExplorer::new();
        explorer.remote_monitoring_enabled = config.remote_monitoring_enabled;
        explorer.follow_terminal_folder = config.follow_terminal_folder;
        let quick_macros = if config.quick_macros.is_empty() {
            default_macros
        } else {
            config.quick_macros.clone()
        };

        // Load SFTP bookmarks from storage
        explorer.bookmarks = config.sftp_bookmarks;

        let mut app = Self {
            storage,
            sessions,
            session_search: String::new(),
            open_tabs: Vec::new(),
            active_tab_idx: 0,
            split_mode: SplitMode::Single,
            multi_exec_enabled: false,
            broadcast_tx,
            broadcast_rx,
            explorer,
            network_tools: NetworkTools::new(),
            tunnel_manager: TunnelManager::with_tunnels(config.tunnels.clone()),
            new_session_dialog: NewSessionDialog::new(),
            show_sftp_sidebar: true,
            sidebar_tab: 0,
            show_network_tools: false,
            net_tools_tab: 0,
            show_tunnels: false,
            tunnel_filter_mode: 0,
            editing_tunnel_idx: None,
            tunnel_ssh_key_path: String::new(),
            selected_session_fill: String::new(),
            snippets: config.snippets.clone(),
            show_snippets: false,
            snippet_search: String::new(),
            snippet_category_filter: "All".to_string(),
            show_snippet_edit: false,
            editing_snippet_idx: None,
            snippet_form_name: String::new(),
            snippet_form_command: String::new(),
            snippet_form_category: "Docker".to_string(),
            snippet_form_desc: String::new(),
            show_snippet_vars: false,
            active_var_snippet: None,
            active_var_fields: Vec::new(),
            active_var_is_run: true,
            highlight_rules: config.highlight_rules.clone(),
            highlight_rules_enabled: config.highlight_rules_enabled,
            show_highlight_modal: false,
            highlight_kw_input: String::new(),
            highlight_color_idx: 0,
            highlight_whole_word: true,
            highlight_match_case: false,
            editing_highlight_idx: None,
            highlight_preview_text: "2026-11-05 14:30:00 [ERROR] Connection failed to 192.168.1.10: Connection refused\n2026-11-05 14:30:05 [WARN] Retry attempt 1/3 failed, retrying in 5s...\n2026-11-05 14:30:10 [SUCCESS] Connection established! Node status is running and active (127.0.0.1:8080).".to_string(),
            show_vault: false,
            show_about: false,
            show_services_modal: false,
            services_tab: 0,
            master_password: String::new(),
            master_password_confirm: String::new(),
            vault_status: None,
            language: config.language,
            theme,
            ui_scale,
            font_size,
            terminal_font_family,
            search_open: false,
            search_query: String::new(),
            pending_paste_text: None,
            paste_protection_enabled,
            copy_on_select,
            auto_log_sessions: config.auto_log_sessions,
            default_log_directory: config.default_log_directory,
            show_settings_dialog: false,
            show_hotkeys_dialog: false,
            show_manage_passwords: false,
            manage_passwords_search: String::new(),
            manage_passwords_show_all: false,
            manage_passwords_save_mode: (config.password_save_mode as usize).min(2),
            manage_passwords_save_ssh_keys: config.save_key_passphrases,
            manage_passwords_tab: 0,
            manage_passwords_unmasked_ids: Vec::new(),
            credentials,
            show_new_cred_modal: false,
            new_cred_name: String::new(),
            new_cred_user: String::new(),
            new_cred_password: String::new(),
            quick_macros,
            show_macro_manager: false,
            new_macro_name: String::new(),
            new_macro_cmd: String::new(),
            quick_connect_input: String::new(),
            home_session_filter: String::new(),
            is_home_active: false,
            scroll_active_tab_into_view: false,
            last_telemetry_time: std::time::Instant::now() - std::time::Duration::from_secs(10),
            local_telemetry: TabTelemetry::new_local(),
            last_local_net_bytes: None,
            last_local_net_time: None,
            selected_sidebar_session_id: None,
            last_synced_tab_id: None,
            last_synced_is_home: true,
            last_synced_tab_idx: 0,
            is_maximized_requested: false,
            connect_as_target: None,
            rename_session_target: None,
            rename_folder_target: None,
            rename_tab_target: None,
            tab_context_menu: None,
            status_toast: None,
            show_keygen: false,
            keygen_type: 0,
            keygen_comment: "rustybox@key".into(),
            keygen_public: String::new(),
            keygen_private: String::new(),
            keygen_fingerprint: String::new(),
            show_pwdgen: false,
            pwdgen_len: 16,
            pwdgen_upper: true,
            pwdgen_lower: true,
            pwdgen_digits: true,
            pwdgen_symbols: true,
            pwdgen_output: String::new(),
            show_diff: false,
            diff_text_a: String::new(),
            diff_text_b: String::new(),
            diff_result: Vec::new(),
            show_mobapt: false,
            mobapt_search: String::new(),
            show_tunnel_edit: false,
            tunnel_edit_mode: 0,
            new_tunnel_name: String::new(),
            new_tunnel_local_port: 8080,
            tunnel_ssh_srv: "127.0.0.1".into(),
            tunnel_ssh_port: 22,
            tunnel_ssh_user: "root".into(),
            new_tunnel_remote_host: "127.0.0.1".into(),
            new_tunnel_remote_port: 80,
            settings_tab: 0,
            show_import_dialog: false,
            import_raw_text: String::new(),
            import_file_path: String::new(),
            import_default_folder: "Imported".into(),
            import_status_msg: None,
            focus_search: false,
            tokio_runtime,
        };

        // Configure modern sleek dark theme (high contrast, elevated surfaces & distinct borders)
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(15, 18, 26);
        visuals.window_fill = Color32::from_rgb(26, 32, 46); // Elevated surface for modals/windows
        visuals.extreme_bg_color = Color32::from_rgb(11, 15, 23);
        visuals.window_stroke = egui::Stroke::new(1.5_f32, Color32::from_rgb(59, 130, 246)); // Crisp vibrant border
        visuals.window_shadow.blur = 24.0;
        visuals.window_shadow.spread = 4.0;
        visuals.window_shadow.color = Color32::from_black_alpha(200);
        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(20, 25, 36);
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, Color32::from_rgb(51, 65, 85));
        visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, Color32::from_rgb(226, 232, 240));
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(18, 24, 38);
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, Color32::from_rgb(71, 85, 105));
        visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, Color32::from_rgb(226, 232, 240));
        visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(30, 41, 59);
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.5_f32, Color32::from_rgb(56, 189, 248));
        visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, Color32::WHITE);
        visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);
        visuals.widgets.active.bg_fill = Color32::from_rgb(37, 99, 235);
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.5_f32, Color32::from_rgb(96, 165, 250));
        visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, Color32::WHITE);
        visuals.widgets.active.rounding = egui::Rounding::same(6.0);
        visuals.window_rounding = egui::Rounding::same(10.0);

        // Enforce dark theme across all platforms regardless of OS system Light/Dark appearance
        cc.egui_ctx.set_theme(egui::ThemePreference::Dark);
        cc.egui_ctx.set_visuals_of(egui::Theme::Dark, visuals.clone());
        cc.egui_ctx.set_visuals_of(egui::Theme::Light, visuals.clone());
        cc.egui_ctx.set_visuals(visuals);
        cc.egui_ctx.set_zoom_factor(ui_scale);

        // Note: Do not spawn a background local terminal on startup to avoid
        // any brief console flash (conhost.exe) on Windows. The user starts at Home Dashboard.
        app.is_home_active = true;

        // Auto-prompt Master Password Vault on startup if vault is configured and locked
        if app.storage.is_vault_configured() && !app.storage.is_vault_unlocked() {
            app.show_vault = true;
        }

        if std::env::var("RUSTYBOX_QA_TERMINAL_ACTIVE").is_ok() {
            app.is_home_active = false;
            app.active_tab_idx = 0;
        }

        // QA Hook for automated verification
        if let Ok(view) = std::env::var("RUSTYBOX_QA_VIEW") {
            match view.as_str() {
                "passwords" => {
                    for s in &mut app.sessions {
                        if s.password.is_none() {
                            s.password = Some("MySecretP@ss2026!".into());
                        }
                    }
                    app.show_manage_passwords = true;
                }
                "passwords_unmasked" => {
                    for s in &mut app.sessions {
                        if s.password.is_none() {
                            s.password = Some("MySecretP@ss2026!".into());
                        }
                    }
                    app.manage_passwords_show_all = true;
                    app.show_manage_passwords = true;
                }
                "passwords_filtered" => {
                    for s in &mut app.sessions {
                        if s.password.is_none() {
                            s.password = Some("MySecretP@ss2026!".into());
                        }
                    }
                    app.manage_passwords_search = "192.168".into();
                    app.manage_passwords_show_all = true;
                    app.show_manage_passwords = true;
                }
                "vault" => {
                    app.show_vault = true;
                }
                "snippets" => {
                    app.show_snippets = true;
                }
                "tunnels" => {
                    app.show_tunnels = true;
                }
                "highlight" => {
                    app.show_highlight_modal = true;
                }
                "diff" => {
                    app.show_diff = true;
                    app.diff_text_a = "server_name example.com;\nlisten 80;\nlocation / {\n    proxy_pass http://127.0.0.1:3000;\n}".to_string();
                    app.diff_text_b = "server_name example.com;\nlisten 443 ssl;\nlocation / {\n    proxy_pass http://127.0.0.1:8080;\n    proxy_set_header Host $host;\n}".to_string();
                }
                "sftp" => {
                    app.show_sftp_sidebar = true;
                    app.sidebar_tab = 1;
                }
                "session_new" => {
                    app.new_session_dialog.open_for_new();
                }
                _ => {}
            }
        }

        app
    }

    pub fn execute_terminal_command(&mut self, cmd: &str) {
        if !self.is_home_active && !self.open_tabs.is_empty() {
            let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
            let _ = self.open_tabs[idx].session.write_str(cmd);
        } else {
            self.spawn_local_terminal("Local Terminal", None, None);
            self.is_home_active = false;
            if !self.open_tabs.is_empty() {
                let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
                let _ = self.open_tabs[idx].session.write_str(cmd);
            }
        }
    }

    pub fn spawn_local_terminal(
        &mut self,
        title: &str,
        shell: Option<&str>,
        workdir: Option<&str>,
    ) {
        self.spawn_local_terminal_ext(title, shell, workdir, None);
    }

    fn resolve_session_log_path(&self, s: &Session) -> Option<std::path::PathBuf> {
        let should_log = s.log_terminal_output || self.auto_log_sessions;
        if !should_log {
            return None;
        }
        let base_dir = if !s.log_directory.trim().is_empty() {
            std::path::PathBuf::from(s.log_directory.trim())
        } else if !self.default_log_directory.trim().is_empty() {
            std::path::PathBuf::from(self.default_log_directory.trim())
        } else {
            self.storage.data_dir().join("logs")
        };
        // Organize logs into daily folders (YYYY-MM-DD)
        let today_str = chrono::Local::now().format("%Y-%m-%d").to_string();
        let daily_dir = base_dir.join(&today_str);
        let _ = std::fs::create_dir_all(&daily_dir);

        // Prune log folders older than 5 days
        Self::cleanup_old_log_folders(&base_dir, 5);

        let safe_name: String = s
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let filename = format!(
            "{}_{}.log",
            if safe_name.is_empty() { "session" } else { &safe_name },
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        Some(daily_dir.join(filename))
    }

    fn resolve_default_log_path(&self, title: &str) -> Option<std::path::PathBuf> {
        if !self.auto_log_sessions {
            return None;
        }
        let base_dir = if !self.default_log_directory.trim().is_empty() {
            std::path::PathBuf::from(self.default_log_directory.trim())
        } else {
            self.storage.data_dir().join("logs")
        };
        // Organize logs into daily folders (YYYY-MM-DD)
        let today_str = chrono::Local::now().format("%Y-%m-%d").to_string();
        let daily_dir = base_dir.join(&today_str);
        let _ = std::fs::create_dir_all(&daily_dir);

        // Prune log folders older than 5 days
        Self::cleanup_old_log_folders(&base_dir, 5);

        let safe_title: String = title
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let filename = format!(
            "{}_{}.log",
            if safe_title.is_empty() { "terminal" } else { &safe_title },
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        Some(daily_dir.join(filename))
    }

    fn cleanup_old_log_folders(base_dir: &std::path::Path, max_days: u32) {
        if let Ok(entries) = std::fs::read_dir(base_dir) {
            let mut date_dirs = Vec::new();
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type()
                    && file_type.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        // Match YYYY-MM-DD format
                        if chrono::NaiveDate::parse_from_str(&name, "%Y-%m-%d").is_ok() {
                            date_dirs.push((name, entry.path()));
                        }
                    }
            }
            // Sort ascending by date string (oldest first)
            date_dirs.sort_by(|a, b| a.0.cmp(&b.0));
            // Keep at most max_days newest folders, remove older ones
            if date_dirs.len() > max_days as usize {
                let to_remove = date_dirs.len() - max_days as usize;
                for (_, path) in date_dirs.into_iter().take(to_remove) {
                    let _ = std::fs::remove_dir_all(path);
                }
            }
        }
    }

    fn persist_preferences(&self) -> Result<(), String> {
        self.storage.save_preferences(
            self.ui_scale,
            self.font_size,
            &self.terminal_font_family,
            self.theme.name(),
            self.paste_protection_enabled,
            self.copy_on_select,
        )
    }

    fn build_ssh_spawn_config(&self, s: &Session, tunnel_x11: bool) -> (Option<String>, crate::terminal::pty_session::SshSpawnConfig) {
        let effective_jump = if let SessionType::Ssh { ref jump_host, .. } = s.session_type {
            jump_host.clone().filter(|j| !j.trim().is_empty())
        } else {
            None
        }
        .or_else(|| {
            if s.use_ssh_gateway && !s.gateway_host.trim().is_empty() {
                let port = if s.gateway_port == 0 { 22 } else { s.gateway_port };
                if s.gateway_user.trim().is_empty() {
                    Some(format!("{}:{}", s.gateway_host.trim(), port))
                } else {
                    Some(format!("{}@{}:{}", s.gateway_user.trim(), s.gateway_host.trim(), port))
                }
            } else {
                None
            }
        });

        let cfg = crate::terminal::pty_session::SshSpawnConfig {
            compression: s.ssh_compression,
            keepalive: s.ssh_keepalive,
            tunnel_x11,
            remote_command: if s.remote_command.trim().is_empty() {
                None
            } else {
                Some(s.remote_command.trim().to_string())
            },
            do_not_exit_after_cmd: s.do_not_exit_after_cmd,
            gateway_key: if s.use_ssh_gateway && !s.gateway_key.trim().is_empty() {
                Some(s.gateway_key.trim().to_string())
            } else {
                None
            },
            log_file_path: self.resolve_session_log_path(s),
        };
        (effective_jump, cfg)
    }

    fn save_current_tab_sftp_path(&mut self) {
        if self.explorer.is_remote
            && self.explorer.is_connected
            && let Some(ref prev_id) = self.last_synced_tab_id
            && let Some(ref active_label) = self.explorer.remote_label
        {
            let cur_sftp = self.explorer.current_path.to_string_lossy().to_string();
            if let Some(prev_tab) = self.open_tabs.iter_mut().find(|t| &t.id == prev_id) {
                let tab_matches_remote = prev_tab.session_def.as_ref().map(|s| {
                    if let SessionType::Ssh { ref host, port, ref user, .. } = s.session_type {
                        format!("{}@{}:{}", user, host, port) == *active_label
                    } else {
                        false
                    }
                }).unwrap_or(false);
                if tab_matches_remote {
                    prev_tab.last_sftp_path = Some(cur_sftp);
                }
            }
        }
    }

    /// Disconnects and removes any background SFTP sessions in `explorer.remote_sessions`
    /// that are no longer referenced by any open SSH tab.
    fn cleanup_unused_remote_sftp_sessions(&mut self) {
        let active_labels: std::collections::HashSet<String> = self
            .open_tabs
            .iter()
            .filter_map(|t| {
                t.session_def.as_ref().and_then(|s| {
                    if let SessionType::Ssh { ref host, port, ref user, .. } = s.session_type {
                        Some(format!("{}@{}:{}", user, host, port))
                    } else {
                        None
                    }
                })
            })
            .collect();

        let stale_labels: Vec<String> = self
            .explorer
            .remote_sessions
            .keys()
            .filter(|lbl| !active_labels.contains(*lbl))
            .cloned()
            .collect();

        for lbl in stale_labels {
            if let Some(sess) = self.explorer.remote_sessions.remove(&lbl) {
                sess.client.lock().disconnect();
            }
            if self.explorer.remote_label.as_deref() == Some(lbl.as_str()) {
                self.explorer.remote_label = None;
                self.explorer.remote_client = None;
                self.explorer.is_remote = false;
                self.explorer.is_connected = false;
                self.explorer.is_loading = false;
            }
        }
    }

    pub fn spawn_local_terminal_ext(
        &mut self,
        title: &str,
        shell: Option<&str>,
        workdir: Option<&str>,
        session_def: Option<Session>,
    ) {
        self.save_current_tab_sftp_path();
        self.is_home_active = false;
        let log_path = match session_def.as_ref() {
            Some(s) => self.resolve_session_log_path(s),
            None => self.resolve_default_log_path(title),
        };
        match PtySession::spawn_local_with_log(24, 80, shell, workdir, log_path) {
            Ok(session) => {
                let telemetry = match &session_def {
                    Some(s) if s.session_type.is_remote() => TabTelemetry::new_remote(s),
                    _ => TabTelemetry::new_local(),
                };
                let tab = OpenTab {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: title.to_string(),
                    session,
                    session_def: session_def.clone(),
                    custom_cmd: shell.map(|s| s.to_string()),
                    workdir: workdir.map(|w| w.to_string()),
                    telemetry,
                    last_synced_cwd: None,
                    last_sftp_path: None,
                };
                self.open_tabs.push(tab);
                self.active_tab_idx = self.open_tabs.len() - 1;
                self.last_synced_is_home = false;
                self.last_synced_tab_id = self.open_tabs.last().map(|t| t.id.clone());
                self.last_synced_tab_idx = self.active_tab_idx;
                self.sync_sidebar_with_active_tab();
                self.sidebar_tab = 0;
                self.scroll_active_tab_into_view = true;

                // Execute startup macro if configured
                if let Some(ref s) = session_def
                    && !s.startup_macro.is_empty() && s.startup_macro != "None" {
                        let cmd_to_run = if let Some((_, cmd)) = self.quick_macros.iter().find(|(name, _)| name == &s.startup_macro) {
                            cmd.clone()
                        } else {
                            format!("{}\n", s.startup_macro)
                        };
                        self.execute_macro(&cmd_to_run);
                    }
            }
            Err(e) => {
                eprintln!("Failed to spawn local terminal: {}", e);
            }
        }
    }

    pub fn record_session_connected(&mut self, s: &mut Session) {
        Session::record_in_list(&mut self.sessions, s);
        let _ = self.storage.save_sessions(&self.sessions);
    }

    pub fn spawn_ssh_terminal(&mut self, mut s: Session) {
        self.save_current_tab_sftp_path();
        self.is_home_active = false;
        self.record_session_connected(&mut s);
        self.selected_sidebar_session_id = Some(s.id.clone());
        if let SessionType::Ssh {
            ref host,
            port,
            ref user,
            ref key_path,
            tunnel_x11,
            ..
        } = s.session_type
        {
            let effective_password = s
                .password
                .as_deref()
                .filter(|p| !p.trim().is_empty())
                .map(|p| p.to_string())
                .or_else(|| {
                    self.credentials
                        .iter()
                        .find(|c| {
                            (!c.username.is_empty() && c.username == *user)
                                || (!c.name.is_empty() && c.name == s.name)
                        })
                        .map(|c| c.password.clone())
                        .filter(|p| !p.trim().is_empty())
                });

            let mut decrypted_pw_buf: Option<String> = None;
            let mut final_password_str: Option<String> = None;
            if let Some(pw) = effective_password {
                if is_encrypted(&pw) {
                    if self.storage.is_vault_unlocked() {
                        if let Some(key) = self.storage.vault_key()
                            && let Ok(dec) = decrypt_str(&key, &pw) {
                                decrypted_pw_buf = Some(dec);
                            }
                    } else {
                        self.show_vault = true;
                        self.vault_status = Some(("🔒 Master Password Vault is locked. Please unlock to auto-submit saved password.".into(), true));
                    }
                } else {
                    final_password_str = Some(pw);
                }
            }

            let final_password = decrypted_pw_buf.as_deref().or(final_password_str.as_deref());

            let (effective_jump, ssh_cfg) = self.build_ssh_spawn_config(&s, tunnel_x11);

            match PtySession::spawn_ssh_with_config(
                24,
                80,
                host,
                port,
                user,
                key_path.as_deref(),
                effective_jump.as_deref(),
                final_password,
                &ssh_cfg,
            ) {
                Ok(session) => {
                    let telemetry = TabTelemetry::new_remote(&s);
                    let tab = OpenTab {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: format!("SSH: {}", s.name),
                        session,
                        session_def: Some(s.clone()),
                        custom_cmd: None,
                        workdir: None,
                        telemetry,
                        last_synced_cwd: None,
                        last_sftp_path: None,
                    };
                    self.open_tabs.push(tab);
                    self.active_tab_idx = self.open_tabs.len() - 1;
                    self.sync_sidebar_with_active_tab();
                    if s.auto_sftp {
                        self.sidebar_tab = 1;
                        self.show_sftp_sidebar = true;
                    }
                    self.scroll_active_tab_into_view = true;

                    // Execute startup macro if configured
                    if !s.startup_macro.is_empty() && s.startup_macro != "None" {
                        let cmd_to_run = if let Some((_, cmd)) = self.quick_macros.iter().find(|(name, _)| name == &s.startup_macro) {
                            cmd.clone()
                        } else {
                            format!("{}\n", s.startup_macro)
                        };
                        self.execute_macro(&cmd_to_run);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to spawn SSH session: {}", e);
                }
            }
        }
    }

    pub fn check_and_sync_active_tab(&mut self) {
        let current_is_home = self.is_home_active || self.open_tabs.is_empty();
        let current_tab_id = if current_is_home {
            None
        } else {
            let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
            Some(self.open_tabs[idx].id.clone())
        };
        let current_idx = if current_is_home { 0 } else { self.active_tab_idx.min(self.open_tabs.len().saturating_sub(1)) };

        if self.last_synced_is_home != current_is_home
            || self.last_synced_tab_id != current_tab_id
            || self.last_synced_tab_idx != current_idx
        {
            // Save the current SFTP path on the outgoing tab before switching away
            if self.last_synced_tab_id != current_tab_id {
                self.save_current_tab_sftp_path();
            }
            self.last_synced_is_home = current_is_home;
            self.last_synced_tab_id = current_tab_id;
            self.last_synced_tab_idx = current_idx;
            self.sync_sidebar_with_active_tab();
        }
    }

    pub fn sync_sidebar_with_active_tab(&mut self) {
        let current_is_home = self.is_home_active || self.open_tabs.is_empty();
        let current_tab_id = if current_is_home {
            None
        } else {
            let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
            Some(self.open_tabs[idx].id.clone())
        };
        let current_idx = if current_is_home { 0 } else { self.active_tab_idx.min(self.open_tabs.len().saturating_sub(1)) };

        if self.last_synced_tab_id != current_tab_id {
            self.save_current_tab_sftp_path();
        }
        self.last_synced_is_home = current_is_home;
        self.last_synced_tab_id = current_tab_id;
        self.last_synced_tab_idx = current_idx;

        // Poll background SFTP events so status is fresh
        self.explorer.poll();
        if self.explorer.just_connected {
            self.explorer.just_connected = false;
        }

        if self.is_home_active || self.open_tabs.is_empty() {
            self.selected_sidebar_session_id = None;
            if self.open_tabs.is_empty() && (self.explorer.is_remote || !self.explorer.remote_sessions.is_empty()) {
                self.explorer.disconnect_all_remotes();
                self.explorer.switch_to_local();
            }
            return;
        }

        let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
        self.active_tab_idx = idx;

        // 1. Sync Sessions Tree in Left Sidebar
        let tab = &self.open_tabs[idx];
        if let Some(ref s) = tab.session_def {
            self.selected_sidebar_session_id = Some(s.id.clone());
        } else {
            self.selected_sidebar_session_id = self.sessions.iter()
                .find(|s| matches!(s.session_type, SessionType::LocalShell { .. }))
                .map(|s| s.id.clone());
        }

        // 2. Sync SFTP / File Explorer in Left Sidebar
        let tab = &mut self.open_tabs[idx];
        if tab.last_sftp_path.is_none() {
            tab.last_synced_cwd = None;
        }
        let is_ssh = tab.session_def.as_ref().map(|s| matches!(s.session_type, SessionType::Ssh { .. })).unwrap_or(false);
        let tab_def = tab.session_def.clone();
        let tab_workdir = tab.workdir.clone();
        let tab_last_sftp = tab.last_sftp_path.clone();

        if is_ssh {
            if let Some(ref s) = tab_def
                && let SessionType::Ssh {
                    ref host,
                    port,
                    ref user,
                    ref key_path,
                    ..
                } = s.session_type
                {
                    let effective_password = s
                        .password
                        .as_deref()
                        .filter(|p| !p.trim().is_empty())
                        .or_else(|| {
                            self.credentials
                                .iter()
                                .find(|c| {
                                    (!c.username.is_empty() && c.username == *user)
                                        || (!c.name.is_empty() && c.name == s.name)
                                })
                                .map(|c| c.password.as_str())
                                .filter(|p| !p.trim().is_empty())
                        });

                    let mut decrypted_pw_buf: Option<String> = None;
                    if let Some(pw) = effective_password
                        && is_encrypted(pw)
                            && self.storage.is_vault_unlocked()
                                && let Some(key) = self.storage.vault_key()
                                    && let Ok(dec) = decrypt_str(&key, pw) {
                                        decrypted_pw_buf = Some(dec);
                                    }

                    let final_password = if let Some(ref dec) = decrypted_pw_buf {
                        Some(dec.as_str())
                    } else {
                        effective_password
                    };

                    let target_label = format!("{}@{}:{}", user, host, port);
                    if self.explorer.is_remote && self.explorer.remote_label.as_deref() == Some(&target_label) && self.explorer.is_connected {
                        if let Some(ref p) = tab_last_sftp {
                            let target = std::path::PathBuf::from(p);
                            if self.explorer.current_path != target {
                                self.explorer.set_path(target);
                            }
                        } else if let Some(detected) = self.open_tabs.get(idx).and_then(detect_terminal_cwd) {
                            self.explorer.sync_terminal_cwd(&detected);
                        } else if let Some(ref w) = tab_workdir {
                            self.explorer.sync_terminal_cwd(w);
                        }
                    } else {
                        self.explorer.connect_remote(crate::sftp::remote::SftpTargetConfig {
                            host: host.clone(),
                            port,
                            user: user.clone(),
                            password: final_password.map(|p| p.to_string()),
                            key_path: key_path.clone(),
                            sudo_mode: false,
                            sudo_password: None,
                        });
                        if self.explorer.is_connected
                            && let Some(ref p) = tab_last_sftp
                        {
                            let target = std::path::PathBuf::from(p);
                            if self.explorer.current_path != target {
                                self.explorer.set_path(target);
                            }
                        }
                    }

                    if s.auto_sftp {
                        self.show_sftp_sidebar = true;
                    }
                }
        } else {
            // Local Terminal / WSL: switch explorer to local files without disconnecting SSH SFTP sessions
            if self.explorer.is_remote {
                self.explorer.switch_to_local();
            }
            let target_local_dir = self.open_tabs.get(idx)
                .and_then(detect_terminal_cwd)
                .or(tab_workdir)
                .map(std::path::PathBuf::from);

            if let Some(dir) = target_local_dir
                && dir.is_dir() && self.explorer.current_path != dir {
                    self.explorer.set_path(dir);
                }
        }

        self.sync_terminal_cwd_if_enabled();
    }

    pub fn sync_active_tab_sftp(&mut self) {
        self.sync_sidebar_with_active_tab();
    }

    pub fn restart_tab(&mut self, idx: usize) {
        let (session_def, custom_cmd, workdir) = match self.open_tabs.get(idx) {
            Some(t) => (t.session_def.clone(), t.custom_cmd.clone(), t.workdir.clone()),
            None => return,
        };

        if let Some(ref s) = session_def {
            if let SessionType::Ssh {
                ref host,
                port,
                ref user,
                ref key_path,
                tunnel_x11,
                ..
            } = s.session_type
            {
                let mut effective_password = s
                    .password
                    .as_deref()
                    .filter(|p| !p.trim().is_empty())
                    .map(|p| p.to_string())
                    .or_else(|| {
                        self.credentials
                            .iter()
                            .find(|c| {
                                (!c.username.is_empty() && c.username == *user)
                                    || (!c.name.is_empty() && c.name == s.name)
                            })
                            .map(|c| c.password.clone())
                            .filter(|p| !p.trim().is_empty())
                    });

                let mut decrypted_pw_buf: Option<String> = None;
                if let Some(ref pw) = effective_password
                    && is_encrypted(pw) {
                        if self.storage.is_vault_unlocked() {
                            if let Some(key) = self.storage.vault_key()
                                && let Ok(dec) = decrypt_str(&key, pw) {
                                    decrypted_pw_buf = Some(dec);
                                }
                        } else {
                            self.show_vault = true;
                            self.vault_status = Some(("🔒 Master Password Vault is locked. Please unlock to auto-submit saved password.".into(), true));
                            effective_password = None;
                        }
                    }

                let final_password = if let Some(ref dec) = decrypted_pw_buf {
                    Some(dec.as_str())
                } else {
                    effective_password.as_deref()
                };

                let (effective_jump, ssh_cfg) = self.build_ssh_spawn_config(s, tunnel_x11);

                let sftp_reconnect_cfg = crate::sftp::remote::SftpTargetConfig {
                    host: host.clone(),
                    port,
                    user: user.clone(),
                    password: final_password.map(|p| p.to_string()),
                    key_path: key_path.clone(),
                    sudo_mode: false,
                    sudo_password: None,
                };

                if let Ok(session) = PtySession::spawn_ssh_with_config(
                    24,
                    80,
                    host,
                    port,
                    user,
                    key_path.as_deref(),
                    effective_jump.as_deref(),
                    final_password,
                    &ssh_cfg,
                ) {
                    if let Some(tab) = self.open_tabs.get_mut(idx) {
                        tab.session = session;
                        tab.telemetry.is_connected = true;
                        tab.telemetry.last_updated = std::time::Instant::now();
                    }
                    // Automatically re-establish SFTP session if this was an SSH tab
                    self.explorer.force_reconnect_remote(sftp_reconnect_cfg);
                }
            }
        } else {
            let log_path = self.resolve_default_log_path("terminal");
            if let Ok(session) = PtySession::spawn_local_with_log(
                24,
                80,
                custom_cmd.as_deref(),
                workdir.as_deref(),
                log_path,
            )
                && let Some(tab) = self.open_tabs.get_mut(idx) {
                    tab.session = session;
                    tab.telemetry.is_connected = true;
                    tab.telemetry.last_updated = std::time::Instant::now();
                }
        }
    }

    pub fn launch_generic_session(&mut self, mut s: Session) {
        self.is_home_active = false;
        if !matches!(s.session_type, SessionType::Ssh { .. }) {
            self.record_session_connected(&mut s);
        }
        self.selected_sidebar_session_id = Some(s.id.clone());
        match s.session_type {
            SessionType::LocalShell { ref custom_shell, ref working_dir } => {
                self.spawn_local_terminal_ext(&s.name, custom_shell.as_deref(), working_dir.as_deref(), Some(s.clone()));
            }
            SessionType::Ssh { .. } => {
                self.spawn_ssh_terminal(s);
            }
            SessionType::Telnet { ref host, port } => {
                let cmd = format!("telnet {} {}", host, port);
                self.spawn_local_terminal_ext(&format!("Telnet: {}", host), Some(&cmd), None, Some(s.clone()));
            }
            SessionType::Serial { ref port_name, baud_rate } => {
                let cmd = format!("screen {} {}", port_name, baud_rate);
                self.spawn_local_terminal_ext(&format!("Serial: {}", port_name), Some(&cmd), None, Some(s.clone()));
            }
            SessionType::Rdp { ref host, port, .. } => {
                // Open system RDP client
                #[cfg(target_os = "windows")]
                {
                    let _ = std::process::Command::new("mstsc")
                        .arg(format!("/v:{}:{}", host, port))
                        .spawn();
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = std::process::Command::new("xfreerdp")
                        .arg(format!("/v:{}:{}", host, port))
                        .spawn();
                }
            }
            SessionType::Vnc { ref host, port } => {
                #[cfg(target_os = "windows")]
                {
                    let _ = std::process::Command::new("vncviewer")
                        .arg(format!("{}:{}", host, port))
                        .spawn();
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = std::process::Command::new("vncviewer")
                        .arg(format!("{}:{}", host, port))
                        .spawn();
                }
            }
            SessionType::Ftp { .. } => {
                self.show_sftp_sidebar = true;
                self.sidebar_tab = 1;
            }
            SessionType::Wsl { ref distro, ref user, ref working_dir } => {
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = distro;
                    let _ = user;
                    // Running natively on Linux/Ubuntu: launch default bash or login as user
                    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
                    self.spawn_local_terminal_ext(&s.name, Some(&shell), working_dir.as_deref(), Some(s.clone()));
                }
                #[cfg(target_os = "windows")]
                {
                    let mut cmd = if distro.is_empty() {
                        "wsl".to_string()
                    } else {
                        format!("wsl -d {}", distro)
                    };
                    if let Some(u) = user
                        && !u.is_empty()
                    {
                        cmd.push_str(&format!(" -u {}", u));
                    }
                    self.spawn_local_terminal_ext(&s.name, Some(&cmd), working_dir.as_deref(), Some(s.clone()));
                }
            }
        }
    }

    pub fn execute_macro(&mut self, cmd: &str) {
        if let Some(tab) = self.open_tabs.get_mut(self.active_tab_idx) {
            let bytes = cmd.as_bytes().to_vec();
            let _ = tab.session.write_bytes(&bytes);
            if self.multi_exec_enabled {
                let _ = self.broadcast_tx.send(bytes);
            }
        }
    }

    pub fn save_active_terminal_buffer(&self) {
        if let Some(tab) = self.open_tabs.get(self.active_tab_idx) {
            let mut parser = tab.session.parser.lock();
            let text = crate::terminal::widget::extract_all_terminal_text(parser.screen_mut());
            drop(parser);

            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Log file", &["log", "txt"])
                .save_file()
            {
                let _ = std::fs::write(path, text);
            }
        }
    }

    fn handle_multi_exec_broadcast(&mut self) {
        let mut all_bytes = Vec::new();
        while let Ok(bytes) = self.broadcast_rx.try_recv() {
            all_bytes.extend(bytes);
        }

        if !all_bytes.is_empty() && self.multi_exec_enabled {
            for (idx, tab) in self.open_tabs.iter_mut().enumerate() {
                if idx != self.active_tab_idx {
                    let _ = tab.session.write_bytes(&all_bytes);
                }
            }
        }
    }

    pub fn get_active_telemetry(&self) -> TabTelemetry {
        if !self.is_home_active && !self.open_tabs.is_empty() {
            let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
            if let Some(tab) = self.open_tabs.get(idx) {
                return tab.telemetry.clone();
            }
        }
        self.local_telemetry.clone()
    }

    fn update_telemetry(&mut self) {
        if self.explorer.just_connected {
            self.explorer.just_connected = false;
        }

        let elapsed = self.last_telemetry_time.elapsed();
        if elapsed < std::time::Duration::from_millis(1500) {
            return;
        }
        self.last_telemetry_time = std::time::Instant::now();

        // 1. Update local system telemetry
        crate::telemetry::collect_local_telemetry(
            &mut self.local_telemetry,
            &mut self.last_local_net_bytes,
            &mut self.last_local_net_time,
        );

        // 2. Update telemetry for each open tab
        for tab in self.open_tabs.iter_mut() {
            let is_alive = tab.session.is_alive();
            tab.telemetry.is_connected = is_alive;

            let is_defined_remote = tab
                .session_def
                .as_ref()
                .map(|s| s.session_type.is_remote())
                .unwrap_or(false);

            if is_defined_remote {
                tab.telemetry.is_remote = true;
                if let Some(ref s) = tab.session_def {
                    let (h, u) = s.session_type.remote_host_and_user();
                    tab.telemetry.host = if !s.name.is_empty() { s.name.clone() } else { h.clone() };
                    tab.telemetry.user = if !u.is_empty() { u.clone() } else { "root".into() };

                    if !is_alive {
                        tab.telemetry.uptime = Some("Disconnected".into());
                        tab.telemetry.cpu_pct = None;
                        tab.telemetry.net_rate = None;
                    } else {
                        let target_label = format!("{}@{}:{}", u, h, s.session_type.port().unwrap_or(22));
                        let remote_metrics = self.explorer.remote_sessions.get(&target_label)
                            .and_then(|sess| sess.remote_telemetry.clone())
                            .or_else(|| {
                                self.explorer.remote_sessions.values()
                                    .find(|sess| sess.config.host.eq_ignore_ascii_case(&h) && sess.config.user == u)
                                    .and_then(|sess| sess.remote_telemetry.clone())
                            })
                            .or_else(|| self.explorer.get_active_telemetry());

                        if let Some(m) = remote_metrics {
                            tab.telemetry.apply_metrics(&m);
                        }
                        if let Some((_used, _total, pct)) = self.explorer.remote_disk_stats
                            && tab.telemetry.disk_pct.is_none() {
                                tab.telemetry.disk_pct = Some(pct.round() as u32);
                            }
                    }
                }
            } else {
                // Local tab mirrors fresh local telemetry
                tab.telemetry.is_remote = false;
                tab.telemetry.cpu_pct = self.local_telemetry.cpu_pct;
                tab.telemetry.ram_used_gb = self.local_telemetry.ram_used_gb;
                tab.telemetry.ram_total_gb = self.local_telemetry.ram_total_gb;
                tab.telemetry.ram_pct = self.local_telemetry.ram_pct;
                tab.telemetry.uptime = self.local_telemetry.uptime.clone();
                tab.telemetry.uptime_secs = self.local_telemetry.uptime_secs;
                tab.telemetry.disk_pct = self.local_telemetry.disk_pct;
                tab.telemetry.cores = self.local_telemetry.cores;
                tab.telemetry.host = self.local_telemetry.host.clone();
                tab.telemetry.user = self.local_telemetry.user.clone();
                tab.telemetry.net_rate = self.local_telemetry.net_rate.clone();
            }
        }
    }

    /// Automatically syncs the File / SFTP Explorer path to the active terminal's current directory when "Follow terminal folder" is enabled.
    pub fn sync_terminal_cwd_if_enabled(&mut self) {
        if !self.explorer.follow_terminal_folder || self.is_home_active || self.open_tabs.is_empty() {
            return;
        }
        let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
        let tab = &mut self.open_tabs[idx];
        if let Some(detected_cwd) = detect_terminal_cwd(tab)
            && tab.last_synced_cwd.as_deref() != Some(&detected_cwd) {
                tab.last_synced_cwd = Some(detected_cwd.clone());
                self.explorer.sync_terminal_cwd(&detected_cwd);
            }
    }

    fn handle_quick_connect(&mut self) {
        let input = self.quick_connect_input.trim();
        if input.is_empty() {
            self.new_session_dialog.open_for_new();
            return;
        }

        if input.eq_ignore_ascii_case("cmd") || input.eq_ignore_ascii_case("bash") || input.eq_ignore_ascii_case("local") {
            self.spawn_local_terminal("Local Terminal", None, None);
            self.quick_connect_input.clear();
            self.is_home_active = false;
            return;
        }

        let (user, host, port) = if let Some((u, rest)) = input.split_once('@') {
            if let Some((h, p)) = rest.split_once(':') {
                (u.trim().to_string(), h.replace(['\r', '\n', '\t'], "").trim().to_string(), p.parse::<u16>().unwrap_or(22))
            } else {
                (u.trim().to_string(), rest.replace(['\r', '\n', '\t'], "").trim().to_string(), 22)
            }
        } else if let Some((h, p)) = input.split_once(':') {
            ("root".to_string(), h.replace(['\r', '\n', '\t'], "").trim().to_string(), p.parse::<u16>().unwrap_or(22))
        } else {
            ("root".to_string(), input.replace(['\r', '\n', '\t'], "").trim().to_string(), 22)
        };

        let sess = Session::new_ssh(&format!("{}@{}", user, host), "Quick Connect", &host, port, &user);
        self.launch_generic_session(sess);
        self.quick_connect_input.clear();
        self.is_home_active = false;
    }

    pub fn generate_ssh_key_pair(&mut self) {
        let tmp_path = format!("{}/rustybox_keygen_{}", std::env::temp_dir().display(), uuid::Uuid::new_v4());
        let (key_type_arg, bits_arg) = match self.keygen_type {
            1 => ("rsa", vec!["-b", "4096"]),
            _ => ("ed25519", vec![]),
        };
        let comment = if self.keygen_comment.trim().is_empty() {
            "rustybox@key".to_string()
        } else {
            self.keygen_comment.trim().to_string()
        };
        let mut cmd = std::process::Command::new("ssh-keygen");
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        cmd.arg("-t").arg(key_type_arg)
            .arg("-N").arg("")
            .arg("-C").arg(&comment)
            .arg("-f").arg(&tmp_path);
        for b in bits_arg { cmd.arg(b); }

        if let Ok(output) = cmd.output()
            && output.status.success() {
                let pub_file = format!("{}.pub", tmp_path);
                if let Ok(pub_content) = std::fs::read_to_string(&pub_file) {
                    self.keygen_public = pub_content.trim().to_string();
                }
                if let Ok(priv_content) = std::fs::read_to_string(&tmp_path) {
                    self.keygen_private = priv_content;
                }
                let mut fp_cmd = std::process::Command::new("ssh-keygen");
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::process::CommandExt;
                    fp_cmd.creation_flags(0x08000000);
                }
                fp_cmd.arg("-lf").arg(&pub_file);
                if let Ok(fp_out) = fp_cmd.output() {
                    self.keygen_fingerprint = String::from_utf8_lossy(&fp_out.stdout).trim().to_string();
                }
                let _ = std::fs::remove_file(&tmp_path);
                let _ = std::fs::remove_file(&pub_file);
                return;
            }
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(format!("{}.pub", tmp_path));
        // If ssh-keygen is unavailable, report clear error instead of generating cryptographically invalid fake keys
        self.keygen_public = "❌ Error: ssh-keygen command failed or is not available on this system.".to_string();
        self.keygen_private = "Please install OpenSSH client (ssh-keygen) to generate secure cryptographic key pairs.".to_string();
        self.keygen_fingerprint = "N/A".to_string();
    }

    pub fn generate_random_password(&mut self) {
        let mut charset = Vec::new();
        if self.pwdgen_upper { charset.extend_from_slice(b"ABCDEFGHJKLMNPQRSTUVWXYZ"); }
        if self.pwdgen_lower { charset.extend_from_slice(b"abcdefghijkmnopqrstuvwxyz"); }
        if self.pwdgen_digits { charset.extend_from_slice(b"23456789"); }
        if self.pwdgen_symbols { charset.extend_from_slice(b"!@#$%^&*()-_=+[]{}<>?"); }
        if charset.is_empty() {
            self.pwdgen_output = "Select at least 1 character set".into();
            return;
        }
        use aes_gcm::aead::rand_core::{OsRng, RngCore};
        let mut random_bytes = vec![0u8; self.pwdgen_len];
        OsRng.fill_bytes(&mut random_bytes);
        let mut res = Vec::with_capacity(self.pwdgen_len);
        for b in random_bytes {
            let idx = (b as usize) % charset.len();
            res.push(charset[idx] as char);
        }
        self.pwdgen_output = res.into_iter().collect();
    }

    pub fn compute_diff(&mut self) {
        self.diff_result.clear();
        let lines_a: Vec<&str> = self.diff_text_a.lines().collect();
        let lines_b: Vec<&str> = self.diff_text_b.lines().collect();
        let max_len = lines_a.len().max(lines_b.len());
        for i in 0..max_len {
            let a = lines_a.get(i).copied().unwrap_or("");
            let b = lines_b.get(i).copied().unwrap_or("");
            if a == b {
                self.diff_result.push(format!("  {}", a));
            } else {
                if !a.is_empty() {
                    self.diff_result.push(format!("- {}", a));
                }
                if !b.is_empty() {
                    self.diff_result.push(format!("+ {}", b));
                }
            }
        }
    }

    fn render_import_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_import_dialog {
            return;
        }
        let lang = self.language;

        // Auto-preload file on initial open if path exists, text is empty, and user hasn't cleared/interacted yet
        if self.import_raw_text.is_empty()
            && self.import_status_msg.is_none()
            && !self.import_file_path.is_empty()
            && std::path::Path::new(&self.import_file_path).exists()
            && let Ok(content) = std::fs::read_to_string(&self.import_file_path) {
                let len = content.len();
                self.import_raw_text = content;
                let msg = match lang {
                    AppLanguage::English => format!("Loaded {} bytes from '{}'.", len, self.import_file_path),
                    AppLanguage::Vietnamese => format!("Đã nạp {} byte từ '{}'.", len, self.import_file_path),
                };
                self.import_status_msg = Some((msg, false));
            }

        let mut open_dialog_open = self.show_import_dialog;
        let mut close = false;
        let screen_rect = ctx.screen_rect();
        let dialog_w = (screen_rect.width() - 48.0).clamp(380.0, 620.0);
        let dialog_h = (screen_rect.height() - 60.0).clamp(360.0, 520.0);

        egui::Window::new(tr(lang, "📥 Import SSH Profiles & Sessions", "📥 Nhập hồ sơ SSH & Phiên kết nối"))
            .open(&mut open_dialog_open)
            .default_size(egui::vec2(dialog_w, dialog_h))
            .max_width(dialog_w)
            .max_height(dialog_h)
            .resizable(true)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let inner_w = (dialog_w - 24.0).max(320.0);
                ui.set_max_width(inner_w);

                ui.heading(RichText::new(tr(lang, "Import SSH Profiles & Sessions into RustyBox", "Nhập hồ sơ SSH & Phiên kết nối vào RustyBox")).size(15.0).color(Color32::from_rgb(56, 189, 248)));
                ui.label(RichText::new(tr(lang, "Supports OpenSSH (~/.ssh/config), MobaXterm (.txt/.ini/.mxtpro), server lists, or JSON.", "Hỗ trợ OpenSSH (~/.ssh/config), MobaXterm (.txt/.ini/.mxtpro), danh sách máy chủ hoặc JSON.")).size(11.5));
                ui.add_space(6.0);

                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(tr(lang, "Target Folder:", "Thư mục đích:")).strong());
                    ui.add(TextEdit::singleline(&mut self.import_default_folder).desired_width(180.0));
                    ui.label(RichText::new(tr(lang, "(e.g. SSH Profiles, OpenSSH, MobaXterm)", "(vd: SSH Profiles, OpenSSH, MobaXterm)")).size(11.0).color(Color32::GRAY));
                });
                ui.add_space(6.0);

                ui.group(|ui| {
                    ui.set_max_width(inner_w - 12.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(tr(lang, "Option A: Load from File on Disk", "Cách A: Nạp từ tệp trên máy")).strong());
                        ui.label(RichText::new(tr(lang, "Quick actions:", "Thao tác nhanh:")).size(11.0).color(Color32::GRAY));

                        if ui.button(RichText::new(tr(lang, "📁 Browse MobaXterm File...", "📁 Chọn tệp MobaXterm...")).color(Color32::from_rgb(251, 146, 60))).clicked()
                            && let Some(path) = rfd::FileDialog::new()
                                .set_title(tr(lang, "Select MobaXterm Export File", "Chọn tệp xuất MobaXterm"))
                                .add_filter("MobaXterm Sessions", &["txt", "ini", "mxtpro", "mxtsessions", "csv"])
                                .add_filter("All Files", &["*"])
                                .pick_file()
                            {
                                let p_str = path.to_string_lossy().to_string();
                                self.import_file_path = p_str.clone();
                                self.import_default_folder = "MobaXterm".into();
                                match std::fs::read_to_string(&path) {
                                    Ok(content) => {
                                        let len = content.len();
                                        self.import_raw_text = content;
                                        let msg = match lang {
                                            AppLanguage::English => format!("Loaded {} bytes from '{}'.", len, p_str),
                                            AppLanguage::Vietnamese => format!("Đã nạp {} byte từ '{}'.", len, p_str),
                                        };
                                        self.import_status_msg = Some((msg, false));
                                    }
                                    Err(e) => {
                                        let msg = match lang {
                                            AppLanguage::English => format!("Cannot read '{}': {}", p_str, e),
                                            AppLanguage::Vietnamese => format!("Không thể đọc '{}': {}", p_str, e),
                                        };
                                        self.import_status_msg = Some((msg, true));
                                    }
                                }
                            }

                        if let Some(ssh_cfg_path) = crate::session::import_export::default_ssh_config_path()
                            && ui.button(RichText::new(tr(lang, "🔑 Load ~/.ssh/config", "🔑 Nạp ~/.ssh/config")).color(Color32::from_rgb(56, 189, 248))).clicked() {
                                let p_str = ssh_cfg_path.to_string_lossy().to_string();
                                self.import_file_path = p_str.clone();
                                self.import_default_folder = "SSH Profiles".into();
                                match std::fs::read_to_string(&ssh_cfg_path) {
                                    Ok(content) => {
                                        let len = content.len();
                                        self.import_raw_text = content;
                                        let msg = match lang {
                                            AppLanguage::English => format!("Loaded {} bytes from '{}'.", len, p_str),
                                            AppLanguage::Vietnamese => format!("Đã nạp {} byte từ '{}'.", len, p_str),
                                        };
                                        self.import_status_msg = Some((msg, false));
                                    }
                                    Err(e) => {
                                        let msg = match lang {
                                            AppLanguage::English => format!("Cannot read '{}': {}", p_str, e),
                                            AppLanguage::Vietnamese => format!("Không thể đọc '{}': {}", p_str, e),
                                        };
                                        self.import_status_msg = Some((msg, true));
                                    }
                                }
                            }
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let path_w = (ui.available_width() - 175.0).max(140.0);
                        let hint = egui::WidgetText::from(tr(lang, "Select a file or enter path on disk...", "Chọn tệp hoặc nhập đường dẫn trên máy...")).color(Color32::from_rgb(120, 130, 150));
                        ui.add(TextEdit::singleline(&mut self.import_file_path).hint_text(hint).desired_width(path_w));
                        if ui.button(tr(lang, "📂 Browse...", "📂 Duyệt...")).clicked()
                            && let Some(path) = rfd::FileDialog::new()
                                .add_filter("SSH & Session Files", &["config", "txt", "ini", "mxtpro", "mxtsessions", "csv", "json"])
                                .add_filter("All Files", &["*"])
                                .pick_file()
                            {
                                let p_str = path.to_string_lossy().to_string();
                                self.import_file_path = p_str.clone();
                                match std::fs::read_to_string(&path) {
                                    Ok(content) => {
                                        let len = content.len();
                                        self.import_raw_text = content;
                                        let msg = match lang {
                                            AppLanguage::English => format!("Loaded {} bytes from '{}'.", len, p_str),
                                            AppLanguage::Vietnamese => format!("Đã nạp {} byte từ '{}'.", len, p_str),
                                        };
                                        self.import_status_msg = Some((msg, false));
                                    }
                                    Err(e) => {
                                        let msg = match lang {
                                            AppLanguage::English => format!("Failed to read file '{}': {}", p_str, e),
                                            AppLanguage::Vietnamese => format!("Lỗi đọc tệp '{}': {}", p_str, e),
                                        };
                                        self.import_status_msg = Some((msg, true));
                                    }
                                }
                            }
                        if ui.button(RichText::new(tr(lang, "📥 Read File", "📥 Đọc tệp")).strong()).clicked() {
                            if self.import_file_path.trim().is_empty() {
                                self.import_status_msg = Some((tr(lang, "Please enter or browse for a file path first.", "Vui lòng nhập hoặc chọn đường dẫn tệp trước.").into(), true));
                            } else {
                                match std::fs::read_to_string(&self.import_file_path) {
                                    Ok(content) => {
                                        let len = content.len();
                                        self.import_raw_text = content;
                                        let msg = match lang {
                                            AppLanguage::English => format!("Read {} bytes from file.", len),
                                            AppLanguage::Vietnamese => format!("Đã đọc {} byte từ tệp.", len),
                                        };
                                        self.import_status_msg = Some((msg, false));
                                    }
                                    Err(e) => {
                                        let msg = match lang {
                                            AppLanguage::English => format!("Failed to read file: {}", e),
                                            AppLanguage::Vietnamese => format!("Lỗi đọc tệp: {}", e),
                                        };
                                        self.import_status_msg = Some((msg, true));
                                    }
                                }
                            }
                        }
                    });
                });

                ui.add_space(6.0);

                ui.group(|ui| {
                    ui.set_max_width(inner_w - 12.0);
                    ui.label(RichText::new(tr(lang, "Option B: Paste OpenSSH Config / MobaXterm / Session Text directly", "Cách B: Dán trực tiếp OpenSSH Config / MobaXterm / văn bản phiên")).strong());
                    ui.label(RichText::new(tr(lang, "Supports OpenSSH (Host/HostName/User/Port/IdentityFile), MobaXterm (#109#...), user@host=pass, or JSON", "Hỗ trợ OpenSSH (Host/HostName/User/Port/IdentityFile), MobaXterm (#109#...), user@host=pass hoặc JSON")).size(10.5).color(Color32::GRAY));
                    ScrollArea::both().max_height(165.0).show(ui, |ui| {
                        ui.add(
                            TextEdit::multiline(&mut self.import_raw_text)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(inner_w - 28.0)
                                .desired_rows(8)
                                .hint_text(tr(lang, "Paste ~/.ssh/config, MobaXterm export, user@host:port, or JSON here...", "Dán ~/.ssh/config, tệp xuất MobaXterm, user@host:port hoặc JSON vào đây..."))
                        );
                    });
                });

                ui.add_space(6.0);

                // Preview count
                let preview_parsed = crate::session::import_export::parse_sessions_from_text(&self.import_raw_text, &self.import_default_folder);
                ui.label(RichText::new(match lang {
                    AppLanguage::English => format!("📊 Detected: {} valid sessions in input", preview_parsed.len()),
                    AppLanguage::Vietnamese => format!("📊 Phát hiện: {} phiên hợp lệ trong dữ liệu", preview_parsed.len()),
                })
                    .strong()
                    .color(if preview_parsed.is_empty() { Color32::GRAY } else { Color32::from_rgb(100, 220, 100) }));

                if let Some((ref msg, is_err)) = self.import_status_msg {
                    ui.add_space(2.0);
                    let color = if is_err { Color32::from_rgb(239, 68, 68) } else { Color32::from_rgb(34, 197, 94) };
                    ui.label(RichText::new(msg).color(color).strong().size(11.5));
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    let can_import = !preview_parsed.is_empty();
                    if ui.add_enabled(can_import, egui::Button::new(RichText::new(tr(lang, "📥 Import & Merge Sessions", "📥 Nhập & Gộp phiên")).strong().color(Color32::WHITE))
                        .fill(Color32::from_rgb(34, 197, 94))
                        .min_size(egui::vec2(180.0, 28.0))).clicked()
                    {
                        let parsed = crate::session::import_export::parse_sessions_from_text(&self.import_raw_text, &self.import_default_folder);
                        let summary = crate::session::import_export::merge_imported_sessions(&mut self.sessions, parsed);
                        let _ = self.storage.save_sessions(&self.sessions);
                        let msg = match lang {
                            AppLanguage::English => format!("✅ Imported {} new sessions! ({} skipped as duplicate, total {} parsed)",
                                summary.new_imported, summary.duplicates_skipped, summary.total_parsed),
                            AppLanguage::Vietnamese => format!("✅ Đã nhập {} phiên mới! (bỏ qua {} bản trùng, tổng {} phiên)",
                                summary.new_imported, summary.duplicates_skipped, summary.total_parsed),
                        };
                        self.import_status_msg = Some((msg, false));
                    }

                    if ui.button(RichText::new(tr(lang, "Clear Text", "Xóa nội dung")).color(Color32::LIGHT_GRAY)).clicked() {
                        self.import_raw_text.clear();
                        self.import_status_msg = Some((tr(lang, "Cleared text input. Paste config or load a file above.", "Đã xóa nội dung. Hãy dán cấu hình hoặc nạp tệp ở trên.").into(), false));
                    }

                    if ui.button(tr(lang, "✖ Close", "✖ Đóng")).clicked() {
                        close = true;
                    }
                });
            });

        if close || !open_dialog_open {
            self.show_import_dialog = false;
        }
    }

    pub fn build_full_export_config(&self) -> crate::session::storage::RustyBoxConfig {
        let mut cfg = self.storage.load_config();
        cfg.language = self.language;
        cfg.sessions = self.sessions.clone();
        cfg.credentials = self.credentials.clone();
        cfg.password_save_mode = self.manage_passwords_save_mode as u8;
        cfg.save_key_passphrases = self.manage_passwords_save_ssh_keys;
        cfg.ui_scale = self.ui_scale;
        cfg.font_size = self.font_size;
        cfg.terminal_font_family = self.terminal_font_family.clone();
        cfg.theme_name = self.theme.name().to_string();
        cfg.paste_protection_enabled = self.paste_protection_enabled;
        cfg.quick_macros = self.quick_macros.clone();
        cfg.snippets = self.snippets.clone();
        cfg.tunnels = self.tunnel_manager.tunnels.clone();
        cfg.highlight_rules = self.highlight_rules.clone();
        cfg.highlight_rules_enabled = self.highlight_rules_enabled;
        cfg.remote_monitoring_enabled = self.explorer.remote_monitoring_enabled;
        cfg.follow_terminal_folder = self.explorer.follow_terminal_folder;
        cfg.sftp_bookmarks = self.explorer.bookmarks.clone();
        cfg.auto_log_sessions = self.auto_log_sessions;
        cfg.default_log_directory = self.default_log_directory.clone();
        cfg
    }

    pub fn apply_imported_config(&mut self, ctx: &egui::Context, mut imported: crate::session::storage::RustyBoxConfig) {
        let mut seen_ids = std::collections::HashSet::new();
        for s in &mut imported.sessions {
            if s.id.is_empty() || seen_ids.contains(&s.id) {
                s.id = uuid::Uuid::new_v4().to_string();
            }
            seen_ids.insert(s.id.clone());
        }
        self.language = imported.language;
        self.sessions = imported.sessions.clone();
        if !imported.credentials.is_empty() {
            self.credentials = imported.credentials.clone();
        }
        if !imported.quick_macros.is_empty() {
            self.quick_macros = imported.quick_macros.clone();
        }
        if !imported.snippets.is_empty() {
            self.snippets = imported.snippets.clone();
        }
        if !imported.tunnels.is_empty() {
            self.tunnel_manager.stop_all_tunnels();
            self.tunnel_manager = TunnelManager::with_tunnels(imported.tunnels.clone());
        }
        if !imported.highlight_rules.is_empty() {
            self.highlight_rules = imported.highlight_rules.clone();
        }
        self.highlight_rules_enabled = imported.highlight_rules_enabled;
        self.manage_passwords_save_mode = (imported.password_save_mode as usize).min(2);
        self.manage_passwords_save_ssh_keys = imported.save_key_passphrases;
        if imported.ui_scale >= 0.7 && imported.ui_scale <= 2.5 {
            self.ui_scale = imported.ui_scale;
        }
        if imported.font_size >= 8.0 && imported.font_size <= 36.0 {
            self.font_size = imported.font_size;
        }
        if !imported.terminal_font_family.is_empty() {
            self.terminal_font_family = imported.terminal_font_family.clone();
            crate::terminal::fonts::setup_terminal_fonts(ctx, &self.terminal_font_family);
        }
        if let Some(t) = TerminalTheme::from_name(&imported.theme_name) {
            self.theme = t;
        }
        self.paste_protection_enabled = imported.paste_protection_enabled;
        self.explorer.remote_monitoring_enabled = imported.remote_monitoring_enabled;
        self.explorer.follow_terminal_folder = imported.follow_terminal_folder;
        if !imported.sftp_bookmarks.is_empty() {
            self.explorer.bookmarks = imported.sftp_bookmarks.clone();
        }
        self.auto_log_sessions = imported.auto_log_sessions;
        if !imported.default_log_directory.is_empty() {
            self.default_log_directory = imported.default_log_directory.clone();
        }

        if imported.vault.is_some() {
            self.storage.set_vault_key(None);
            self.storage.set_vault_configured(true);
            let _ = self.storage.save_config(&imported);
            self.show_vault = true;
        } else {
            let full = self.build_full_export_config();
            let _ = self.storage.save_config(&full);
        }
        self.status_toast = Some((
            format!("Imported configuration ({} sessions)", self.sessions.len()),
            std::time::Instant::now(),
        ));
    }

    pub fn shutdown_cleanup(&mut self) {
        self.tunnel_manager.stop_all_tunnels();
        self.network_tools.stop_http_server();
        self.network_tools.stop_syslog_server();
        self.network_tools.stop_tftp_server();
        self.explorer.disconnect_all_remotes();
        for mut tab in self.open_tabs.drain(..) {
            tab.session.kill();
        }
    }
}

impl eframe::App for RustyBoxApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        Color32::from_rgb(15, 18, 26).to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let lang = self.language;
        // Enforce dark theme mode across all frames regardless of OS appearance events
        if ctx.theme() != egui::Theme::Dark {
            ctx.set_theme(egui::ThemePreference::Dark);
        }

        // Enforce Window Maximized on launch only if not already maximized
        if !self.is_maximized_requested {
            if ctx.input(|i| i.viewport().maximized) != Some(true) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(true));
            }
            self.is_maximized_requested = true;
        }

        // Enforce UI zoom / font scale factor only when changed
        if (ctx.zoom_factor() - self.ui_scale).abs() > 0.001 {
            ctx.set_zoom_factor(self.ui_scale);
        }

        // Synchronize left explorer (Sessions tree & SFTP browser) if active tab changed
        self.check_and_sync_active_tab();

        // Global Keyboard Shortcuts for UI Zoom & Font Scale
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL | egui::Modifiers::SHIFT, egui::Key::Plus)
            || i.consume_key(egui::Modifiers::CTRL | egui::Modifiers::SHIFT, egui::Key::Equals)) {
            self.ui_scale = (self.ui_scale + 0.1).min(2.0);
            let _ = self.persist_preferences();
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL | egui::Modifiers::SHIFT, egui::Key::Minus)) {
            self.ui_scale = (self.ui_scale - 0.1).max(0.7);
            let _ = self.persist_preferences();
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL | egui::Modifiers::SHIFT, egui::Key::Num0)
            || i.consume_key(egui::Modifiers::CTRL, egui::Key::Num0)) {
            self.ui_scale = 1.0;
            let _ = self.persist_preferences();
        }

        // Global Keyboard Shortcuts
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::PageDown))
            && !self.open_tabs.is_empty() {
                self.is_home_active = false;
                self.active_tab_idx = (self.active_tab_idx + 1) % self.open_tabs.len();
                self.sync_sidebar_with_active_tab();
            }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::PageUp))
            && !self.open_tabs.is_empty() {
                self.is_home_active = false;
                self.active_tab_idx = if self.active_tab_idx == 0 {
                    self.open_tabs.len() - 1
                } else {
                    self.active_tab_idx - 1
                };
                self.sync_sidebar_with_active_tab();
            }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::F) || i.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
            self.search_open = true;
            self.focus_search = true;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::I) || i.consume_key(egui::Modifiers::COMMAND, egui::Key::I)) {
            self.show_import_dialog = true;
        }
        let active_tab_dead = !self.is_home_active
            && self
                .open_tabs
                .get(self.active_tab_idx)
                .map(|t| !t.session.is_alive())
                .unwrap_or(false);
        let close_tab_shortcut = ctx.input_mut(|i| {
            i.consume_key(egui::Modifiers::CTRL | egui::Modifiers::SHIFT, egui::Key::W)
                || i.consume_key(
                    egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
                    egui::Key::W,
                )
                || (active_tab_dead
                    && (i.consume_key(egui::Modifiers::CTRL, egui::Key::W)
                        || i.consume_key(egui::Modifiers::COMMAND, egui::Key::W)))
        });
        if close_tab_shortcut
            && !self.open_tabs.is_empty() && !self.is_home_active {
                let active = self.active_tab_idx;
                if active < self.open_tabs.len() {
                    let mut closed = self.open_tabs.remove(active);
                    closed.session.kill();
                    if self.open_tabs.is_empty() {
                        self.is_home_active = true;
                        self.active_tab_idx = 0;
                        self.sidebar_tab = 0;
                    } else if self.active_tab_idx >= self.open_tabs.len() {
                        self.active_tab_idx = self.open_tabs.len() - 1;
                    }
                    self.cleanup_unused_remote_sftp_sessions();
                    self.sync_sidebar_with_active_tab();
                }
            }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::T) || i.consume_key(egui::Modifiers::COMMAND, egui::Key::T)) {
            self.spawn_local_terminal("Local Terminal", None, None);
        }

        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.show_network_tools = false;
            self.show_services_modal = false;
            self.show_tunnels = false;
            self.show_tunnel_edit = false;
            self.show_keygen = false;
            self.show_pwdgen = false;
            self.show_diff = false;
            self.show_mobapt = false;
            self.show_macro_manager = false;
            self.show_vault = false;
            self.show_settings_dialog = false;
            self.show_hotkeys_dialog = false;
            self.show_about = false;
            self.show_manage_passwords = false;
            self.show_import_dialog = false;
            self.new_session_dialog.is_open = false;
            self.connect_as_target = None;
            self.rename_session_target = None;
            self.rename_folder_target = None;
            self.pending_paste_text = None;
            self.search_open = false;
        }
        self.handle_multi_exec_broadcast();
        self.explorer.poll();
        if self.explorer.bookmarks_changed {
            self.explorer.bookmarks_changed = false;
            let _ = self.storage.save_sftp_bookmarks(&self.explorer.bookmarks);
        }
        self.update_telemetry();
        self.sync_terminal_cwd_if_enabled();

        if let Some(target_dir) = self.explorer.requested_cd_terminal.take()
            && !self.is_home_active && !self.open_tabs.is_empty() {
                let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
                let cmd = format!("cd \"{}\"\n", target_dir);
                let _ = self.open_tabs[idx].session.write_str(&cmd);
            }

        if let Some(paste_path) = self.explorer.requested_terminal_paste.take()
            && !self.is_home_active && !self.open_tabs.is_empty() {
                let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
                let snippet = format!("{} ", paste_path);
                let _ = self.open_tabs[idx].session.write_str(&snippet);
            }

        // Smart Repaint: Repaint immediately only if VISIBLE active terminal(s) have new output
        let visible_has_data = match self.split_mode {
            SplitMode::Single => {
                if !self.is_home_active && !self.open_tabs.is_empty() {
                    let idx = self.active_tab_idx.min(self.open_tabs.len() - 1);
                    self.open_tabs[idx].session.has_new_data.swap(false, std::sync::atomic::Ordering::Relaxed)
                } else {
                    false
                }
            }
            SplitMode::Horizontal | SplitMode::Vertical => {
                let mut d = false;
                if !self.is_home_active && !self.open_tabs.is_empty() {
                    let idx_a = self.active_tab_idx.min(self.open_tabs.len() - 1);
                    d |= self.open_tabs[idx_a].session.has_new_data.swap(false, std::sync::atomic::Ordering::Relaxed);
                    if self.open_tabs.len() > 1 {
                        let idx_b = if idx_a == 0 { 1 } else { 0 };
                        d |= self.open_tabs[idx_b].session.has_new_data.swap(false, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                d
            }
            SplitMode::Grid2x2 => {
                let mut d = false;
                if !self.is_home_active && !self.open_tabs.is_empty() {
                    for i in 0..4.min(self.open_tabs.len()) {
                        d |= self.open_tabs[i].session.has_new_data.swap(false, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                d
            }
        };

        // Clear has_new_data on background inactive tabs so it doesn't linger
        let mut any_bg_has_data = false;
        for (i, t) in self.open_tabs.iter().enumerate() {
            if i != self.active_tab_idx {
                if self.multi_exec_enabled {
                    any_bg_has_data |= t.session.has_new_data.swap(false, std::sync::atomic::Ordering::Relaxed);
                } else {
                    t.session.has_new_data.store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        let is_minimized = ctx.input(|i| i.viewport().minimized == Some(true))
            || ctx.screen_rect().width() <= 1.0
            || ctx.screen_rect().height() <= 1.0;
        crate::set_ui_minimized(is_minimized);

        if is_minimized {
            ctx.request_repaint_after(std::time::Duration::from_secs(2));
        } else if visible_has_data || any_bg_has_data {
            ctx.request_repaint();
        } else if self.explorer.is_loading || self.explorer.transfer_progress.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        } else {
            // PTY reader & SFTP worker threads call `crate::request_ui_repaint()` immediately on
            // incoming data, so idle frames only need a gentle 500ms tick for cursor blink & telemetry.
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }

        // 1. TOP MENU BAR (Branded Header + Menus + Quick Utilities)
        TopBottomPanel::top("top_menu")
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(14, 18, 26))
                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(26, 32, 46)))
                    .inner_margin(egui::Margin::symmetric(10.0, 4.0))
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("⚡ RustyBox")
                            .color(Color32::from_rgb(56, 189, 248))
                            .strong()
                            .size(13.5),
                    );
                    egui::Frame::none()
                        .fill(Color32::from_rgb(22, 30, 44))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(38, 54, 80)))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(5.0, 1.5))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("v1.4.14")
                                    .color(Color32::from_rgb(147, 197, 253))
                                    .size(10.5)
                                    .strong(),
                            );
                        });
                    ui.add_space(4.0);
                    ui.separator();
                    ui.add_space(4.0);

                    let lang = self.language;
                    menu::bar(ui, |ui| {
                // SESSIONS MENU
                ui.menu_button(tr(lang, "Sessions", "Phiên"), |ui| {
                    if ui.button(tr(lang, "➕ New Session...", "➕ Tạo phiên mới...")).clicked() {
                        self.new_session_dialog.open_for_new();
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "💾 Save Sessions", "💾 Lưu danh sách phiên")).clicked() {
                        let _ = self.storage.save_sessions(&self.sessions);
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button(tr(lang, "📤 Export Sessions (JSON)...", "📤 Xuất phiên (JSON)...")).clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).save_file() {
                            let cfg = self.build_full_export_config();
                            let _ = self.storage.export_to_file(&path, &cfg);
                        }
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "📥 Import SSH Profiles / Sessions (~/.ssh/config, MobaXterm)...\tCtrl+I", "📥 Nhập SSH Profile / Phiên (~/.ssh/config, MobaXterm)...\tCtrl+I")).clicked() {
                        self.show_import_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "📥 Import Sessions from File (JSON)...", "📥 Nhập phiên từ File (JSON)...")).clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file()
                            && let Ok(imported) = self.storage.import_from_file(&path) {
                                self.apply_imported_config(ui.ctx(), imported);
                            }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button(tr(lang, "🚪 Exit", "🚪 Thoát")).clicked() {
                        self.shutdown_cleanup();
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        ui.close_menu();
                    }
                });

                // TERMINAL MENU
                ui.menu_button(tr(lang, "Terminal", "Terminal"), |ui| {
                    if ui.button(tr(lang, "💻 New Local Terminal\tCtrl+T", "💻 Mở Terminal cục bộ mới\tCtrl+T")).clicked() {
                        self.spawn_local_terminal("Local Terminal", None, None);
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "📑 Duplicate Current Tab", "📑 Nhân bản Tab hiện tại")).clicked() {
                        let dup_info = self.open_tabs.get(self.active_tab_idx).map(|tab| {
                            (
                                tab.title.clone(),
                                tab.session_def.clone(),
                                tab.custom_cmd.clone(),
                                tab.workdir.clone(),
                            )
                        });
                        if let Some((title, session_def, custom_cmd, workdir)) = dup_info {
                            if let Some(s) = session_def {
                                self.launch_generic_session(s);
                            } else {
                                let name = format!("{} (Copy)", title);
                                self.spawn_local_terminal(&name, custom_cmd.as_deref(), workdir.as_deref());
                            }
                        }
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "✖ Close Active Tab\tCtrl+Shift+W", "✖ Đóng Tab đang mở\tCtrl+Shift+W")).clicked() {
                        if !self.open_tabs.is_empty() && !self.is_home_active {
                            let active = self.active_tab_idx;
                            if active < self.open_tabs.len() {
                                let mut closed = self.open_tabs.remove(active);
                                closed.session.kill();
                                if self.open_tabs.is_empty() {
                                    self.is_home_active = true;
                                    self.active_tab_idx = 0;
                                    self.sidebar_tab = 0;
                                } else if self.active_tab_idx >= self.open_tabs.len() {
                                    self.active_tab_idx = self.open_tabs.len() - 1;
                                }
                                self.cleanup_unused_remote_sftp_sessions();
                                self.sync_sidebar_with_active_tab();
                            }
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button(tr(lang, "🧹 Clear Terminal Screen\tCtrl+L", "🧹 Xóa màn hình Terminal\tCtrl+L")).clicked() {
                        if let Some(tab) = self.open_tabs.get_mut(self.active_tab_idx) {
                            let _ = tab.session.write_bytes(b"clear\n");
                        }
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🔍 Find in Terminal...\tCtrl+F", "🔍 Tìm trong Terminal...\tCtrl+F")).clicked() {
                        self.search_open = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "💾 Save Terminal Buffer to File...", "💾 Lưu nội dung Terminal ra tệp...")).clicked() {
                        self.save_active_terminal_buffer();
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.menu_button(tr(lang, "🔤 Terminal Font", "🔤 Phông chữ Terminal"), |ui| {
                        for opt in crate::terminal::fonts::AVAILABLE_TERMINAL_FONTS {
                            let is_selected = self.terminal_font_family == opt.id;
                            if ui.selectable_label(is_selected, opt.name).clicked() {
                                self.terminal_font_family = opt.id.to_string();
                                crate::terminal::fonts::setup_terminal_fonts(ui.ctx(), &self.terminal_font_family);
                                let _ = self.persist_preferences();
                                ui.close_menu();
                            }
                        }
                    });
                    if ui.button(tr(lang, "➕ Increase Font Size\tCtrl++", "➕ Tăng cỡ chữ\tCtrl++")).clicked() {
                        self.font_size = (self.font_size + 1.0).min(32.0);
                        let _ = self.persist_preferences();
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "➖ Decrease Font Size\tCtrl+-", "➖ Giảm cỡ chữ\tCtrl+-")).clicked() {
                        self.font_size = (self.font_size - 1.0).max(8.0);
                        let _ = self.persist_preferences();
                        ui.close_menu();
                    }
                });

                // VIEW MENU
                ui.menu_button(tr(lang, "View", "Hiển thị"), |ui| {
                    ui.checkbox(&mut self.show_sftp_sidebar, tr(lang, "Show Sidebar (Sessions & SFTP)", "Hiện thanh bên (Phiên & SFTP)"));
                    ui.separator();
                    if ui.selectable_label(self.split_mode == SplitMode::Single, tr(lang, "🗖 Single Terminal", "🗖 1 Khung Terminal")).clicked() {
                        self.split_mode = SplitMode::Single;
                        ui.close_menu();
                    }
                    if ui.selectable_label(self.split_mode == SplitMode::Horizontal, tr(lang, "◫ Split 2 Columns", "◫ Chia 2 cột")).clicked() {
                        self.split_mode = SplitMode::Horizontal;
                        ui.close_menu();
                    }
                    if ui.selectable_label(self.split_mode == SplitMode::Vertical, tr(lang, "⬒ Split 2 Rows", "⬒ Chia 2 hàng")).clicked() {
                        self.split_mode = SplitMode::Vertical;
                        ui.close_menu();
                    }
                    if ui.selectable_label(self.split_mode == SplitMode::Grid2x2, tr(lang, "⊞ Split 2x2 Grid", "⊞ Chia lưới 2x2")).clicked() {
                        self.split_mode = SplitMode::Grid2x2;
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.checkbox(&mut self.multi_exec_enabled, tr(lang, "⚡ Multi-Execution (Broadcast to all tabs)", "⚡ Thực thi đồng loạt (Gửi tới mọi tab)"));
                    ui.separator();
                    ui.menu_button(tr(lang, "🔍 UI Font & Zoom Scale", "🔍 Thu phóng giao diện"), |ui| {
                        if ui.button(tr(lang, "➕ Zoom In UI (+10%)\tCtrl+Shift++", "➕ Phóng to giao diện (+10%)\tCtrl+Shift++")).clicked() {
                            self.ui_scale = (self.ui_scale + 0.1).min(2.0);
                            let _ = self.persist_preferences();
                            ui.close_menu();
                        }
                        if ui.button(tr(lang, "➖ Zoom Out UI (-10%)\tCtrl+Shift+-", "➖ Thu nhỏ giao diện (-10%)\tCtrl+Shift+-")).clicked() {
                            self.ui_scale = (self.ui_scale - 0.1).max(0.7);
                            let _ = self.persist_preferences();
                            ui.close_menu();
                        }
                        if ui.button(tr(lang, "↺ Reset Zoom (100%)\tCtrl+0", "↺ Đặt lại thu phóng (100%)\tCtrl+0")).clicked() {
                            self.ui_scale = 1.0;
                            let _ = self.persist_preferences();
                            ui.close_menu();
                        }
                        ui.separator();
                        for scale in [0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0] {
                            let label = format!("{:.0}%{}", scale * 100.0, if (self.ui_scale - scale).abs() < 0.02 { "  ✓" } else { "" });
                            if ui.selectable_label((self.ui_scale - scale).abs() < 0.02, label).clicked() {
                                self.ui_scale = scale;
                                let _ = self.persist_preferences();
                                ui.close_menu();
                            }
                        }
                    });
                    ui.separator();
                    ui.menu_button(tr(lang, "🎨 Terminal Theme", "🎨 Giao diện Terminal"), |ui| {
                        for t in TerminalTheme::all() {
                            if ui.selectable_label(self.theme == *t, t.name()).clicked() {
                                self.theme = *t;
                                if let Some(tab) = self.open_tabs.get_mut(self.active_tab_idx)
                                    && let Some(ref mut s) = tab.session_def {
                                        s.terminal_color_scheme = t.name().to_string();
                                    }
                                let _ = self.persist_preferences();
                                ui.ctx().request_repaint();
                                ui.close_menu();
                            }
                        }
                    });
                });

                // TOOLS MENU
                ui.menu_button(tr(lang, "Tools", "Công cụ"), |ui| {
                    if ui.button(tr(lang, "🔍 Port Scanner", "🔍 Quét cổng mạng")).clicked() {
                        self.show_network_tools = true;
                        self.net_tools_tab = 0;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "📡 Subnet NetScan (LAN IP Scanner)", "📡 Quét dải IP nội bộ (NetScan)")).clicked() {
                        self.show_network_tools = true;
                        self.net_tools_tab = 1;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "⏱ TCP Ping Utility", "⏱ Kiểm tra Ping TCP")).clicked() {
                        self.show_network_tools = true;
                        self.net_tools_tab = 2;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "📊 Active Connections (Netstat)", "📊 Kết nối đang hoạt động (Netstat)")).clicked() {
                        self.show_network_tools = true;
                        self.net_tools_tab = 3;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "⚡ Wake-on-LAN (WOL)", "⚡ Đánh thức qua mạng (Wake-on-LAN)")).clicked() {
                        self.show_network_tools = true;
                        self.net_tools_tab = 5;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🌐 DNS Lookup", "🌐 Tra cứu tên miền (DNS)")).clicked() {
                        self.show_network_tools = true;
                        self.net_tools_tab = 4;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button(tr(lang, "🚀 Embedded Daemons (HTTP, Syslog, TFTP)", "🚀 Dịch vụ mạng tích hợp (HTTP, Syslog, TFTP)")).clicked() {
                        self.show_services_modal = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "📋 Command Snippets (DevOps Library)", "📋 Kho lệnh mẫu (Snippets)")).clicked() {
                        self.show_snippets = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🎨 Auto-Highlight Keywords (ZOC Style)", "🎨 Tự động tô màu từ khóa (kiểu ZOC)")).clicked() {
                        self.show_highlight_modal = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🔀 SSH Tunnels / Port Forwarding", "🔀 Đường hầm SSH / Chuyển tiếp cổng")).clicked() {
                        self.show_tunnels = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🔑 SSH Key Generator (RustyBox KeyGen)", "🔑 Trình tạo khóa SSH (RustyBox KeyGen)")).clicked() {
                        self.show_keygen = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🗝 Random Password Generator", "🗝 Trình tạo mật khẩu ngẫu nhiên")).clicked() {
                        self.show_pwdgen = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "📄 File Comparison (RustyBox Diff)", "📄 So sánh tệp (RustyBox Diff)")).clicked() {
                        self.show_diff = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "⚡ Manage Sysadmin Macros...", "⚡ Quản lý Macro thao tác nhanh...")).clicked() {
                        self.show_macro_manager = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "📦 RustyBox Apt Package Manager...", "📦 Trình quản lý gói RustyBox Apt...")).clicked() {
                        self.show_mobapt = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🔒 Master Password & Vault", "🔒 Mật khẩu chính & Két bảo mật")).clicked() {
                        self.show_vault = true;
                        ui.close_menu();
                    }
                });

                // SETTINGS MENU (MobaXterm TFORMPARAMS & TFormManagePasswords)
                ui.menu_button(tr(lang, "Settings", "Cài đặt"), |ui| {
                    if ui.button(tr(lang, "⚙ Configuration / Preferences...", "⚙ Cấu hình / Tùy chọn...")).clicked() {
                        self.show_settings_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🔑 Manage Passwords...", "🔑 Quản lý mật khẩu...")).clicked() {
                        self.show_manage_passwords = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🔒 Master Password Settings...", "🔒 Cài đặt mật khẩu chính...")).clicked() {
                        self.show_vault = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button(tr(lang, "📋 Paste Warning Settings...", "📋 Cài đặt cảnh báo dán...")).clicked() {
                        self.show_settings_dialog = true;
                        self.settings_tab = 1;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "🖱 Windows Right-Click Menu Integration...", "🖱 Tích hợp menu chuột phải Windows...")).clicked() {
                        self.show_settings_dialog = true;
                        self.settings_tab = 6;
                        ui.close_menu();
                    }
                });

                // HELP MENU
                ui.menu_button(tr(lang, "Help", "Trợ giúp"), |ui| {
                    if ui.button(tr(lang, "⌨ Keyboard Shortcuts (Hotkeys)", "⌨ Phím tắt (Hotkeys)")).clicked() {
                        self.show_hotkeys_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button(tr(lang, "ℹ About RustyBox", "ℹ Giới thiệu RustyBox")).clicked() {
                        self.show_about = true;
                        ui.close_menu();
                    }
                });
            });

            // Quick utilities on the right side of Menu Bar
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let util_btn = |ui: &mut egui::Ui, text: &str| -> egui::Response {
                    ui.add(
                        egui::Button::new(
                            RichText::new(text)
                                .color(Color32::from_rgb(210, 220, 235))
                                .size(11.5),
                        )
                        .fill(Color32::from_rgb(20, 26, 38))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(34, 44, 62)))
                        .rounding(5.0),
                    )
                };

                let next_lang = match lang {
                    AppLanguage::English => AppLanguage::Vietnamese,
                    AppLanguage::Vietnamese => AppLanguage::English,
                };
                if util_btn(ui, &format!("🌐 {}", lang.short_code()))
                    .on_hover_text(tr(
                        lang,
                        "Switch language (English / Tiếng Việt)",
                        "Đổi ngôn ngữ (Tiếng Việt / English)",
                    ))
                    .clicked()
                {
                    self.language = next_lang;
                    let cfg = self.build_full_export_config();
                    let _ = self.storage.save_config(&cfg);
                }

                if util_btn(ui, tr(lang, "⚙ Settings", "⚙ Cài đặt")).clicked() {
                    self.show_settings_dialog = true;
                }
                if util_btn(ui, "🔑 KeyGen").clicked() {
                    self.show_keygen = true;
                }
                if util_btn(ui, "🗝 PwdGen").clicked() {
                    self.show_pwdgen = true;
                }
                if util_btn(ui, tr(lang, "📁 Files", "📁 Tệp SFTP")).clicked() {
                    if self.show_sftp_sidebar && self.sidebar_tab == 1 {
                        self.show_sftp_sidebar = false;
                    } else {
                        self.show_sftp_sidebar = true;
                        self.sidebar_tab = 1;
                    }
                }
                if util_btn(ui, tr(lang, "📋 Snippets", "📋 Lệnh mẫu")).clicked() {
                    self.show_snippets = true;
                }
                if util_btn(ui, tr(lang, "🎨 Highlight", "🎨 Tô màu")).clicked() {
                    self.show_highlight_modal = true;
                }
                if util_btn(ui, tr(lang, "🔀 Tunnels", "🔀 Đường hầm")).clicked() {
                    self.show_tunnels = true;
                }
                if util_btn(ui, "🕊 Daemons").clicked() {
                    self.show_services_modal = true;
                }
                if util_btn(ui, "🌐 NetTools").clicked() {
                    self.show_network_tools = true;
                }
            });
        });
    });

        // 2. MAIN TOOLBAR (Unified Modern Toolbar Suite)
        TopBottomPanel::top("main_toolbar")
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(16, 20, 29))
                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(26, 33, 47)))
                    .inner_margin(egui::Margin::symmetric(10.0, 5.0))
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let toolbar_h = 26.0;

                    let tb_button = |ui: &mut egui::Ui, text: &str, active: bool| -> egui::Response {
                        let fill = if active {
                            Color32::from_rgb(37, 99, 235)
                        } else {
                            Color32::from_rgb(22, 28, 40)
                        };
                        let stroke = if active {
                            egui::Stroke::new(1.0_f32, Color32::from_rgb(96, 165, 250))
                        } else {
                            egui::Stroke::new(1.0_f32, Color32::from_rgb(36, 46, 64))
                        };
                        let text_color = if active {
                            Color32::WHITE
                        } else {
                            Color32::from_rgb(205, 215, 228)
                        };
                        let btn = egui::Button::new(RichText::new(text).color(text_color).size(12.0))
                            .fill(fill)
                            .stroke(stroke)
                            .rounding(6.0)
                            .min_size(egui::vec2(0.0, toolbar_h));
                        ui.add(btn)
                    };

                    // Prominent Modern New Session Button
                    let lang = self.language;
                    let new_sess_btn = egui::Button::new(
                        RichText::new(tr(lang, "➕ New Session", "➕ Phiên mới")).color(Color32::WHITE).size(12.0).strong()
                    )
                    .fill(Color32::from_rgb(37, 99, 235))
                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(96, 165, 250)))
                    .rounding(6.0)
                    .min_size(egui::vec2(0.0, toolbar_h));
                    if ui.add(new_sess_btn).clicked() {
                        self.new_session_dialog.open_for_new();
                    }

                    let import_tb_btn = egui::Button::new(
                        RichText::new(tr(lang, "📥 Import", "📥 Nhập")).color(Color32::from_rgb(205, 215, 228)).size(12.0).strong()
                    )
                    .fill(Color32::from_rgb(22, 28, 40))
                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248)))
                    .rounding(6.0)
                    .min_size(egui::vec2(0.0, toolbar_h));
                    if ui.add(import_tb_btn).on_hover_text(tr(lang, "Import SSH Profiles (~/.ssh/config, MobaXterm, JSON) [Ctrl+I]", "Nhập cấu hình SSH (~/.ssh/config, MobaXterm, JSON) [Ctrl+I]")).clicked() {
                        self.show_import_dialog = true;
                    }

                    ui.add_space(5.0);
                    ui.separator();
                    ui.add_space(5.0);

                    // Modern Linear-style Segmented Layout Control
                    egui::Frame::none()
                        .fill(Color32::from_rgb(12, 15, 22))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(30, 38, 54)))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(2.0, 2.0))
                        .show(ui, |ui| {
                            ui.spacing_mut().item_spacing.x = 2.0;
                            let seg_btn = |ui: &mut egui::Ui, text: &str, active: bool| -> egui::Response {
                                let (fill, stroke, text_color) = if active {
                                    (
                                        Color32::from_rgb(37, 99, 235),
                                        egui::Stroke::new(1.0_f32, Color32::from_rgb(96, 165, 250)),
                                        Color32::WHITE,
                                    )
                                } else {
                                    (
                                        Color32::TRANSPARENT,
                                        egui::Stroke::NONE,
                                        Color32::from_rgb(160, 175, 195),
                                    )
                                };
                                ui.add(
                                    egui::Button::new(RichText::new(text).color(text_color).size(11.5))
                                        .fill(fill)
                                        .stroke(stroke)
                                        .rounding(4.0)
                                        .min_size(egui::vec2(0.0, toolbar_h - 4.0))
                                )
                            };
                            let lang = self.language;
                            if seg_btn(ui, tr(lang, "🗖 Single", "🗖 1 Khung"), self.split_mode == SplitMode::Single).clicked() {
                                self.split_mode = SplitMode::Single;
                            }
                            if seg_btn(ui, tr(lang, "◫ 2-Cols", "◫ 2 Cột"), self.split_mode == SplitMode::Horizontal).clicked() {
                                self.split_mode = SplitMode::Horizontal;
                            }
                            if seg_btn(ui, tr(lang, "⬒ 2-Rows", "⬒ 2 Hàng"), self.split_mode == SplitMode::Vertical).clicked() {
                                self.split_mode = SplitMode::Vertical;
                            }
                            if seg_btn(ui, tr(lang, "⊞ 2x2 Grid", "⊞ Lưới 2x2"), self.split_mode == SplitMode::Grid2x2).clicked() {
                                self.split_mode = SplitMode::Grid2x2;
                            }
                        });

                    ui.add_space(5.0);
                    ui.separator();
                    ui.add_space(5.0);

                    // Multi-Exec toggle
                    let lang = self.language;
                    let multi_btn = if self.multi_exec_enabled {
                        egui::Button::new(RichText::new(tr(lang, "⚡ Multi-Exec: ON", "⚡ Gõ đồng loạt: BẬT")).color(Color32::WHITE).size(12.0).strong())
                            .fill(Color32::from_rgb(217, 119, 6))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(251, 191, 36)))
                    } else {
                        egui::Button::new(RichText::new(tr(lang, "⚡ Multi-Exec: OFF", "⚡ Gõ đồng loạt: TẮT")).color(Color32::from_rgb(148, 163, 184)).size(12.0))
                            .fill(Color32::from_rgb(22, 28, 40))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(36, 46, 64)))
                    }
                    .rounding(6.0)
                    .min_size(egui::vec2(0.0, toolbar_h));
                    if ui.add(multi_btn).on_hover_text(tr(lang, "Broadcast input to all open split terminals simultaneously", "Gửi lệnh đồng thời tới tất cả các khung terminal đang mở")).clicked() {
                        self.multi_exec_enabled = !self.multi_exec_enabled;
                    }

                    ui.add_space(5.0);
                    ui.separator();
                    ui.add_space(5.0);

                    // Find in terminal
                    if tb_button(ui, tr(lang, "🔍 Find", "🔍 Tìm kiếm"), self.search_open).clicked() {
                        self.search_open = !self.search_open;
                    }

                    // Dual UI Scale & Terminal Font stepper in modern unified container
                    egui::Frame::none()
                        .fill(Color32::from_rgb(22, 28, 40))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(36, 46, 64)))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                        .show(ui, |ui| {
                            ui.set_height(toolbar_h);
                            ui.horizontal(|ui| {
                                // UI Font / Scale Zoom
                                ui.label(RichText::new(tr(lang, "UI:", "Giao diện:")).color(Color32::from_rgb(148, 163, 184)).size(11.0));
                                if ui.small_button("➖").on_hover_text(tr(lang, "Zoom out UI font (Ctrl+Shift+-)", "Thu nhỏ giao diện (Ctrl+Shift+-)")).clicked() && self.ui_scale > 0.75 {
                                    self.ui_scale = (self.ui_scale - 0.1).max(0.7);
                                    let _ = self.persist_preferences();
                                }
                                let pct = (self.ui_scale * 100.0).round() as i32;
                                if ui.button(RichText::new(format!("{}%", pct)).size(11.0).strong())
                                    .on_hover_text(tr(lang, "Click to reset UI Zoom to 100%", "Nhấn để đặt lại tỉ lệ giao diện 100%"))
                                    .clicked() {
                                    self.ui_scale = 1.0;
                                    let _ = self.persist_preferences();
                                }
                                if ui.small_button("➕").on_hover_text(tr(lang, "Zoom in UI font (Ctrl+Shift++)", "Phóng to giao diện (Ctrl+Shift++)")).clicked() && self.ui_scale < 2.0 {
                                    self.ui_scale = (self.ui_scale + 0.1).min(2.0);
                                    let _ = self.persist_preferences();
                                }

                                ui.separator();

                                // Terminal Font Size
                                ui.label(RichText::new(tr(lang, "Term:", "Chữ:")).color(Color32::from_rgb(148, 163, 184)).size(11.0));
                                if ui.small_button("➖").on_hover_text(tr(lang, "Decrease terminal font size (Ctrl+-)", "Giảm cỡ chữ Terminal (Ctrl+-)")).clicked() && self.font_size > 8.0 {
                                    self.font_size -= 1.0;
                                    let _ = self.persist_preferences();
                                }
                                ui.label(RichText::new(format!("{:.0}px", self.font_size)).size(11.0).strong());
                                if ui.small_button("➕").on_hover_text(tr(lang, "Increase terminal font size (Ctrl++)", "Tăng cỡ chữ Terminal (Ctrl++)")).clicked() && self.font_size < 32.0 {
                                    self.font_size += 1.0;
                                    let _ = self.persist_preferences();
                                }
                            });
                        });

                    // Theme selector in a modern unified container
                    egui::Frame::none()
                        .fill(Color32::from_rgb(22, 28, 40))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(36, 46, 64)))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(4.0, 1.0))
                        .show(ui, |ui| {
                            ui.set_height(toolbar_h);
                            let prev_theme = self.theme;
                            egui::ComboBox::from_id_salt("toolbar_theme_select")
                                .selected_text(RichText::new(self.theme.name()).size(11.0))
                                .show_ui(ui, |ui| {
                                    for t in TerminalTheme::all() {
                                        if ui.selectable_value(&mut self.theme, *t, t.name()).clicked()
                                            && let Some(tab) = self.open_tabs.get_mut(self.active_tab_idx)
                                                && let Some(ref mut s) = tab.session_def {
                                                    s.terminal_color_scheme = t.name().to_string();
                                                }
                                    }
                                });
                            if self.theme != prev_theme {
                                let _ = self.persist_preferences();
                                ui.ctx().request_repaint();
                            }
                        });

                    ui.add_space(5.0);
                    ui.separator();
                    ui.add_space(5.0);

                    // Master Password Vault status indicator
                    let is_vault_configured = self.storage.is_vault_configured();
                    let is_unlocked = self.storage.is_vault_unlocked();
                    let (v_icon, v_txt, v_col) = if !is_vault_configured {
                        ("🔑", tr(lang, "Master Key: Off", "Khóa chính: Tắt"), Color32::from_rgb(148, 163, 184))
                    } else if is_unlocked {
                        ("🔓", tr(lang, "Vault: Unlocked", "Két: Đã mở"), Color32::from_rgb(34, 197, 94))
                    } else {
                        ("🔒", tr(lang, "Vault: Locked", "Két: Đang khóa"), Color32::from_rgb(251, 191, 36))
                    };
                    if ui.add(
                        egui::Button::new(RichText::new(format!("{} {}", v_icon, v_txt)).size(11.0).color(v_col).strong())
                            .fill(Color32::from_rgb(22, 28, 40))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(36, 46, 64)))
                            .rounding(6.0)
                            .min_size(egui::vec2(0.0, toolbar_h))
                    ).on_hover_text(tr(lang, "Manage Master Password & AES-256-GCM Vault", "Quản lý Mật khẩu chính & Két bảo mật AES-256-GCM")).clicked() {
                        self.show_vault = true;
                    }
                });
            });

        // 3. COMPACT BOTTOM PANEL (Quick Macros + Real-time System Telemetry)
        TopBottomPanel::bottom("bottom_bar")
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(14, 18, 25))
                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(26, 33, 46)))
                    .inner_margin(egui::Margin::symmetric(10.0, 3.5))
            )
            .min_height(26.0)
            .show(ctx, |ui| {
                let avail_w = ui.available_width();
                let telem_w = 660.0f32.min(avail_w * 0.55);
                let macros_w = (avail_w - telem_w - 12.0).max(100.0);

                let bottom_rect = ui.available_rect_before_wrap();
                let macros_rect = egui::Rect::from_min_max(bottom_rect.min, pos2(bottom_rect.min.x + macros_w, bottom_rect.max.y));
                let telem_rect = egui::Rect::from_min_max(pos2(bottom_rect.max.x - telem_w, bottom_rect.min.y), bottom_rect.max);

                // LEFT: QUICK MACROS (Scrollable without scrollbar so it never collides with telemetry)
                let mut macros_ui = ui.new_child(egui::UiBuilder::new().max_rect(macros_rect).layout(Layout::left_to_right(Align::Center)));
                egui::ScrollArea::horizontal()
                    .id_salt("quick_macros_scroll")
                    .auto_shrink([false, false])
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                    .show(&mut macros_ui, |ui| {
                        let lang = self.language;
                        ui.label(RichText::new(tr(lang, "⚡ Quick:", "⚡ Nhanh:")).weak().size(11.0).color(Color32::from_rgb(148, 163, 184)));
                        let mut macro_to_run: Option<String> = None;
                        for (name, cmd) in &self.quick_macros {
                            let pill = egui::Button::new(
                                RichText::new(name).size(11.0).color(Color32::from_rgb(220, 230, 245))
                            )
                            .fill(Color32::from_rgb(22, 28, 40))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(36, 46, 64)))
                            .rounding(6.0);
                            if ui.add(pill).clicked() {
                                macro_to_run = Some(cmd.clone());
                            }
                        }
                        if ui.add(
                            egui::Button::new(RichText::new(tr(lang, "⚙ Manage", "⚙ Quản lý")).size(11.0).color(Color32::from_rgb(148, 163, 184)))
                                .fill(Color32::from_rgb(18, 23, 33))
                                .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(32, 40, 56)))
                                .rounding(5.0)
                        ).clicked() {
                            self.show_macro_manager = true;
                        }
                        if let Some(cmd) = macro_to_run {
                            self.execute_macro(&cmd);
                        }
                    });

                // RIGHT: LIVE SYSTEM TELEMETRY MONITOR (per active tab / server)
                let mut telem_ui = ui.new_child(egui::UiBuilder::new().max_rect(telem_rect).layout(Layout::right_to_left(Align::Center)));
                telem_ui.set_clip_rect(telem_rect);
                {
                    let ui = &mut telem_ui;
                    let telem = self.get_active_telemetry();
                    let stat_chip = |ui: &mut egui::Ui, text: RichText| {
                        egui::Frame::none()
                            .fill(Color32::from_rgb(18, 24, 35))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(30, 40, 58)))
                            .rounding(5.0)
                            .inner_margin(egui::Margin::symmetric(6.0, 1.5))
                            .show(ui, |ui| {
                                ui.label(text);
                            });
                    };

                        // 1. Host (Far right)
                        let host_display = if !telem.host.is_empty() { &telem.host } else { "--" };
                        stat_chip(ui, RichText::new(format!("🖥 {}", host_display)).strong().size(10.5).color(Color32::WHITE));

                        // 2. CPU with visual gauge or placeholder
                        match telem.cpu_pct {
                            Some(cpu_pct) => {
                                let cpu_frac = (cpu_pct as f32 / 100.0).clamp(0.0, 1.0);
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(18, 24, 35))
                                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(30, 40, 58)))
                                    .rounding(5.0)
                                    .inner_margin(egui::Margin::symmetric(7.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(format!("⚡ {}%", cpu_pct)).size(10.5).color(Color32::from_rgb(220, 230, 245)));
                                            let (rect, _) = ui.allocate_exact_size(egui::vec2(28.0, 6.0), egui::Sense::hover());
                                            ui.painter().rect_filled(rect, 2.5, Color32::from_rgb(30, 38, 52));
                                            let mut filled_rect = rect;
                                            filled_rect.set_width(rect.width() * cpu_frac);
                                            let bar_color = if cpu_pct > 75 {
                                                Color32::from_rgb(239, 68, 68)
                                            } else if cpu_pct > 50 {
                                                Color32::from_rgb(245, 158, 11)
                                            } else {
                                                Color32::from_rgb(34, 197, 94)
                                            };
                                            ui.painter().rect_filled(filled_rect, 2.5, bar_color);
                                        });
                                    });
                            }
                            None => {
                                stat_chip(ui, RichText::new("⚡ --%").size(10.5).color(Color32::from_rgb(148, 163, 184)));
                            }
                        }

                        // 3. Cores
                        match telem.cores {
                            Some(cores) => {
                                stat_chip(ui, RichText::new(format!("⚙ {} Cores", cores)).color(Color32::from_rgb(167, 139, 250)).size(10.5));
                            }
                            None => {
                                stat_chip(ui, RichText::new("⚙ -- Cores").size(10.5).color(Color32::from_rgb(148, 163, 184)));
                            }
                        }

                        // 4. RAM with visual gauge or placeholder
                        match (telem.ram_used_gb, telem.ram_total_gb, telem.ram_pct) {
                            (Some(used), Some(total), _) => {
                                let ram_pct = (used / total.max(0.1)).clamp(0.0, 1.0);
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(18, 24, 35))
                                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(30, 40, 58)))
                                    .rounding(5.0)
                                    .inner_margin(egui::Margin::symmetric(7.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(format!("💾 {:.1}/{:.1}G", used, total)).size(10.5).color(Color32::from_rgb(220, 230, 245)));
                                            let (rect, _) = ui.allocate_exact_size(egui::vec2(28.0, 6.0), egui::Sense::hover());
                                            ui.painter().rect_filled(rect, 2.5, Color32::from_rgb(30, 38, 52));
                                            let mut filled_rect = rect;
                                            filled_rect.set_width(rect.width() * ram_pct);
                                            ui.painter().rect_filled(filled_rect, 2.5, Color32::from_rgb(56, 189, 248));
                                        });
                                    });
                            }
                            (_, _, Some(pct)) => {
                                let ram_pct = (pct as f32 / 100.0).clamp(0.0, 1.0);
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(18, 24, 35))
                                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(30, 40, 58)))
                                    .rounding(5.0)
                                    .inner_margin(egui::Margin::symmetric(7.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(format!("💾 {}%", pct)).size(10.5).color(Color32::from_rgb(220, 230, 245)));
                                            let (rect, _) = ui.allocate_exact_size(egui::vec2(28.0, 6.0), egui::Sense::hover());
                                            ui.painter().rect_filled(rect, 2.5, Color32::from_rgb(30, 38, 52));
                                            let mut filled_rect = rect;
                                            filled_rect.set_width(rect.width() * ram_pct);
                                            ui.painter().rect_filled(filled_rect, 2.5, Color32::from_rgb(56, 189, 248));
                                        });
                                    });
                            }
                            _ => {
                                stat_chip(ui, RichText::new("💾 --/--G").size(10.5).color(Color32::from_rgb(148, 163, 184)));
                            }
                        }

                        // 5. Network throughput
                        match telem.net_rate {
                            Some(ref rate) => {
                                stat_chip(ui, RichText::new(format!("🌐 {}", rate)).color(Color32::from_rgb(56, 189, 248)).size(10.5));
                            }
                            None => {
                                stat_chip(ui, RichText::new("🌐 --").size(10.5).color(Color32::from_rgb(148, 163, 184)));
                            }
                        }

                        // 6. Uptime
                        match telem.uptime {
                            Some(ref uptime) => {
                                stat_chip(ui, RichText::new(format!("⏱ {}", uptime)).size(10.5).color(Color32::from_rgb(156, 163, 175)));
                            }
                            None => {
                                stat_chip(ui, RichText::new("⏱ --").size(10.5).color(Color32::from_rgb(148, 163, 184)));
                            }
                        }

                        // 7. User
                        let user_str = if !telem.user.is_empty() { format!("👤 {}", telem.user) } else { "👤 --".to_string() };
                        stat_chip(ui, RichText::new(user_str).size(10.5).color(Color32::from_rgb(201, 209, 217)));

                        // 8. Disk usage
                        match telem.disk_pct {
                            Some(disk) => {
                                stat_chip(
                                    ui,
                                    RichText::new(format!("🖴 {}%", disk))
                                        .color(Color32::from_rgb(74, 222, 128))
                                        .size(10.5),
                                );
                            }
                            None => {
                                stat_chip(ui, RichText::new("🖴 --%").size(10.5).color(Color32::from_rgb(148, 163, 184)));
                            }
                        }

                        // 9. Multi-Exec Warning
                        let lang = self.language;
                        if self.multi_exec_enabled {
                            stat_chip(ui, RichText::new(tr(lang, "⚠ MULTI-EXEC", "⚠ ĐỒNG LOẠT")).color(Color32::from_rgb(251, 191, 36)).size(10.5).strong());
                        }

                        // 10. Connection status
                        if self.open_tabs.is_empty() || self.is_home_active {
                            stat_chip(ui, RichText::new(tr(lang, "○ Ready", "○ Sẵn sàng")).weak().size(10.5));
                        } else if telem.is_connected {
                            stat_chip(ui, RichText::new(tr(lang, "● Connected", "● Đã kết nối")).color(Color32::from_rgb(34, 197, 94)).size(10.5).strong());
                        } else {
                            stat_chip(ui, RichText::new(tr(lang, "✕ Disconnected", "✕ Mất kết nối")).color(Color32::from_rgb(239, 68, 68)).size(10.5).strong());
                        }
                    }
            });

        // 5. LEFT SIDEBAR (Sessions Tree & SFTP Explorer)
        if self.show_sftp_sidebar {
            // Auto-switch to SFTP tab if user drags external files over the sidebar while SFTP is connected
            if self.sidebar_tab == 0 && self.explorer.is_remote {
                let is_dragging_files = ctx.input(|i| !i.raw.hovered_files.is_empty());
                if is_dragging_files
                    && let Some(pos) = ctx.input(|i| i.pointer.hover_pos())
                        && pos.x <= 320.0 {
                            self.sidebar_tab = 1;
                        }
            }
            let max_sidebar_w = (ctx.screen_rect().width() * 0.50).max(320.0);
            ctx.style_mut(|s| {
                s.interaction.resize_grab_radius_side = 8.0;
            });
            let sidebar_resp = egui::SidePanel::left("left_sidebar")
                .frame(
                    egui::Frame::none()
                        .fill(Color32::from_rgb(14, 18, 25))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(26, 33, 46)))
                        .inner_margin(egui::Margin::symmetric(8.0, 8.0))
                )
                .resizable(true)
                .default_width(320.0)
                .width_range(180.0..=max_sidebar_w)
                .show(ctx, |ui| {
                    // Modern segmented pill switcher
                    egui::Frame::none()
                        .fill(Color32::from_rgb(10, 13, 19))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(28, 36, 50)))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(2.0, 2.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 2.0;
                                let btn_w = (ui.available_width() - 2.0) / 2.0;
                                let s_active = self.sidebar_tab == 0;
                                let sftp_active = self.sidebar_tab == 1;

                                let (s_fill, s_stroke, s_text) = if s_active {
                                    (Color32::from_rgb(37, 99, 235), egui::Stroke::new(1.0_f32, Color32::from_rgb(96, 165, 250)), Color32::WHITE)
                                } else {
                                    (Color32::TRANSPARENT, egui::Stroke::NONE, Color32::from_rgb(148, 163, 184))
                                };
                                let (sftp_fill, sftp_stroke, sftp_text) = if sftp_active {
                                    (Color32::from_rgb(37, 99, 235), egui::Stroke::new(1.0_f32, Color32::from_rgb(96, 165, 250)), Color32::WHITE)
                                } else {
                                    (Color32::TRANSPARENT, egui::Stroke::NONE, Color32::from_rgb(148, 163, 184))
                                };

                                if ui.add_sized([btn_w, 24.0], egui::Button::new(RichText::new(tr(lang, "📂 Sessions", "📂 Phiên")).size(11.0).strong().color(s_text)).fill(s_fill).stroke(s_stroke).rounding(5.0)).clicked() {
                                    self.sidebar_tab = 0;
                                }
                                if ui.add_sized([btn_w, 24.0], egui::Button::new(RichText::new(tr(lang, "📁 SFTP Browser", "📁 Trình duyệt SFTP")).size(11.0).strong().color(sftp_text)).fill(sftp_fill).stroke(sftp_stroke).rounding(5.0)).clicked() {
                                    self.sidebar_tab = 1;
                                }
                            });
                        });
                    ui.add_space(5.0);
                    ui.separator();
                    ui.add_space(5.0);

                    if self.sidebar_tab == 0 {
                        // SESSIONS TREE
                        // Modern Search bar with inline clear button
                        ui.horizontal(|ui| {
                            let filter_hint = match lang {
                                AppLanguage::English => format!("🔍 Filter {} sessions...", self.sessions.len()),
                                AppLanguage::Vietnamese => format!("🔍 Lọc {} phiên...", self.sessions.len()),
                            };
                            let has_search = !self.session_search.is_empty();
                            let avail_w = ui.available_width() - if has_search { 28.0 } else { 0.0 };
                            ui.add(
                                TextEdit::singleline(&mut self.session_search)
                                    .hint_text(filter_hint)
                                    .desired_width(avail_w),
                            );
                            if has_search
                                && ui
                                    .add(
                                        egui::Button::new(RichText::new("✖").size(11.0).color(Color32::from_rgb(148, 163, 184)))
                                            .fill(Color32::from_rgb(22, 28, 40))
                                            .rounding(4.0)
                                            .min_size(egui::vec2(22.0, 20.0)),
                                    )
                                    .on_hover_text(tr(lang, "Clear filter", "Xóa bộ lọc"))
                                    .clicked()
                            {
                                self.session_search.clear();
                            }
                        });
                        ui.add_space(6.0);

                        let is_searching = !self.session_search.trim().is_empty();

                        let mut grouped: BTreeMap<String, Vec<Session>> = BTreeMap::new();
                        for s in &self.sessions {
                            if s.matches_filter(&self.session_search) {
                                grouped.entry(s.folder.clone()).or_default().push(s.clone());
                            }
                        }
                        let total_filtered_sessions: usize = grouped.values().map(|v| v.len()).sum();

                        let mut to_launch: Option<Session> = None;
                        let mut to_connect_as: Option<(Session, String)> = None;
                        let mut to_ping_host: Option<String> = None;
                        let mut to_rename: Option<(String, String)> = None;
                        let mut to_edit: Option<Session> = None;
                        let mut to_delete_id: Option<String> = None;
                        let mut to_duplicate: Option<Session> = None;
                        let mut to_save_file: Option<Session> = None;
                        let mut to_create_shortcut: Option<Session> = None;
                        let mut to_save_preset: Option<Session> = None;
                        let mut to_copy_settings: Option<Session> = None;
                        let mut to_new_in_folder: Option<String> = None;
                        let mut to_rename_folder: Option<(String, String)> = None;
                        let mut to_delete_folder: Option<String> = None;

                        ScrollArea::vertical().show(ui, |ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.spacing_mut().button_padding = egui::vec2(4.0, 2.0);
                            ui.spacing_mut().indent = 16.0;
                            ui.visuals_mut().indent_has_left_vline = true;
                            ui.visuals_mut().widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(51, 65, 85));

                            let root_header = egui::CollapsingHeader::new(
                                RichText::new(match lang {
                                    AppLanguage::English => format!("★ User sessions ({})", total_filtered_sessions),
                                    AppLanguage::Vietnamese => format!("★ Phiên người dùng ({})", total_filtered_sessions),
                                })
                                    .color(Color32::from_rgb(234, 179, 8))
                                    .strong()
                                    .size(13.0),
                            )
                            .id_salt("user_sessions_root_tree")
                            .default_open(true)
                            .open(if is_searching { Some(true) } else { None });

                            let root_res = root_header.show(ui, |ui| {
                                for (folder, list) in grouped {
                                    let folder_name = folder.clone();
                                    let display_folder = if folder.is_empty() { "Default" } else { &folder };
                                    let folder_count = list.len();
                                    let folder_id = ui.make_persistent_id(format!("user_sessions_folder_{}", folder));
                                    let mut state = egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), folder_id, false);
                                    if is_searching {
                                        state.set_open(true);
                                    }
                                    let is_open = state.is_open();

                                    // Custom MobaXterm-style Folder Header Row (filled yellow folder icon + crisp white label + count badge)
                                    let header_res = ui.allocate_response(egui::vec2(ui.available_width(), 25.0), egui::Sense::click());
                                    let rect = header_res.rect;

                                    if header_res.clicked() {
                                        state.toggle(ui);
                                    }

                                    let bg = if header_res.hovered() {
                                        Color32::from_rgb(30, 41, 59)
                                    } else if is_open {
                                        Color32::from_rgb(20, 27, 40)
                                    } else {
                                        Color32::TRANSPARENT
                                    };
                                    if bg != Color32::TRANSPARENT {
                                        ui.painter().rect_filled(rect, 4.0, bg);
                                    }

                                    // +/- box or chevron like MobaXterm
                                    let box_center = egui::pos2(rect.left() + 8.0, rect.center().y);
                                    let box_rect = egui::Rect::from_center_size(box_center, egui::vec2(10.0, 10.0));
                                    ui.painter().rect_stroke(box_rect, 1.5, egui::Stroke::new(1.0, Color32::from_rgb(148, 163, 184)));
                                    // Horizontal line '-'
                                    ui.painter().line_segment(
                                        [egui::pos2(box_center.x - 2.5, box_center.y), egui::pos2(box_center.x + 2.5, box_center.y)],
                                        egui::Stroke::new(1.2, Color32::from_rgb(226, 232, 240)),
                                    );
                                    // Vertical line '+' when closed
                                    if !is_open {
                                        ui.painter().line_segment(
                                            [egui::pos2(box_center.x, box_center.y - 2.5), egui::pos2(box_center.x, box_center.y + 2.5)],
                                            egui::Stroke::new(1.2, Color32::from_rgb(226, 232, 240)),
                                        );
                                    }

                                    // Solid Filled Yellow Folder Icon drawn crisp with painter
                                    let f_left = rect.left() + 18.0;
                                    let f_top = rect.center().y - 6.0;
                                    let tab_rect = egui::Rect::from_min_size(egui::pos2(f_left, f_top), egui::vec2(7.0, 3.5));
                                    let body_rect = egui::Rect::from_min_size(egui::pos2(f_left, f_top + 2.5), egui::vec2(15.0, 10.0));
                                    let folder_fill = if is_open {
                                        Color32::from_rgb(250, 204, 21) // Vàng sáng
                                    } else {
                                        Color32::from_rgb(234, 179, 8) // Vàng đậm
                                    };
                                    let folder_flap = Color32::from_rgb(254, 240, 138);
                                    ui.painter().rect_filled(tab_rect, egui::Rounding { nw: 2.0, ne: 2.0, sw: 0.0, se: 0.0 }, Color32::from_rgb(202, 138, 4));
                                    ui.painter().rect_filled(body_rect, 2.0, folder_fill);
                                    if is_open {
                                        // Slight open flap highlight
                                        let open_rect = egui::Rect::from_min_size(egui::pos2(f_left + 1.5, f_top + 5.5), egui::vec2(14.5, 7.0));
                                        ui.painter().rect_filled(open_rect, 1.5, folder_flap);
                                    }

                                    // Folder Name (crisp off-white / bright white, readable like MobaXterm)
                                    let text_col = if is_open { Color32::from_rgb(254, 240, 138) } else { Color32::from_rgb(241, 245, 249) };
                                    ui.painter().text(
                                        egui::pos2(f_left + 21.0, rect.center().y),
                                        egui::Align2::LEFT_CENTER,
                                        display_folder,
                                        egui::FontId::proportional(13.0),
                                        text_col,
                                    );

                                    // Right-aligned session count badge
                                    let count_txt = format!("{}", folder_count);
                                    let badge_rect = egui::Rect::from_min_size(
                                        egui::pos2(rect.right() - 28.0, rect.center().y - 8.0),
                                        egui::vec2(22.0, 16.0),
                                    );
                                    ui.painter().rect_filled(badge_rect, 8.0, Color32::from_rgb(30, 41, 59));
                                    ui.painter().text(
                                        badge_rect.center(),
                                        egui::Align2::CENTER_CENTER,
                                        count_txt,
                                        egui::FontId::proportional(10.5),
                                        Color32::from_rgb(148, 163, 184),
                                    );

                                    state.show_body_indented(&header_res, ui, |ui| {
                                        for s in list {
                                        let icon = match s.session_type {
                                            SessionType::LocalShell { .. } => ">_ ",
                                            SessionType::Ssh { .. } => "🔑 ",
                                            SessionType::Serial { .. } => "🔌 ",
                                            SessionType::Telnet { .. } => "📡 ",
                                            SessionType::Rdp { .. } => "🖥 ",
                                            SessionType::Vnc { .. } => "👁 ",
                                            SessionType::Ftp { .. } => "📁 ",
                                            SessionType::Wsl { .. } => "🐧 ",
                                        };

                                        let subtitle = match &s.session_type {
                                            SessionType::LocalShell { .. } => "local terminal".to_string(),
                                            SessionType::Ssh { host, user, port, .. } => format!("{}@{}:{}", user, host, port),
                                            SessionType::Telnet { host, port } => format!("telnet://{}:{}", host, port),
                                            SessionType::Rdp { host, port, .. } => format!("rdp://{}:{}", host, port),
                                            SessionType::Vnc { host, port, .. } => format!("vnc://{}:{}", host, port),
                                            SessionType::Ftp { host, port, user } => format!("ftp://{}@{}:{}", user, host, port),
                                            SessionType::Serial { port_name, baud_rate, .. } => format!("{} @ {} baud", port_name, baud_rate),
                                            SessionType::Wsl { distro, .. } => format!("wsl ({})", distro),
                                        };

                                        let is_connected_tab = self.open_tabs.iter().any(|t| {
                                            t.session_def.as_ref().map(|def| def.id == s.id).unwrap_or(false) && t.session.is_alive()
                                        });
                                        let is_active_tab_session = !self.is_home_active
                                            && self.open_tabs.get(self.active_tab_idx)
                                                .and_then(|t| t.session_def.as_ref())
                                                .map(|def| def.id == s.id)
                                                .unwrap_or(false);

                                        let is_selected = self.selected_sidebar_session_id.as_deref() == Some(&s.id)
                                            || is_active_tab_session;

                                        let id = ui.make_persistent_id(&s.id);
                                        let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 38.0), egui::Sense::hover());
                                        let resp = ui.interact(rect, id, egui::Sense::click());

                                        if resp.clicked() {
                                            self.selected_sidebar_session_id = Some(s.id.clone());
                                            if !resp.double_clicked() {
                                                resp.request_focus();
                                            }
                                        } else if resp.secondary_clicked() {
                                            self.selected_sidebar_session_id = Some(s.id.clone());
                                        }

                                        let (bg, stroke) = if is_active_tab_session {
                                            (Color32::from_rgb(29, 78, 216), egui::Stroke::new(1.5_f32, Color32::from_rgb(56, 189, 248)))
                                        } else if is_selected {
                                            (Color32::from_rgb(37, 99, 235), egui::Stroke::new(1.0_f32, Color32::from_rgb(96, 165, 250)))
                                        } else if resp.hovered() {
                                            (Color32::from_rgb(24, 32, 46), egui::Stroke::new(1.0_f32, Color32::from_rgb(38, 50, 72)))
                                        } else {
                                            (Color32::TRANSPARENT, egui::Stroke::NONE)
                                        };
                                        ui.painter().rect(rect, 6.0, bg, stroke);

                                        let text_color = if is_selected { Color32::WHITE } else { Color32::from_rgb(220, 230, 242) };
                                        let sub_color = if is_selected { Color32::from_rgb(200, 225, 255) } else { Color32::from_rgb(139, 148, 158) };
                                        let icon_color = if is_selected { Color32::WHITE } else { Color32::from_rgb(56, 189, 248) };

                                        ui.painter().text(
                                            egui::pos2(rect.left() + 8.0, rect.top() + 11.0),
                                            egui::Align2::LEFT_CENTER,
                                            icon,
                                            egui::FontId::proportional(12.5),
                                            icon_color,
                                        );
                                        ui.painter().text(
                                            egui::pos2(rect.left() + 28.0, rect.top() + 11.0),
                                            egui::Align2::LEFT_CENTER,
                                            &s.name,
                                            egui::FontId::proportional(12.5),
                                            text_color,
                                        );
                                        ui.painter().text(
                                            egui::pos2(rect.left() + 28.0, rect.top() + 25.0),
                                            egui::Align2::LEFT_CENTER,
                                            &subtitle,
                                            egui::FontId::proportional(10.5),
                                            sub_color,
                                        );
                                        if is_active_tab_session {
                                            let badge_x = if is_connected_tab { rect.right() - 24.0 } else { rect.right() - 10.0 };
                                            ui.painter().text(
                                                egui::pos2(badge_x, rect.top() + 10.0),
                                                egui::Align2::RIGHT_CENTER,
                                                "ACTIVE",
                                                egui::FontId::proportional(8.5),
                                                Color32::from_rgb(74, 222, 128),
                                            );
                                        }
                                        if is_connected_tab {
                                            let dot_pos = egui::pos2(rect.right() - 14.0, rect.center().y);
                                            ui.painter().circle_filled(dot_pos, 4.0, Color32::from_rgb(34, 197, 94));
                                        }

                                        let row_enter_launch = resp.has_focus()
                                            && !self.is_any_modal_open()
                                            && ui.input_mut(|i| {
                                                i.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                                            });
                                        if resp.double_clicked() || row_enter_launch {
                                            resp.surrender_focus();
                                            to_launch = Some(s.clone());
                                        }
                                        resp.context_menu(|ui| {
                                            ui.set_min_width(210.0);
                                            if ui.button(RichText::new(tr(lang, "★ Execute", "★ Kết nối ngay")).strong().color(Color32::from_rgb(234, 179, 8))).clicked() {
                                                to_launch = Some(s.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button(tr(lang, "👤 Connect as...", "👤 Kết nối bằng tài khoản khác...")).clicked() {
                                                let cur_user = match &s.session_type {
                                                    SessionType::Ssh { user, .. } => user.clone(),
                                                    _ => "root".to_string(),
                                                };
                                                to_connect_as = Some((s.clone(), cur_user));
                                                ui.close_menu();
                                            }
                                            if let Some(h) = s.host_str()
                                                && ui.button(tr(lang, "🌐 Ping host", "🌐 Ping máy chủ")).clicked() {
                                                    to_ping_host = Some(h);
                                                    ui.close_menu();
                                                }
                                            ui.separator();
                                            if ui.button(tr(lang, "📝 Rename session", "📝 Đổi tên phiên")).clicked() {
                                                to_rename = Some((s.id.clone(), s.name.clone()));
                                                ui.close_menu();
                                            }
                                            if ui.button(tr(lang, "⚙ Edit session", "⚙ Sửa phiên")).clicked() {
                                                to_edit = Some(s.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button(RichText::new(tr(lang, "× Delete session", "× Xóa phiên")).strong().color(Color32::from_rgb(239, 68, 68))).clicked() {
                                                to_delete_id = Some(s.id.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button(tr(lang, "🔑 Duplicate session", "🔑 Nhân bản phiên")).clicked() {
                                                to_duplicate = Some(s.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button(tr(lang, "💾 Save session to file", "💾 Lưu phiên ra tệp")).clicked() {
                                                to_save_file = Some(s.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button(tr(lang, "☆ Create a desktop shortcut", "☆ Tạo lối tắt Desktop")).clicked() {
                                                to_create_shortcut = Some(s.clone());
                                                ui.close_menu();
                                            }
                                            ui.separator();
                                            if ui.button(tr(lang, "📥 Save session settings as default presets", "📥 Lưu làm cấu hình mặc định")).clicked() {
                                                to_save_preset = Some(s.clone());
                                                ui.close_menu();
                                            }
                                            if ui.button(tr(lang, "📋 Copy session settings", "📋 Sao chép cấu hình phiên")).clicked() {
                                                to_copy_settings = Some(s.clone());
                                                ui.close_menu();
                                            }
                                        });
                                    }
                                });

                                header_res.context_menu(|ui| {
                                    if ui.button(tr(lang, "➕ New session in this folder...", "➕ Tạo phiên trong thư mục này...")).clicked() {
                                        to_new_in_folder = Some(folder_name.clone());
                                        ui.close_menu();
                                    }
                                    if ui.button(tr(lang, "📁 Rename folder...", "📁 Đổi tên thư mục...")).clicked() {
                                        to_rename_folder = Some((folder_name.clone(), folder_name.clone()));
                                        ui.close_menu();
                                    }
                                    if ui.button(RichText::new(tr(lang, "✕ Delete folder", "✕ Xóa thư mục")).color(Color32::from_rgb(239, 68, 68))).clicked() {
                                        to_delete_folder = Some(folder_name.clone());
                                        ui.close_menu();
                                    }
                                });
                            }
                            });

                            root_res.header_response.context_menu(|ui| {
                                if ui.button(tr(lang, "➕ New Session...", "➕ Phiên mới...")).clicked() {
                                    self.new_session_dialog.open_for_new();
                                    ui.close_menu();
                                }
                            });

                            ui.add_space(8.0);
                            ui.separator();
                            ui.add_space(2.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(tr(lang, "💡 Tip:", "💡 Mẹo:")).color(Color32::from_rgb(234, 179, 8)).size(10.5).strong());
                                ui.label(RichText::new(tr(lang, "Double-click to connect · Right-click for menu", "Nhấn đúp để kết nối · Chuột phải để mở menu")).color(Color32::from_rgb(148, 163, 184)).size(10.5));
                            });
                        });

                        if let Some(s) = to_launch {
                            self.launch_generic_session(s);
                        }
                        if let Some((s, u)) = to_connect_as {
                            self.connect_as_target = Some((s, u));
                        }
                        if let Some(h) = to_ping_host {
                            self.show_network_tools = true;
                            self.net_tools_tab = 2;
                            self.network_tools.ping_host = h;
                            self.network_tools.ping_logs.lock().clear();
                        }
                        if let Some((id, name)) = to_rename {
                            self.rename_session_target = Some((id, name));
                        }
                        if let Some(s) = to_edit {
                            self.new_session_dialog.open_for_edit(&s);
                        }
                        if let Some(del_id) = to_delete_id {
                            self.sessions.retain(|item| item.id != del_id);
                            let _ = self.storage.save_sessions(&self.sessions);
                        }
                        if let Some(dup_s) = to_duplicate {
                            let mut copy = dup_s.clone();
                            copy.id = uuid::Uuid::new_v4().to_string();
                            copy.name = format!("{} (Copy)", copy.name);
                            self.sessions.push(copy);
                            let _ = self.storage.save_sessions(&self.sessions);
                        }
                        if let Some(save_s) = to_save_file
                            && let Some(path) = rfd::FileDialog::new()
                                .set_file_name(format!("{}.json", save_s.name.replace('/', "_")))
                                .add_filter("JSON session", &["json"])
                                .save_file()
                                && let Ok(json) = serde_json::to_string_pretty(&save_s) {
                                    let _ = std::fs::write(path, json);
                                }
                        if let Some(sc_s) = to_create_shortcut {
                            #[cfg(target_os = "windows")]
                            {
                                if let Some(desktop) = dirs::desktop_dir() {
                                    let safe_name = sc_s.name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
                                    let bat_path = desktop.join(format!("{}.bat", safe_name));
                                    let content = format!("@echo off\r\nstart \"\" \"%~dp0RustyBox.exe\" --session \"{}\"\r\n", sc_s.name);
                                    let _ = std::fs::write(&bat_path, content);
                                    self.status_toast = Some((format!("Shortcut created: {}.bat", safe_name), std::time::Instant::now()));
                                }
                            }
                            #[cfg(not(target_os = "windows"))]
                            {
                                if let Some(desktop) = dirs::desktop_dir() {
                                    let safe_name = sc_s.name.replace('/', "_");
                                    let sh_path = desktop.join(format!("{}.sh", safe_name));
                                    let content = format!("#!/bin/sh\nrustybox --session \"{}\"\n", sc_s.name);
                                    let _ = std::fs::write(&sh_path, content);
                                    self.status_toast = Some((format!("Shortcut created: {}.sh", safe_name), std::time::Instant::now()));
                                }
                            }
                        }
                        if let Some(preset_s) = to_save_preset {
                            self.status_toast = Some((format!("Saved preset for '{}'", preset_s.name), std::time::Instant::now()));
                        }
                        if let Some(copy_s) = to_copy_settings
                            && let Ok(json) = serde_json::to_string(&copy_s) {
                                copy_text_to_clipboard(ui, &json);
                                self.status_toast = Some(("Session settings copied to clipboard".into(), std::time::Instant::now()));
                            }
                        if let Some(f) = to_new_in_folder {
                            self.new_session_dialog.open_for_new_in_folder(&f);
                        }
                        if let Some((old_f, new_f)) = to_rename_folder {
                            self.rename_folder_target = Some((old_f, new_f));
                        }
                        if let Some(f_del) = to_delete_folder {
                            self.sessions.retain(|s| s.folder != f_del);
                            let _ = self.storage.save_sessions(&self.sessions);
                        }
                    } else {
                        // SFTP BROWSER
                        let prev_mon = self.explorer.remote_monitoring_enabled;
                        let prev_follow = self.explorer.follow_terminal_folder;
                        if !self.is_home_active && self.explorer.follow_terminal_folder {
                            self.sync_terminal_cwd_if_enabled();
                        }
                        render_sftp_sidebar(ui, &mut self.explorer, self.language);
                        if self.explorer.remote_monitoring_enabled != prev_mon
                            || self.explorer.follow_terminal_folder != prev_follow
                        {
                            let _ = self.storage.save_sftp_preferences(
                                self.explorer.remote_monitoring_enabled,
                                self.explorer.follow_terminal_folder,
                            );
                        }
                    }
                });

            // Visual splitter handle & cursor feedback on right border of sidebar
            let r_edge = sidebar_resp.response.rect.right();
            let splitter_rect = egui::Rect::from_min_max(
                pos2(r_edge - 4.0, sidebar_resp.response.rect.top()),
                pos2(r_edge + 4.0, sidebar_resp.response.rect.bottom()),
            );
            let mouse_pos = ctx.input(|i| i.pointer.hover_pos());
            let is_splitter_hovered = mouse_pos.is_some_and(|p| splitter_rect.contains(p));
            if is_splitter_hovered {
                ctx.set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
                let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("sidebar_splitter_indicator")));
                painter.line_segment(
                    [pos2(r_edge, sidebar_resp.response.rect.top()), pos2(r_edge, sidebar_resp.response.rect.bottom())],
                    egui::Stroke::new(2.0_f32, Color32::from_rgb(56, 189, 248)),
                );
            }
        }

        // 6. CENTER WORKSPACE (Tabs Header, Search Bar & Terminals Grid)
        let mut triggered_action = TerminalAction::None;

        let center_frame = egui::Frame::central_panel(&ctx.style())
            .fill(Color32::from_rgb(15, 18, 26));
        egui::CentralPanel::default().frame(center_frame).show(ctx, |ui| {
            // TAB BAR HEADER (Full-width Tabs strip + optional Tab Switcher dropdown)
            let strip_height = 28.0;
            let (strip_rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), strip_height), egui::Sense::hover());
            let tab_count = self.open_tabs.len();
            let tabs_overflow_id = ui.id().with("tabs_bar_overflow");
            let prev_overflow: bool = ui.ctx().data(|d| d.get_temp(tabs_overflow_id).unwrap_or(false));
            let switcher_w = if tab_count > 1 {
                if prev_overflow { 104.0f32 } else { 60.0f32 }
            } else {
                0.0f32
            };
            let right_w = switcher_w;
            let tabs_rect = if right_w > 0.0 {
                egui::Rect::from_min_max(strip_rect.min, pos2(strip_rect.max.x - right_w - 4.0, strip_rect.max.y))
            } else {
                strip_rect
            };
            let right_rect = egui::Rect::from_min_max(pos2(strip_rect.max.x - right_w, strip_rect.min.y), strip_rect.max);

            let mut close_tab_idx: Option<usize> = None;
            let mut switch_to_tab: Option<usize> = None;
            enum TabMenuAction { Duplicate, Restart, Rename, Close, CloseOthers, CloseRight }
            let mut tab_menu_action: Option<(usize, TabMenuAction)> = None;

            // Dynamic tab width: smoothly scales so all tabs fit cleanly without clipping
            let avail_tabs_w = (tabs_rect.width() - 85.0).max(60.0);
            let num_tabs = self.open_tabs.len().max(1);
            let dynamic_tab_w = ((avail_tabs_w - 20.0) / num_tabs as f32).clamp(80.0, 180.0);

            // 1. TABS AREA (Home + Scrollable tab strip, scrollbar hidden so it never steals tab clicks/hover)
            let mut tabs_ui = ui.new_child(egui::UiBuilder::new().max_rect(tabs_rect).layout(Layout::left_to_right(Align::Center)));
            let tab_scroll_out = ScrollArea::horizontal()
                .id_salt("tabs_scroll_area")
                .auto_shrink([false, false])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                .show(&mut tabs_ui, |ui| {
                    ui.horizontal(|ui| {
                        // Home Tab (Engineered inside the exact same row as all other tabs)
                        let is_home = self.is_home_active;
                        let (home_rect, home_resp) = ui.allocate_exact_size(vec2(76.0, 26.0), egui::Sense::click());
                        let home_hovered = home_resp.hovered();

                        let (h_fill, h_stroke, h_text) = if is_home {
                            (
                                Color32::from_rgb(26, 36, 56),
                                egui::Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248)),
                                Color32::WHITE,
                            )
                        } else if home_hovered {
                            (
                                Color32::from_rgb(28, 36, 48),
                                egui::Stroke::new(1.0_f32, Color32::from_rgb(48, 58, 76)),
                                Color32::from_rgb(215, 225, 238),
                            )
                        } else {
                            (
                                Color32::from_rgb(20, 26, 36),
                                egui::Stroke::new(1.0_f32, Color32::from_rgb(34, 44, 60)),
                                Color32::from_rgb(160, 172, 188),
                            )
                        };

                        // Background tab frame
                        ui.painter().rect(
                            home_rect,
                            egui::Rounding { nw: 6.0, ne: 6.0, sw: 0.0, se: 0.0 },
                            h_fill,
                            h_stroke,
                        );

                        // Electric cyan top line for active Home tab
                        if is_home {
                            ui.painter().line_segment(
                                [pos2(home_rect.left() + 2.0, home_rect.top() + 1.0), pos2(home_rect.right() - 2.0, home_rect.top() + 1.0)],
                                egui::Stroke::new(2.5_f32, Color32::from_rgb(56, 189, 248)),
                            );
                        }

                        // Centered icon and title
                        ui.painter().text(
                            home_rect.center(),
                            egui::Align2::CENTER_CENTER,
                            tr(lang, "🏠 Home", "🏠 Trang chủ"),
                            egui::FontId::proportional(11.5),
                            h_text,
                        );

                        if home_resp.clicked() {
                            self.is_home_active = true;
                            self.sync_sidebar_with_active_tab();
                        }

                        ui.add_space(2.0);

                        for (idx, tab) in self.open_tabs.iter().enumerate() {
                                let is_active = !self.is_home_active && idx == self.active_tab_idx;
                                let _tab_id = &tab.id;

                                let tab_w = dynamic_tab_w;
                                let title_w = (tab_w - 22.0).max(40.0);
                                let (title_rect, title_resp) = ui.allocate_exact_size(
                                    vec2(title_w, 26.0),
                                    egui::Sense::click(),
                                );
                                let (close_rect, close_resp) = ui.allocate_exact_size(
                                    vec2(22.0, 26.0),
                                    egui::Sense::click(),
                                );
                                let tab_rect = egui::Rect::from_min_max(title_rect.min, close_rect.max);
                                let tab_hovered = title_resp.hovered() || close_resp.hovered();

                                if is_active && self.scroll_active_tab_into_view {
                                    title_resp.scroll_to_me(Some(egui::Align::Center));
                                }

                                let (fill, stroke, text_color) = if is_active {
                                    (
                                        Color32::from_rgb(26, 36, 56),
                                        egui::Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248)),
                                        Color32::WHITE,
                                    )
                                } else if tab_hovered {
                                    (
                                        Color32::from_rgb(28, 36, 48),
                                        egui::Stroke::new(1.0_f32, Color32::from_rgb(48, 58, 76)),
                                        Color32::from_rgb(215, 225, 238),
                                    )
                                } else {
                                    (
                                        Color32::from_rgb(20, 26, 36),
                                        egui::Stroke::new(1.0_f32, Color32::from_rgb(34, 44, 60)),
                                        Color32::from_rgb(160, 172, 188),
                                    )
                                };

                                // Render tab background frame with modern rounded top corners
                                ui.painter().rect(
                                    tab_rect,
                                    egui::Rounding { nw: 6.0, ne: 6.0, sw: 0.0, se: 0.0 },
                                    fill,
                                    stroke,
                                );

                                // Electric cyan top line for active tab
                                if is_active {
                                    ui.painter().line_segment(
                                        [pos2(tab_rect.left() + 2.0, tab_rect.top() + 1.0), pos2(tab_rect.right() - 2.0, tab_rect.top() + 1.0)],
                                        egui::Stroke::new(2.5_f32, Color32::from_rgb(56, 189, 248)),
                                    );
                                }

                                // Status dot
                                let dot_center = pos2(tab_rect.left() + 9.0, tab_rect.center().y);
                                let is_alive = tab.session.is_alive();
                                let dot_col = if is_alive {
                                    Color32::from_rgb(34, 197, 94) // Green alive
                                } else {
                                    Color32::from_rgb(239, 68, 68) // Red stopped / error
                                };
                                ui.painter().circle_filled(dot_center, 3.5, dot_col);

                                // Icon
                                let icon = if tab.title.contains("SSH") {
                                    "🔒 "
                                } else if tab.title.contains("WSL") {
                                    "🐧 "
                                } else if tab.title.contains("Telnet") {
                                    "⚡ "
                                } else {
                                    ">_ "
                                };

                                // Title text with dynamic truncation based on actual tab width
                                let full_title = format!("{}{}", icon, tab.title);
                                let clean_title = tab.title.trim_start_matches("SSH: ").trim();
                                let max_chars = (((tab_w - 38.0) / 7.0) as usize).clamp(7, 22);
                                let display_title = if clean_title.chars().count() > max_chars {
                                    let s: String = clean_title.chars().take(max_chars.saturating_sub(1)).collect();
                                    format!("{}{}\u{2026}", icon, s)
                                } else {
                                    format!("{}{}", icon, clean_title)
                                };

                                let text_pos = pos2(tab_rect.left() + 16.0, tab_rect.center().y - 6.5);
                                ui.painter().text(
                                    text_pos,
                                    Align2::LEFT_TOP,
                                    display_title,
                                    egui::FontId::proportional(11.0),
                                    text_color,
                                );

                                // Close icon rendering (crisp anti-aliased cross, no font tofu)
                                let close_center = pos2(close_rect.center().x, close_rect.center().y);
                                let r_x = 3.5;
                                if close_resp.hovered() {
                                    ui.painter().circle_filled(
                                        close_center,
                                        7.5,
                                        Color32::from_rgb(220, 38, 38),
                                    );
                                    let stroke = egui::Stroke::new(1.4_f32, Color32::WHITE);
                                    ui.painter().line_segment([pos2(close_center.x - r_x, close_center.y - r_x), pos2(close_center.x + r_x, close_center.y + r_x)], stroke);
                                    ui.painter().line_segment([pos2(close_center.x - r_x, close_center.y + r_x), pos2(close_center.x + r_x, close_center.y - r_x)], stroke);
                                } else {
                                    let stroke = egui::Stroke::new(1.3_f32, if is_active { Color32::from_rgb(248, 113, 113) } else { Color32::from_rgb(140, 150, 160) });
                                    ui.painter().line_segment([pos2(close_center.x - r_x, close_center.y - r_x), pos2(close_center.x + r_x, close_center.y + r_x)], stroke);
                                    ui.painter().line_segment([pos2(close_center.x - r_x, close_center.y + r_x), pos2(close_center.x + r_x, close_center.y - r_x)], stroke);
                                }

                                let tab_middle_clicked = title_resp.middle_clicked() || close_resp.middle_clicked();
                                if close_resp.clicked() || tab_middle_clicked {
                                    close_tab_idx = Some(idx);
                                } else if title_resp.clicked() {
                                    switch_to_tab = Some(idx);
                                }

                                let right_clicked = title_resp.secondary_clicked() || (title_resp.hovered() && ui.input(|i| i.pointer.button_clicked(egui::PointerButton::Secondary)));
                                if right_clicked {
                                    let p = ui.input(|i| i.pointer.interact_pos()).unwrap_or_else(|| pos2(title_rect.left(), title_rect.bottom() + 2.0));
                                    self.tab_context_menu = Some((idx, p));
                                }

                                let tip = match lang {
                                    AppLanguage::English => format!("{}\nStatus: {}\nClick to switch • Middle-click or ✕ to close • Right-click for menu", full_title, if is_alive { "Connected" } else { "Disconnected / Stopped" }),
                                    AppLanguage::Vietnamese => format!("{}\nTrạng thái: {}\nNhấp để chuyển • Chuột giữa hoặc ✕ để đóng • Chuột phải để mở menu", full_title, if is_alive { "Đang kết nối" } else { "Đã ngắt kết nối / Dừng" }),
                                };
                                title_resp.on_hover_text(tip);
                            }

                            // '+' Button right after tabs in scroll area
                            let add_btn = egui::Button::new(
                                RichText::new("+").size(15.0).strong().color(Color32::from_rgb(180, 190, 200)),
                            )
                            .fill(Color32::from_rgb(30, 36, 46))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 61)))
                            .rounding(4.0)
                            .min_size(egui::vec2(24.0, 24.0));
                            if ui.add(add_btn).on_hover_text(tr(lang, "Open new local terminal", "Mở Terminal cục bộ mới")).clicked() {
                                self.spawn_local_terminal("Local Terminal", None, None);
                                self.is_home_active = false;
                            }
                        });
                    });

            let tabs_max_scroll_x = (tab_scroll_out.content_size.x - tab_scroll_out.inner_rect.width()).max(0.0);
            let tabs_overflow = tabs_max_scroll_x > 2.0;
            if tabs_overflow != prev_overflow {
                ui.ctx().data_mut(|d| d.insert_temp(tabs_overflow_id, tabs_overflow));
            }

            // 2. RIGHT TAB SWITCHER DROPDOWN + OVERFLOW ARROWS (when multiple tabs exist)
            if tab_count > 1 {
                let mut right_ui = ui.new_child(egui::UiBuilder::new().max_rect(right_rect).layout(Layout::right_to_left(Align::Center)));
                right_ui.menu_button(
                    RichText::new(format!("📑 {} ▾", tab_count))
                        .size(11.0)
                        .color(Color32::from_rgb(147, 197, 253))
                        .strong(),
                    |ui| {
                        ui.set_min_width(260.0);
                        ui.label(RichText::new(match lang {
                            AppLanguage::English => format!("📑 Open Tabs ({})", tab_count),
                            AppLanguage::Vietnamese => format!("📑 Các Tab đang mở ({})", tab_count),
                        }).strong().size(12.0));
                        ui.separator();

                        if ui.selectable_label(self.is_home_active, tr(lang, "🏠 Home Dashboard", "🏠 Bảng điều khiển chính")).clicked() {
                            self.is_home_active = true;
                            ui.close_menu();
                        }
                        ui.separator();

                        for idx in 0..self.open_tabs.len() {
                            let is_active = !self.is_home_active && self.active_tab_idx == idx;
                            let (tab_title, tab_type_icon) = {
                                let t = &self.open_tabs[idx];
                                let icon = if t.title.contains("SSH") {
                                    "🔒 "
                                } else if t.title.contains("WSL") {
                                    "🐧 "
                                } else if t.title.contains("Telnet") {
                                    "⚡ "
                                } else {
                                    ">_ "
                                };
                                (t.title.clone(), icon)
                            };

                            ui.horizontal(|ui| {
                                let row_label = format!("{}. {}{}", idx + 1, tab_type_icon, tab_title);
                                if ui.selectable_label(is_active, row_label).clicked() {
                                    switch_to_tab = Some(idx);
                                    ui.close_menu();
                                }
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.small_button("✕").on_hover_text(tr(lang, "Close Tab", "Đóng Tab")).clicked() {
                                        close_tab_idx = Some(idx);
                                        ui.close_menu();
                                    }
                                });
                            });
                        }

                        ui.separator();
                        if ui.button(tr(lang, "➕ Open Local Terminal (Ctrl+T)", "➕ Mở Terminal cục bộ (Ctrl+T)")).clicked() {
                            self.spawn_local_terminal("Local Terminal", None, None);
                            self.is_home_active = false;
                            self.sidebar_tab = 0;
                            ui.close_menu();
                        }
                        if ui.button(tr(lang, "✕ Close Inactive Tabs", "✕ Đóng các Tab khác")).clicked() {
                            tab_menu_action = Some((self.active_tab_idx, TabMenuAction::CloseOthers));
                            ui.close_menu();
                        }
                    },
                );
                if tabs_overflow {
                    let cur_x = tab_scroll_out.state.offset.x;
                    if right_ui
                        .add_enabled(
                            cur_x < tabs_max_scroll_x - 1.0,
                            egui::Button::new(RichText::new("▶").size(10.0)).min_size(vec2(18.0, 20.0)),
                        )
                        .on_hover_text(tr(self.language, "Scroll tabs right", "Cuộn tab sang phải"))
                        .clicked()
                    {
                        let mut st = tab_scroll_out.state;
                        st.offset.x = (cur_x + 180.0).min(tabs_max_scroll_x);
                        st.store(ctx, tab_scroll_out.id);
                    }
                    if right_ui
                        .add_enabled(
                            cur_x > 1.0,
                            egui::Button::new(RichText::new("◀").size(10.0)).min_size(vec2(18.0, 20.0)),
                        )
                        .on_hover_text(tr(self.language, "Scroll tabs left", "Cuộn tab sang trái"))
                        .clicked()
                    {
                        let mut st = tab_scroll_out.state;
                        st.offset.x = (cur_x - 180.0).max(0.0);
                        st.store(ctx, tab_scroll_out.id);
                    }
                }
            }

            if let Some(idx) = switch_to_tab
                && idx < self.open_tabs.len()
            {
                self.is_home_active = false;
                self.active_tab_idx = idx;
                self.scroll_active_tab_into_view = true;
                self.selected_sidebar_session_id = self.open_tabs.get(idx).and_then(|t| t.session_def.as_ref()).map(|def| def.id.clone());
                self.sync_active_tab_sftp();
                ctx.memory_mut(|m| {
                    if let Some(fid) = m.focused() {
                        m.surrender_focus(fid);
                    }
                });
            }

            // Tab Right-Click Context Menu (Floating Foreground Area)
            if let Some((menu_idx, pos)) = self.tab_context_menu {
                let mut close_menu = false;
                let menu_area = egui::Area::new(egui::Id::new("tab_context_menu_area"))
                    .fixed_pos(pos)
                    .order(egui::Order::Foreground)
                    .show(ctx, |ui| {
                        egui::Frame::menu(ui.style())
                            .fill(Color32::from_rgb(26, 32, 42))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(52, 60, 72)))
                            .rounding(6.0)
                            .shadow(egui::epaint::Shadow {
                                offset: vec2(0.0, 4.0),
                                blur: 8.0,
                                spread: 0.0,
                                color: Color32::from_black_alpha(160),
                            })
                            .inner_margin(egui::Margin::symmetric(6.0, 6.0))
                            .show(ui, |ui| {
                                ui.set_min_width(190.0);
                                if ui.button(RichText::new(tr(lang, "🔑 Duplicate Tab", "🔑 Nhân bản Tab")).size(12.0).color(Color32::WHITE)).clicked() {
                                    tab_menu_action = Some((menu_idx, TabMenuAction::Duplicate));
                                    close_menu = true;
                                }
                                if ui.button(RichText::new(tr(lang, "🔄 Restart / Reconnect", "🔄 Khởi động lại / Kết nối lại")).size(12.0).color(Color32::WHITE)).clicked() {
                                    tab_menu_action = Some((menu_idx, TabMenuAction::Restart));
                                    close_menu = true;
                                }
                                if ui.button(RichText::new(tr(lang, "✏ Rename Tab", "✏ Đổi tên Tab")).size(12.0).color(Color32::WHITE)).clicked() {
                                    tab_menu_action = Some((menu_idx, TabMenuAction::Rename));
                                    close_menu = true;
                                }
                                if ui.button(RichText::new(tr(lang, "× Close Tab", "× Đóng Tab")).size(12.0).color(Color32::from_rgb(248, 113, 113))).clicked() {
                                    tab_menu_action = Some((menu_idx, TabMenuAction::Close));
                                    close_menu = true;
                                }
                                ui.separator();
                                if ui.button(RichText::new(tr(lang, "Close Other Tabs", "Đóng các Tab khác")).size(12.0).color(Color32::from_rgb(210, 220, 230))).clicked() {
                                    tab_menu_action = Some((menu_idx, TabMenuAction::CloseOthers));
                                    close_menu = true;
                                }
                                if ui.button(RichText::new(tr(lang, "Close Tabs to the Right", "Đóng các Tab bên phải")).size(12.0).color(Color32::from_rgb(210, 220, 230))).clicked() {
                                    tab_menu_action = Some((menu_idx, TabMenuAction::CloseRight));
                                    close_menu = true;
                                }
                            });
                    });

                let clicked_outside = ctx.input(|i| i.pointer.primary_clicked() && !menu_area.response.rect.contains(i.pointer.interact_pos().unwrap_or(pos2(-100.0, -100.0))));
                let esc_pressed = ctx.input(|i| i.key_pressed(egui::Key::Escape));
                if close_menu || clicked_outside || esc_pressed {
                    self.tab_context_menu = None;
                }
            }

                if let Some((idx, action)) = tab_menu_action {
                    match action {
                        TabMenuAction::Duplicate => {
                            let dup_info = self.open_tabs.get(idx).map(|tab| {
                                (
                                    tab.title.clone(),
                                    tab.session_def.clone(),
                                    tab.custom_cmd.clone(),
                                    tab.workdir.clone(),
                                )
                            });
                            if let Some((title, session_def, custom_cmd, workdir)) = dup_info {
                                if let Some(s) = session_def {
                                    self.launch_generic_session(s);
                                } else {
                                    let name = format!("{}_copy", title);
                                    self.spawn_local_terminal(&name, custom_cmd.as_deref(), workdir.as_deref());
                                }
                            }
                        }
                        TabMenuAction::Restart => {
                            self.restart_tab(idx);
                        }
                        TabMenuAction::Rename => {
                            if let Some(tab) = self.open_tabs.get(idx) {
                                self.rename_tab_target = Some((idx, tab.title.clone()));
                            }
                        }
                        TabMenuAction::Close => {
                            close_tab_idx = Some(idx);
                        }
                        TabMenuAction::CloseOthers => {
                            if idx < self.open_tabs.len() {
                                let keep = self.open_tabs.remove(idx);
                                for mut t in self.open_tabs.drain(..) {
                                    t.session.kill();
                                }
                                self.open_tabs.push(keep);
                                self.active_tab_idx = 0;
                                self.cleanup_unused_remote_sftp_sessions();
                                self.sync_sidebar_with_active_tab();
                            }
                        }
                        TabMenuAction::CloseRight => {
                            for mut t in self.open_tabs.drain(idx + 1..) {
                                t.session.kill();
                            }
                            if self.active_tab_idx > idx {
                                self.active_tab_idx = idx;
                            }
                            self.cleanup_unused_remote_sftp_sessions();
                            self.sync_sidebar_with_active_tab();
                        }
                    }
                }

                if let Some(close_idx) = close_tab_idx
                    && close_idx < self.open_tabs.len() {
                        let mut closed = self.open_tabs.remove(close_idx);
                        closed.session.kill();
                        if self.open_tabs.is_empty() {
                            self.is_home_active = true;
                            self.active_tab_idx = 0;
                            self.sidebar_tab = 0;
                        } else if self.active_tab_idx >= self.open_tabs.len() {
                            self.active_tab_idx = self.open_tabs.len() - 1;
                        } else if self.active_tab_idx > close_idx {
                            self.active_tab_idx = self.active_tab_idx.saturating_sub(1);
                        }
                        self.cleanup_unused_remote_sftp_sessions();
                        self.sync_sidebar_with_active_tab();
                    }

                ui.add_space(2.0);

            // If Home tab is active, render Modern Welcome Dashboard
            if self.is_home_active {
                ScrollArea::vertical()
                    .id_salt("home_dashboard_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("⚡ RustyBox").size(30.0).strong().color(Color32::from_rgb(56, 189, 248)));
                    ui.label(RichText::new(tr(lang, "High-Performance Remote Toolbox & Multi-Terminal Workstation", "Bộ công cụ quản trị từ xa & đa Terminal hiệu năng cao")).size(13.0).color(Color32::from_rgb(148, 163, 184)));
                });
                ui.add_space(18.0);

                let card_w: f32 = 264.0;
                let action_card_h: f32 = 58.0;
                let session_card_h: f32 = 68.0;
                let card_spacing: f32 = 14.0;
                let total_card_grid_w: f32 = card_w * 3.0 + card_spacing * 2.0; // 820.0

                let avail_w = ui.available_width();
                let content_w = total_card_grid_w.min((avail_w - 24.0).max(300.0));
                let left_pad = ((avail_w - content_w) / 2.0).max(0.0);

                let mut to_launch_quick: Option<Session> = None;
                let mut to_edit_session: Option<Session> = None;
                let mut to_clear_recent_id: Option<String> = None;
                let mut to_delete_id: Option<String> = None;

                ui.horizontal(|ui| {
                    ui.add_space(left_pad);
                    ui.vertical(|ui| {
                        ui.set_width(content_w);
                        ui.set_max_width(content_w);

                        // Hero Quick Connect Box
                        egui::Frame::none()
                            .fill(Color32::from_rgb(16, 21, 30))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(32, 42, 60)))
                            .rounding(10.0)
                            .inner_margin(egui::Margin::symmetric(18.0, 12.0))
                            .show(ui, |ui| {
                                ui.set_width(content_w - 36.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(tr(lang, "⚡ Quick Connect:", "⚡ Kết nối nhanh:")).strong().color(Color32::from_rgb(56, 189, 248)).size(13.0));
                                let q_edit = ui.add(
                                    TextEdit::singleline(&mut self.quick_connect_input)
                                        .hint_text("user@host:port, cmd, wsl...")
                                        .desired_width(340.0),
                                );
                                let conn_btn = egui::Button::new(
                                    RichText::new(tr(lang, "▶ Connect", "▶ Kết nối")).strong().color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(37, 99, 235))
                                .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(96, 165, 250)))
                                .rounding(6.0);
                                if (q_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                                    || ui.add(conn_btn).clicked()
                                {
                                    self.handle_quick_connect();
                                }
                            });
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                let chip = |ui: &mut egui::Ui, text: &str| -> egui::Response {
                                    ui.add(
                                        egui::Button::new(
                                            RichText::new(text).size(11.0).color(Color32::from_rgb(190, 205, 225)),
                                        )
                                        .fill(Color32::from_rgb(22, 28, 40))
                                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(36, 46, 64)))
                                        .rounding(6.0),
                                    )
                                };
                                if chip(ui, tr(lang, "💻 Local Shell", "💻 Terminal cục bộ")).clicked() {
                                    self.spawn_local_terminal("Local Terminal", None, None);
                                    self.is_home_active = false;
                                }
                                if chip(ui, "🐧 WSL").clicked() {
                                    #[cfg(target_os = "windows")]
                                    self.spawn_local_terminal("WSL", Some("wsl"), None);
                                    #[cfg(not(target_os = "windows"))]
                                    self.spawn_local_terminal("Local Shell", None, None);
                                    self.is_home_active = false;
                                }
                                if chip(ui, tr(lang, "🌐 New Session", "🌐 Phiên mới")).clicked() {
                                    self.new_session_dialog.open_for_new();
                                }
                                if chip(ui, tr(lang, "📥 Import SSH", "📥 Nhập SSH")).clicked() {
                                    self.show_import_dialog = true;
                                }
                                if chip(ui, tr(lang, "📁 Import MobaXterm", "📁 Nhập MobaXterm")).clicked() {
                                    self.show_import_dialog = true;
                                    if let Some(path) = rfd::FileDialog::new()
                                        .set_title(tr(lang, "Select MobaXterm Export File", "Chọn tệp xuất MobaXterm"))
                                        .add_filter("MobaXterm Sessions", &["txt", "ini", "mxtpro", "mxtsessions", "csv"])
                                        .add_filter("All Files", &["*"])
                                        .pick_file()
                                    {
                                        let p_str = path.to_string_lossy().to_string();
                                        self.import_file_path = p_str.clone();
                                        self.import_default_folder = "MobaXterm".into();
                                        match std::fs::read_to_string(&path) {
                                            Ok(content) => {
                                                let len = content.len();
                                                self.import_raw_text = content;
                                                let msg = match lang {
                                                    AppLanguage::English => format!("Loaded {} bytes from '{}'.", len, p_str),
                                                    AppLanguage::Vietnamese => format!("Đã nạp {} byte từ '{}'.", len, p_str),
                                                };
                                                self.import_status_msg = Some((msg, false));
                                            }
                                            Err(e) => {
                                                let msg = match lang {
                                                    AppLanguage::English => format!("Cannot read '{}': {}", p_str, e),
                                                    AppLanguage::Vietnamese => format!("Không thể đọc '{}': {}", p_str, e),
                                                };
                                                self.import_status_msg = Some((msg, true));
                                            }
                                        }
                                    }
                                }
                                if chip(ui, tr(lang, "📡 NetScan", "📡 Quét mạng")).clicked() {
                                    self.show_network_tools = true;
                                    self.net_tools_tab = 1;
                                }
                                if chip(ui, tr(lang, "📋 Snippets", "📋 Đoạn lệnh")).clicked() {
                                    self.show_snippets = true;
                                }
                                if chip(ui, tr(lang, "🔀 Tunnels", "🔀 Đường hầm SSH")).clicked() {
                                    self.show_tunnels = true;
                                }
                            });
                        });

                    ui.add_space(22.0);

                    // 6 Modern Action Cards with icon badge & refined hover effects in a balanced 3x2 grid
                    let modern_card = |ui: &mut egui::Ui, icon: &str, title: &str, desc: &str, tint: Color32, w: f32, h: f32| -> egui::Response {
                        let (rect, resp) = ui.allocate_exact_size(vec2(w, h), egui::Sense::click());
                        let is_hovered = resp.hovered();
                        let bg = if is_hovered {
                            Color32::from_rgb(25, 34, 50)
                        } else {
                            Color32::from_rgb(17, 22, 32)
                        };
                        let border = if is_hovered {
                            egui::Stroke::new(1.2_f32, Color32::from_rgb(56, 189, 248))
                        } else {
                            egui::Stroke::new(1.0_f32, Color32::from_rgb(32, 42, 60))
                        };
                        ui.painter().rect(rect, egui::Rounding::same(8.0), bg, border);

                        let mut c_ui = ui.new_child(
                            egui::UiBuilder::new()
                                .max_rect(rect.shrink2(vec2(10.0, 10.0)))
                                .layout(Layout::left_to_right(Align::Min)),
                        );
                        c_ui.set_clip_rect(c_ui.clip_rect().intersect(rect.shrink(2.0)));
                        c_ui.spacing_mut().item_spacing.x = 10.0;
                        // Icon badge container - perfectly centered with 10px top/bottom margins
                        let (badge_rect, _) = c_ui.allocate_exact_size(vec2(38.0, 38.0), egui::Sense::hover());
                        c_ui.painter().rect_filled(badge_rect, 6.0, Color32::from_rgb(24, 32, 46));
                        c_ui.painter().rect_stroke(badge_rect, 6.0, egui::Stroke::new(1.0_f32, tint));
                        c_ui.painter().text(
                            badge_rect.center(),
                            egui::Align2::CENTER_CENTER,
                            icon,
                            egui::FontId::proportional(20.0),
                            Color32::WHITE,
                        );

                        c_ui.vertical(|v_ui| {
                            v_ui.spacing_mut().item_spacing.y = 2.0;
                            let tc = if is_hovered {
                                Color32::from_rgb(56, 189, 248)
                            } else {
                                Color32::WHITE
                            };
                            v_ui.label(RichText::new(title).strong().size(12.5).color(tc));
                            v_ui.label(RichText::new(desc).size(10.0).color(Color32::from_rgb(148, 163, 184)));
                        });
                        resp
                    };

                    // Row 1: Local Terminal, SSH Client, SFTP Browser
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = card_spacing;
                        if modern_card(ui, "💻", tr(lang, "Local Terminal", "Terminal cục bộ"), tr(lang, "Interactive shell with ConPTY", "Terminal tương tác với ConPTY"), Color32::from_rgb(56, 189, 248), card_w, action_card_h).clicked() {
                            self.spawn_local_terminal("Local Terminal", None, None);
                            self.is_home_active = false;
                        }
                        if modern_card(ui, "🌐", tr(lang, "SSH Client", "Kết nối SSH"), tr(lang, "Key auth & auto-SFTP stream", "Xác thực khóa & đồng bộ SFTP"), Color32::from_rgb(96, 165, 250), card_w, action_card_h).clicked() {
                            self.new_session_dialog.open_for_new();
                        }
                        if modern_card(ui, "📁", tr(lang, "SFTP Browser", "Trình duyệt SFTP"), tr(lang, "Dual-pane remote file manager", "Quản lý tệp từ xa trực quan"), Color32::from_rgb(52, 211, 153), card_w, action_card_h).clicked() {
                            self.show_sftp_sidebar = true;
                            self.sidebar_tab = 1;
                        }
                    });

                    ui.add_space(card_spacing);

                    // Row 2: Network Scanner, SSH Tunnels, Network Daemons
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = card_spacing;
                        if modern_card(ui, "📡", tr(lang, "Network Scanner", "Quét mạng & Cổng"), tr(lang, "Subnet IP discovery & Port Scan", "Tìm IP mạng nội bộ & Quét cổng"), Color32::from_rgb(251, 191, 36), card_w, action_card_h).clicked() {
                            self.show_network_tools = true;
                            self.net_tools_tab = 1;
                        }
                        if modern_card(ui, "🔀", tr(lang, "SSH Tunnels", "Đường hầm SSH"), tr(lang, "Local, remote & SOCKS5 proxy", "Chuyển tiếp cổng & Proxy SOCKS5"), Color32::from_rgb(192, 132, 252), card_w, action_card_h).clicked() {
                            self.show_tunnels = true;
                        }
                        if modern_card(ui, "🕊", tr(lang, "Network Daemons", "Dịch vụ mạng"), tr(lang, "Micro HTTP, TFTP & Syslog", "Máy chủ HTTP, TFTP & Syslog"), Color32::from_rgb(244, 114, 182), card_w, action_card_h).clicked() {
                            self.show_services_modal = true;
                        }
                    });

                    ui.add_space(22.0);

                    // Search / Filter bar for Recent & Saved connections
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr(lang, "🔍 Filter Connections:", "🔍 Lọc kết nối:")).strong().size(12.0).color(Color32::from_rgb(148, 163, 184)));
                        ui.add(
                            TextEdit::singleline(&mut self.home_session_filter)
                                .hint_text(tr(lang, "Search by name, host, user, or folder...", "Tìm theo tên, máy chủ, người dùng hoặc thư mục..."))
                                .desired_width(280.0),
                        );
                        if !self.home_session_filter.is_empty() && ui.small_button(tr(lang, "✖ Clear", "✖ Xóa")).clicked() {
                            self.home_session_filter.clear();
                        }
                    });

                    ui.add_space(16.0);

                    let render_session_card = |ui: &mut egui::Ui, s: &Session, show_time: bool| -> egui::Response {
                        let icon = match s.session_type {
                            SessionType::LocalShell { .. } => "💻",
                            SessionType::Wsl { .. } => "🐧",
                            SessionType::Rdp { .. } => "🖥",
                            SessionType::Ftp { .. } => "📁",
                            _ => "🔑",
                        };
                        let (q_rect, q_resp) = ui.allocate_exact_size(vec2(card_w, session_card_h), egui::Sense::click());
                        let is_h = q_resp.hovered();
                        let bg = if is_h { Color32::from_rgb(26, 36, 54) } else { Color32::from_rgb(18, 23, 33) };
                        let border = if is_h {
                            egui::Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248))
                        } else {
                            egui::Stroke::new(1.0_f32, Color32::from_rgb(32, 42, 60))
                        };
                        ui.painter().rect(q_rect, 6.0, bg, border);

                        let mut c_ui = ui.new_child(
                            egui::UiBuilder::new()
                                .max_rect(q_rect.shrink2(vec2(10.0, 8.0)))
                                .layout(Layout::left_to_right(Align::Min)),
                        );
                        c_ui.set_clip_rect(c_ui.clip_rect().intersect(q_rect.shrink(2.0)));
                        c_ui.spacing_mut().item_spacing.x = 8.0;
                        c_ui.label(RichText::new(icon).size(16.0));
                        c_ui.vertical(|v_ui| {
                            v_ui.spacing_mut().item_spacing.y = 2.0;
                            v_ui.set_max_width((q_rect.width() - 32.0).max(80.0));
                            v_ui.horizontal(|h_ui| {
                                let title_col = if is_h { Color32::from_rgb(56, 189, 248) } else { Color32::WHITE };
                                h_ui.add(egui::Label::new(RichText::new(&s.name).strong().size(11.5).color(title_col)).truncate());
                                if !s.folder.is_empty() {
                                    h_ui.add(
                                        egui::Label::new(
                                            RichText::new(format!("[{}]", s.folder))
                                                .size(9.5)
                                                .color(Color32::from_rgb(100, 116, 139)),
                                        )
                                        .truncate(),
                                    );
                                }
                            });
                            v_ui.add(
                                egui::Label::new(
                                    RichText::new(s.connection_subtitle())
                                        .monospace()
                                        .size(10.0)
                                        .color(Color32::from_rgb(148, 163, 184)),
                                )
                                .truncate(),
                            );
                            if show_time
                                && let Some(ts) = s.last_connected_display() {
                                    v_ui.add(
                                        egui::Label::new(
                                            RichText::new(format!("🕒 {} ({}x)", ts, s.connect_count.max(1)))
                                                .size(9.5)
                                                .color(Color32::from_rgb(52, 211, 153)),
                                        )
                                        .truncate(),
                                    );
                                }
                        });
                        q_resp.on_hover_text(format!(
                            "{}\n{}\nFolder: {}",
                            s.name,
                            s.connection_subtitle(),
                            s.folder
                        ))
                    };

                    // Section 1: Recent Connections (Tối đa 6 kết nối gần nhất - 2 hàng x 3 cột cân đối)
                    let recent_sessions: Vec<_> = Session::recent_sessions(&self.sessions, &self.home_session_filter)
                        .into_iter()
                        .take(6)
                        .collect();

                    ui.label(
                        RichText::new(match lang {
                            AppLanguage::English => format!("🕒 Recent Connections ({})", recent_sessions.len()),
                            AppLanguage::Vietnamese => format!("🕒 Kết nối gần đây ({})", recent_sessions.len()),
                        })
                            .strong()
                            .size(13.0)
                            .color(Color32::from_rgb(52, 211, 153)),
                    );
                    ui.add_space(8.0);

                    if recent_sessions.is_empty() {
                        ui.label(
                            RichText::new(tr(lang, "No recent connections yet. Connect to any session or use Quick Connect above.", "Chưa có kết nối gần đây. Hãy mở một phiên hoặc dùng Kết nối nhanh ở trên."))
                                .size(11.5)
                                .color(Color32::from_rgb(100, 116, 139)),
                        );
                    } else {
                        for chunk in recent_sessions.chunks(3) {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = card_spacing;
                                for s in chunk {
                                    let q_resp = render_session_card(ui, s, true);
                                    if q_resp.clicked() {
                                        to_launch_quick = Some((*s).clone());
                                    }
                                    q_resp.context_menu(|menu_ui| {
                                        if menu_ui.button(tr(lang, "▶ Connect", "▶ Kết nối")).clicked() {
                                            to_launch_quick = Some((*s).clone());
                                            menu_ui.close_menu();
                                        }
                                        if menu_ui.button(tr(lang, "✏ Edit Session", "✏ Sửa phiên")).clicked() {
                                            to_edit_session = Some((*s).clone());
                                            menu_ui.close_menu();
                                        }
                                        if menu_ui.button(tr(lang, "🧹 Clear from Recent", "🧹 Xóa khỏi Gần đây")).clicked() {
                                            to_clear_recent_id = Some(s.id.clone());
                                            menu_ui.close_menu();
                                        }
                                        if menu_ui.button(RichText::new(tr(lang, "🗑 Delete Session", "🗑 Xóa phiên")).color(Color32::from_rgb(248, 113, 113))).clicked() {
                                            to_delete_id = Some(s.id.clone());
                                            menu_ui.close_menu();
                                        }
                                    });
                                }
                            });
                            ui.add_space(8.0);
                        }
                    }

                    if let Some(edit_s) = to_edit_session {
                        self.new_session_dialog.open_for_edit(&edit_s);
                    }
                    if let Some(clear_id) = to_clear_recent_id
                        && let Some(existing) = self.sessions.iter_mut().find(|item| item.id == clear_id) {
                            existing.last_connected_at = None;
                            existing.connect_count = 0;
                            let _ = self.storage.save_sessions(&self.sessions);
                        }
                    if let Some(del_id) = to_delete_id {
                        self.sessions.retain(|item| item.id != del_id);
                        let _ = self.storage.save_sessions(&self.sessions);
                    }
                    if let Some(s) = to_launch_quick {
                        self.launch_generic_session(s);
                        self.is_home_active = false;
                    }
                    ui.add_space(24.0);
                });
                });
                });
                return;
            }

            // INLINE TERMINAL SEARCH BAR (Ctrl+F)
            if self.search_open {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(tr(lang, "🔍 Find:", "🔍 Tìm:")).strong().color(Color32::from_rgb(255, 200, 80)));
                    let text_resp = ui.add(TextEdit::singleline(&mut self.search_query)
                        .hint_text(tr(lang, "Search across scrollback & screen...", "Tìm trong bộ đệm & màn hình..."))
                        .desired_width(240.0));
                    if self.focus_search {
                        text_resp.request_focus();
                        self.focus_search = false;
                    }

                    // Search across all 2,000 scrollback lines + visible screen if active tab exists
                    if !self.search_query.is_empty() {
                        let nav_idx_id = egui::Id::new("term_search_match_idx").with(self.active_tab_idx);
                        let mut matches = Vec::new();
                        if let Some(tab) = self.open_tabs.get(self.active_tab_idx) {
                            let mut parser = tab.session.parser.lock();
                            matches = crate::terminal::widget::search_terminal_buffer(
                                parser.screen_mut(),
                                &self.search_query,
                            );
                        }
                        let match_count = matches.len();
                        let mut cur_match_idx: usize = ui
                            .data(|d| d.get_temp(nav_idx_id))
                            .unwrap_or_else(|| match_count.saturating_sub(1));
                        if match_count > 0 && cur_match_idx >= match_count {
                            cur_match_idx = match_count - 1;
                        }

                        if match_count > 0 {
                            ui.label(
                                RichText::new(format!(
                                    "{} / {} match{}",
                                    cur_match_idx + 1,
                                    match_count,
                                    if match_count > 1 { "es" } else { "" }
                                ))
                                .color(Color32::from_rgb(100, 220, 100))
                                .strong(),
                            );

                            let enter_pressed = text_resp.has_focus()
                                && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                            let shift_held = ctx.input(|i| i.modifiers.shift);
                            let mut jump_to: Option<usize> = None;

                            if ui.small_button(tr(lang, "▲ Prev", "▲ Trước")).clicked() || (enter_pressed && shift_held) {
                                cur_match_idx = if cur_match_idx == 0 {
                                    match_count - 1
                                } else {
                                    cur_match_idx - 1
                                };
                                jump_to = Some(cur_match_idx);
                            }
                            if ui.small_button(tr(lang, "▼ Next", "▼ Sau")).clicked() || (enter_pressed && !shift_held) {
                                cur_match_idx = (cur_match_idx + 1) % match_count;
                                jump_to = Some(cur_match_idx);
                            }

                            if let Some(target_idx) = jump_to {
                                ui.data_mut(|d| d.insert_temp(nav_idx_id, target_idx));
                                if let Some((abs_row, _, _)) = matches.get(target_idx)
                                    && let Some(tab) = self.open_tabs.get(self.active_tab_idx) {
                                        let mut parser = tab.session.parser.lock();
                                        crate::terminal::widget::scroll_to_abs_row(
                                            parser.screen_mut(),
                                            *abs_row,
                                        );
                                    }
                            }
                        } else {
                            ui.label(RichText::new(tr(lang, "0 matches", "0 kết quả")).color(Color32::from_rgb(200, 100, 100)));
                        }

                        if ui.small_button(tr(lang, "Clear", "Xóa")).clicked() {
                            self.search_query.clear();
                        }
                    }

                    if ui.small_button(tr(lang, "✖ Close (Esc)", "✖ Đóng (Esc)")).clicked() || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                        self.search_open = false;
                        self.search_query.clear();
                    }
                });
                ui.separator();
            }

            ui.separator();

            let num_tabs = self.open_tabs.len();
            if num_tabs == 0 {
                ui.centered_and_justified(|ui| {
                    ui.label(tr(lang, "No active sessions. Press '+' or select a session to connect.", "Chưa có phiên nào đang mở. Nhấn '+' hoặc chọn một phiên để kết nối."));
                });
                return;
            }

            let broadcast_tx = if self.multi_exec_enabled {
                Some(&self.broadcast_tx)
            } else {
                None
            };

            let search_ref = if self.search_open && !self.search_query.is_empty() {
                Some(self.search_query.as_str())
            } else {
                None
            };
            let font_sz = self.font_size;
            let current_theme = self.theme;
            let current_active_idx = self.active_tab_idx.min(num_tabs - 1);
            let mut newly_focused_tab_idx: Option<usize> = None;
            let copy_on_select = self.copy_on_select;
            let highlight_rules = &self.highlight_rules;
            let highlight_rules_enabled = self.highlight_rules_enabled;
            let modal_open = self.is_any_modal_open();

            let render_pane = |ui: &mut egui::Ui,
                               pane_idx: usize,
                               tab: &mut OpenTab,
                               is_active: bool|
             -> (egui::Response, TerminalAction) {
                let eff_theme = tab
                    .session_def
                    .as_ref()
                    .and_then(|s| {
                        let scheme = s.terminal_color_scheme.trim();
                        if scheme.is_empty()
                            || scheme.eq_ignore_ascii_case("default")
                            || scheme.eq_ignore_ascii_case("rustybox dark (default)")
                        {
                            None
                        } else {
                            TerminalTheme::from_name(scheme)
                        }
                    })
                    .unwrap_or(current_theme);
                let eff_font = tab
                    .session_def
                    .as_ref()
                    .map(|s| s.terminal_font_size as f32)
                    .filter(|&sz| sz >= 9.0 && (font_sz - 14.0).abs() < 0.1)
                    .unwrap_or(font_sz);
                let eff_font_family = tab
                    .session_def
                    .as_ref()
                    .map(|s| s.terminal_font_family.as_str())
                    .filter(|f| !f.is_empty())
                    .map(crate::terminal::fonts::get_terminal_font_family)
                    .unwrap_or(egui::FontFamily::Monospace);
                let bs_ctrl_h = tab
                    .session_def
                    .as_ref()
                    .map(|s| s.backspace_sends_ctrl_h)
                    .unwrap_or(false);
                let rc_paste = tab
                    .session_def
                    .as_ref()
                    .map(|s| s.right_click_paste)
                    .unwrap_or(false);

                let widget = TerminalWidget::new(&tab.id, &mut tab.session)
                    .with_font_size(eff_font)
                    .with_font_family(eff_font_family)
                    .with_theme(eff_theme)
                    .with_search(search_ref)
                    .with_active_pane(is_active)
                    .with_backspace_ctrl_h(bs_ctrl_h)
                    .with_right_click_paste(rc_paste)
                    .with_copy_on_select(copy_on_select)
                    .with_highlight_rules(Some(highlight_rules), highlight_rules_enabled)
                    .with_suppress_escape(modal_open)
                    .with_language(self.language);
                let _ = pane_idx;
                widget.ui(ui, broadcast_tx)
            };

            match self.split_mode {
                SplitMode::Single => {
                    let tab = &mut self.open_tabs[current_active_idx];
                    let (_, act) = render_pane(ui, current_active_idx, tab, true);
                    triggered_action = act;
                }
                SplitMode::Horizontal => {
                    let tab_a_idx = current_active_idx;
                    let tab_b_idx = if num_tabs > 1 {
                        if tab_a_idx == 0 { 1 } else { 0 }
                    } else {
                        tab_a_idx
                    };

                    ui.columns(2, |columns| {
                        let (resp_a, act_a) = {
                            let tab_a = &mut self.open_tabs[tab_a_idx];
                            render_pane(&mut columns[0], tab_a_idx, tab_a, true)
                        };
                        if resp_a.clicked() || resp_a.drag_started() || resp_a.secondary_clicked() {
                            newly_focused_tab_idx = Some(tab_a_idx);
                        }
                        if !matches!(act_a, TerminalAction::None) {
                            newly_focused_tab_idx = Some(tab_a_idx);
                            triggered_action = act_a;
                        }

                        if tab_a_idx != tab_b_idx {
                            let (resp_b, act_b) = {
                                let tab_b = &mut self.open_tabs[tab_b_idx];
                                render_pane(&mut columns[1], tab_b_idx, tab_b, false)
                            };
                            if resp_b.clicked() || resp_b.drag_started() || resp_b.secondary_clicked() {
                                newly_focused_tab_idx = Some(tab_b_idx);
                            }
                            if !matches!(act_b, TerminalAction::None) {
                                newly_focused_tab_idx = Some(tab_b_idx);
                                if matches!(triggered_action, TerminalAction::None) {
                                    triggered_action = act_b;
                                }
                            }
                        } else {
                            columns[1].centered_and_justified(|ui| {
                                ui.label(tr(self.language, "Open another session to view side-by-side", "Mở thêm một phiên khác để xem song song 2 cột"));
                            });
                        }
                    });
                }
                SplitMode::Vertical => {
                    let tab_a_idx = current_active_idx;
                    let tab_b_idx = if num_tabs > 1 {
                        if tab_a_idx == 0 { 1 } else { 0 }
                    } else {
                        tab_a_idx
                    };

                    let half_height = (ui.available_height() - 10.0) / 2.0;

                    ui.vertical(|ui| {
                        ui.allocate_ui_with_layout(
                            vec2(ui.available_width(), half_height),
                            Layout::top_down(Align::Min),
                            |ui| {
                                let tab_a = &mut self.open_tabs[tab_a_idx];
                                let (resp_a, act_a) = render_pane(ui, tab_a_idx, tab_a, true);
                                if resp_a.clicked() || resp_a.drag_started() || resp_a.secondary_clicked() {
                                    newly_focused_tab_idx = Some(tab_a_idx);
                                }
                                if !matches!(act_a, TerminalAction::None) {
                                    newly_focused_tab_idx = Some(tab_a_idx);
                                    triggered_action = act_a;
                                }
                            },
                        );

                        ui.separator();

                        ui.allocate_ui_with_layout(
                            vec2(ui.available_width(), half_height),
                            Layout::top_down(Align::Min),
                            |ui| {
                                if tab_a_idx != tab_b_idx {
                                    let tab_b = &mut self.open_tabs[tab_b_idx];
                                    let (resp_b, act_b) = render_pane(ui, tab_b_idx, tab_b, false);
                                    if resp_b.clicked() || resp_b.drag_started() || resp_b.secondary_clicked() {
                                        newly_focused_tab_idx = Some(tab_b_idx);
                                    }
                                    if !matches!(act_b, TerminalAction::None) {
                                        newly_focused_tab_idx = Some(tab_b_idx);
                                        if matches!(triggered_action, TerminalAction::None) {
                                            triggered_action = act_b;
                                        }
                                    }
                                } else {
                                    ui.centered_and_justified(|ui| {
                                        ui.label(tr(self.language, "Open another session to view stacked", "Mở thêm một phiên khác để xem xếp dọc 2 hàng"));
                                    });
                                }
                            },
                        );
                    });
                }
                SplitMode::Grid2x2 => {
                    let total_h = ui.available_height();
                    let half_h = (total_h - 10.0) / 2.0;

                    ui.allocate_ui_with_layout(
                        vec2(ui.available_width(), half_h),
                        Layout::left_to_right(Align::Min),
                        |ui| {
                            ui.columns(2, |cols| {
                                if num_tabs > 0 {
                                    let tab0 = &mut self.open_tabs[0];
                                    let (resp0, act0) =
                                        render_pane(&mut cols[0], 0, tab0, current_active_idx == 0);
                                    if resp0.clicked() || resp0.drag_started() || resp0.secondary_clicked() {
                                        newly_focused_tab_idx = Some(0);
                                    }
                                    if !matches!(act0, TerminalAction::None) {
                                        newly_focused_tab_idx = Some(0);
                                        triggered_action = act0;
                                    }
                                }
                                if num_tabs > 1 {
                                    let tab1 = &mut self.open_tabs[1];
                                    let (resp1, act1) =
                                        render_pane(&mut cols[1], 1, tab1, current_active_idx == 1);
                                    if resp1.clicked() || resp1.drag_started() || resp1.secondary_clicked() {
                                        newly_focused_tab_idx = Some(1);
                                    }
                                    if !matches!(act1, TerminalAction::None) {
                                        newly_focused_tab_idx = Some(1);
                                        if matches!(triggered_action, TerminalAction::None) {
                                            triggered_action = act1;
                                        }
                                    }
                                }
                            });
                        },
                    );

                    ui.separator();

                    ui.allocate_ui_with_layout(
                        vec2(ui.available_width(), half_h),
                        Layout::left_to_right(Align::Min),
                        |ui| {
                            ui.columns(2, |cols| {
                                if num_tabs > 2 {
                                    let tab2 = &mut self.open_tabs[2];
                                    let (resp2, act2) =
                                        render_pane(&mut cols[0], 2, tab2, current_active_idx == 2);
                                    if resp2.clicked() || resp2.drag_started() || resp2.secondary_clicked() {
                                        newly_focused_tab_idx = Some(2);
                                    }
                                    if !matches!(act2, TerminalAction::None) {
                                        newly_focused_tab_idx = Some(2);
                                        if matches!(triggered_action, TerminalAction::None) {
                                            triggered_action = act2;
                                        }
                                    }
                                }
                                if num_tabs > 3 {
                                    let tab3 = &mut self.open_tabs[3];
                                    let (resp3, act3) =
                                        render_pane(&mut cols[1], 3, tab3, current_active_idx == 3);
                                    if resp3.clicked() || resp3.drag_started() || resp3.secondary_clicked() {
                                        newly_focused_tab_idx = Some(3);
                                    }
                                    if !matches!(act3, TerminalAction::None) {
                                        newly_focused_tab_idx = Some(3);
                                        if matches!(triggered_action, TerminalAction::None) {
                                            triggered_action = act3;
                                        }
                                    }
                                }
                            });
                        },
                    );
                }
            }

            if let Some(new_idx) = newly_focused_tab_idx
                && self.active_tab_idx != new_idx {
                    self.active_tab_idx = new_idx;
                    self.sync_sidebar_with_active_tab();
                }
        });

        // Handle Action from Terminal
        match triggered_action {
            TerminalAction::MultiLinePaste(text) => {
                if self.paste_protection_enabled {
                    self.pending_paste_text = Some(text);
                } else if let Some(tab) = self.open_tabs.get_mut(self.active_tab_idx)
                    && let Ok(bytes) = tab.session.paste_text(&text)
                        && self.multi_exec_enabled {
                            let _ = self.broadcast_tx.send(bytes);
                        }
            }
            TerminalAction::SaveBufferToFile => {
                self.save_active_terminal_buffer();
            }
            TerminalAction::ZoomIn => {
                self.font_size = (self.font_size + 1.0).min(32.0);
                let _ = self.persist_preferences();
            }
            TerminalAction::ZoomOut => {
                self.font_size = (self.font_size - 1.0).max(8.0);
                let _ = self.persist_preferences();
            }
            TerminalAction::ZoomReset => {
                self.font_size = 14.0;
                let _ = self.persist_preferences();
            }
            TerminalAction::OpenSearch => {
                self.search_open = true;
                self.focus_search = true;
            }
            TerminalAction::RestartTab => {
                let active = self.active_tab_idx;
                self.restart_tab(active);
            }
            TerminalAction::CloseTab => {
                if !self.open_tabs.is_empty() {
                    let active = self.active_tab_idx;
                    if active < self.open_tabs.len() {
                        let mut closed = self.open_tabs.remove(active);
                        closed.session.kill();
                        if self.open_tabs.is_empty() {
                            self.is_home_active = true;
                            self.active_tab_idx = 0;
                            self.sidebar_tab = 0;
                        } else if self.active_tab_idx >= self.open_tabs.len() {
                            self.active_tab_idx = self.open_tabs.len() - 1;
                        }
                        self.cleanup_unused_remote_sftp_sessions();
                        self.sync_sidebar_with_active_tab();
                    }
                }
            }
            TerminalAction::NextTab => {
                if !self.open_tabs.is_empty() {
                    self.is_home_active = false;
                    self.active_tab_idx = (self.active_tab_idx + 1) % self.open_tabs.len();
                    self.sync_sidebar_with_active_tab();
                    self.scroll_active_tab_into_view = true;
                }
            }
            TerminalAction::PrevTab
                if !self.open_tabs.is_empty() => {
                    self.is_home_active = false;
                    self.active_tab_idx = if self.active_tab_idx == 0 {
                        self.open_tabs.len() - 1
                    } else {
                        self.active_tab_idx - 1
                    };
                    self.sync_sidebar_with_active_tab();
                    self.scroll_active_tab_into_view = true;
                }
            _ => {}
        }

        // 7. POPUP DIALOGS & MODAL WINDOWS

        // Multi-line Paste Safety Warning Modal (MobaXterm TFORMCHECKCLIPBOARD)
        if self.pending_paste_text.is_some() {
            let mut close = false;
            let mut run_paste = false;
            let mut copy_pending = false;
            let text_to_copy = self.pending_paste_text.clone();

            egui::Window::new(tr(lang, "⚠ Multi-line Paste Warning", "⚠ Cảnh báo dán nhiều dòng"))
                .default_size(Vec2::new(540.0, 340.0))
                .pivot(egui::Align2::CENTER_CENTER)
                .default_pos(ctx.screen_rect().center())
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.label(RichText::new(tr(lang, "Warning: The clipboard text contains newlines!", "Cảnh báo: Nội dung dán có chứa nhiều dòng lệnh!")).color(Color32::from_rgb(255, 180, 50)).strong());
                    ui.label(tr(lang, "Review or modify commands before executing in the terminal:", "Kiểm tra hoặc chỉnh sửa lệnh trước khi thực thi trong Terminal:"));
                    ui.add_space(6.0);

                    if let Some(ref mut text) = self.pending_paste_text {
                        let lines_count = text.lines().count();
                        ui.label(RichText::new(match lang {
                            AppLanguage::English => format!("Total lines: {} | Characters: {}", lines_count, text.len()),
                            AppLanguage::Vietnamese => format!("Tổng số dòng: {} | Ký tự: {}", lines_count, text.len()),
                        }).weak().size(11.0));

                        let available_h = (ui.available_height() - 50.0).clamp(140.0, 400.0);
                        ScrollArea::vertical().max_height(available_h).show(ui, |ui| {
                            let text_resp = ui.add(TextEdit::multiline(text).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                            text_resp.context_menu(|ui| {
                                if ui.button(tr(lang, "📋 Copy", "📋 Sao chép")).clicked() {
                                    copy_pending = true;
                                    ui.close_menu();
                                }
                            });
                        });
                    }

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.add_sized([160.0, 26.0], egui::Button::new(RichText::new(tr(lang, "✔ Execute in Terminal", "✔ Thực thi trong Terminal")).strong().color(Color32::from_rgb(80, 240, 120)))).clicked() {
                            run_paste = true;
                        }
                        if ui.add_sized([110.0, 26.0], egui::Button::new(tr(lang, "📋 Copy Text", "📋 Sao chép"))).on_hover_text(tr(lang, "Copy all command text to clipboard", "Sao chép toàn bộ nội dung lệnh vào clipboard")).clicked() {
                            copy_pending = true;
                        }
                        if ui.add_sized([80.0, 26.0], egui::Button::new(tr(lang, "Cancel", "Hủy"))).clicked() {
                            close = true;
                        }
                    });

                    if copy_pending
                        && let Some(ref text) = text_to_copy {
                            copy_text_to_clipboard(ui, text);
                        }
                });

            let _ = copy_pending;

            if run_paste {
                if let Some(text) = self.pending_paste_text.take()
                    && let Some(tab) = self.open_tabs.get_mut(self.active_tab_idx)
                        && let Ok(bytes) = tab.session.paste_text(&text)
                            && self.multi_exec_enabled {
                                let _ = self.broadcast_tx.send(bytes);
                            }
            } else if close {
                self.pending_paste_text = None;
            }
        }

        // New Session Dialog
        self.new_session_dialog.language = self.language;
        self.new_session_dialog.available_credentials = self.credentials.clone();
        self.new_session_dialog.available_macros = self.quick_macros.clone();
        if let Some(mut new_session) = render_new_session_dialog(ctx, &mut self.new_session_dialog) {
            if let Some(idx) = self.sessions.iter().position(|s| s.id == new_session.id) {
                // Editing existing session: preserve connection history metadata
                new_session.last_connected_at = self.sessions[idx].last_connected_at.clone();
                new_session.connect_count = self.sessions[idx].connect_count;
                self.sessions[idx] = new_session.clone();
            } else {
                // Brand new session: append to list
                self.sessions.push(new_session.clone());
            }
            let _ = self.storage.save_sessions(&self.sessions);
            self.selected_sidebar_session_id = Some(new_session.id.clone());
            self.is_home_active = false;
            self.launch_generic_session(new_session);
        }

        if self.new_session_dialog.request_open_passwords {
            self.new_session_dialog.request_open_passwords = false;
            self.manage_passwords_tab = 1; // Open Credentials / Users tab directly
            self.show_manage_passwords = true;
        }
        if self.new_session_dialog.request_open_import {
            self.new_session_dialog.request_open_import = false;
            self.show_import_dialog = true;
        }

        // Network Tools & Scanner Modal (Port Scan, Subnet NetScan, Ping, Netstat)
        if self.show_network_tools {
            let mut open = self.show_network_tools;
            let rt_handle = self.tokio_runtime.handle().clone();

            egui::Window::new(tr(lang, "🌐 Network Tools Suite (NetScan, Ping, Ports, Netstat)", "🌐 Bộ công cụ mạng (Quét mạng, Ping, Cổng, Netstat)"))
                .open(&mut open)
                .default_size(Vec2::new(620.0, 480.0))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.net_tools_tab, 0, tr(lang, "🔍 Port Scanner", "🔍 Quét cổng"));
                        ui.selectable_value(&mut self.net_tools_tab, 1, tr(lang, "📡 Subnet NetScan", "📡 Quét mạng nội bộ"));
                        ui.selectable_value(&mut self.net_tools_tab, 2, "⏱ TCP Ping");
                        ui.selectable_value(&mut self.net_tools_tab, 3, "📊 Netstat");
                        ui.selectable_value(&mut self.net_tools_tab, 4, tr(lang, "🌐 DNS Lookup", "🌐 Tra cứu DNS"));
                        ui.selectable_value(&mut self.net_tools_tab, 5, "⚡ Wake-on-LAN");
                    });
                    ui.separator();

                    match self.net_tools_tab {
                        0 => {
                            // Port Scanner
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Target Host / IP:", "Máy chủ / IP đích:"));
                                ui.text_edit_singleline(&mut self.network_tools.target_host);
                                if ui.button(tr(lang, "🔍 Scan Common Ports", "🔍 Quét các cổng phổ biến")).clicked() {
                                    self.network_tools.start_port_scan(&rt_handle);
                                }
                            });

                            let progress = *self.network_tools.scan_progress.lock();
                            ui.add(egui::ProgressBar::new(progress).show_percentage());

                            ui.separator();
                            ui.label(RichText::new(tr(lang, "Port Scan Results:", "Kết quả quét cổng:")).strong());

                            ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                                let results = self.network_tools.scan_results.lock().clone();
                                for item in results {
                                    let status_text = if item.is_open {
                                        RichText::new(match lang {
                                            AppLanguage::English => format!("OPEN ({}ms)", item.latency_ms.unwrap_or(0)),
                                            AppLanguage::Vietnamese => format!("MỞ ({}ms)", item.latency_ms.unwrap_or(0)),
                                        })
                                            .color(Color32::from_rgb(50, 220, 50))
                                    } else {
                                        RichText::new(tr(lang, "Closed", "Đóng")).color(Color32::from_rgb(180, 70, 70))
                                    };

                                    ui.horizontal(|ui| {
                                        ui.label(match lang {
                                            AppLanguage::English => format!("Port {:5} ({:12}):", item.port, item.service),
                                            AppLanguage::Vietnamese => format!("Cổng {:5} ({:12}):", item.port, item.service),
                                        });
                                        ui.label(status_text);
                                    });
                                }
                            });
                        }
                        1 => {
                            // Subnet NetScan
                            ui.label(tr(lang, "Scan live IP addresses across your local network subnet:", "Quét các địa chỉ IP đang hoạt động trong mạng nội bộ:"));
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Subnet Prefix:", "Tiền tố mạng con:"));
                                ui.add(TextEdit::singleline(&mut self.network_tools.subnet_prefix).desired_width(120.0).hint_text("192.168.1"));
                                if ui.button(tr(lang, "📡 Scan Subnet (.1 - .50)", "📡 Quét mạng con (.1 - .50)")).clicked() {
                                    self.network_tools.start_subnet_scan(&rt_handle);
                                }
                            });

                            let progress = *self.network_tools.subnet_progress.lock();
                            ui.add(egui::ProgressBar::new(progress).show_percentage());

                            ui.separator();
                            ui.label(RichText::new(tr(lang, "Discovered Live Hosts:", "Các máy đang hoạt động:")).strong());

                            ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                                let results = self.network_tools.subnet_results.lock().clone();
                                if results.is_empty() {
                                    ui.label(tr(lang, "No active hosts found yet. Click 'Scan Subnet' to start.", "Chưa tìm thấy máy nào. Nhấn 'Quét mạng con' để bắt đầu."));
                                }
                                for item in results {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(format!("🟢 {}", item.ip)).strong().color(Color32::from_rgb(80, 230, 120)));
                                        ui.label(match lang {
                                            AppLanguage::English => format!("Latency: {}ms", item.latency_ms.unwrap_or(0)),
                                            AppLanguage::Vietnamese => format!("Độ trễ: {}ms", item.latency_ms.unwrap_or(0)),
                                        });
                                        if let Some(srv) = item.open_service {
                                            ui.label(RichText::new(match lang {
                                                AppLanguage::English => format!("Service: {}", srv),
                                                AppLanguage::Vietnamese => format!("Dịch vụ: {}", srv),
                                            }).color(Color32::from_rgb(100, 200, 255)));
                                        }
                                    });
                                }
                            });
                        }
                        2 => {
                            // TCP Ping
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Ping Target:", "Máy chủ đích:"));
                                ui.text_edit_singleline(&mut self.network_tools.ping_host);
                                if ui.button(tr(lang, "📡 Start Ping", "📡 Bắt đầu Ping")).clicked() {
                                    self.network_tools.start_ping(&rt_handle);
                                }
                            });

                            ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                                let logs = self.network_tools.ping_logs.lock().clone();
                                for line in logs {
                                    ui.label(RichText::new(line).monospace().size(11.0));
                                }
                            });
                        }
                        3 => {
                            // Netstat Viewer
                            ui.horizontal(|ui| {
                                if ui.button(tr(lang, "🔄 Refresh Active Connections", "🔄 Làm mới kết nối đang mở")).clicked() {
                                    self.network_tools.refresh_netstat(&rt_handle);
                                }
                            });
                            ui.separator();

                            ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                                let entries = self.network_tools.netstat_entries.lock().clone();
                                if entries.is_empty() {
                                    ui.label(tr(lang, "Click 'Refresh Active Connections' to view open ports and sockets.", "Nhấn 'Làm mới kết nối đang mở' để xem các cổng và socket."));
                                } else {
                                    for entry in entries {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(&entry.proto).color(Color32::from_rgb(255, 200, 80)));
                                            ui.label(format!("{:22} -> {:22}", entry.local_addr, entry.remote_addr));
                                            ui.label(RichText::new(&entry.state).color(Color32::from_rgb(80, 230, 120)).strong());
                                        });
                                    }
                                }
                            });
                        }
                        4 => {
                            // DNS Lookup
                            ui.label(tr(lang, "Domain Name System (DNS) & Hostname Resolution:", "Phân giải tên miền (DNS) & Hostname:"));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Hostname / Domain:", "Tên miền / Hostname:"));
                                ui.add(TextEdit::singleline(&mut self.network_tools.dns_query).desired_width(220.0).hint_text(tr(lang, "e.g. google.com", "VD: google.com")));
                                if ui.button(tr(lang, "🔍 Resolve IP", "🔍 Phân giải IP")).clicked() {
                                    self.network_tools.lookup_dns();
                                }
                            });
                            ui.separator();
                            ui.label(RichText::new(tr(lang, "Resolution Results:", "Kết quả phân giải:")).strong());
                            ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                                if self.network_tools.dns_results.is_empty() {
                                    ui.label(tr(lang, "Enter a hostname and click Resolve IP.", "Nhập tên miền và nhấn Phân giải IP."));
                                } else {
                                    for res in &self.network_tools.dns_results {
                                        ui.label(RichText::new(res).monospace().color(Color32::from_rgb(56, 189, 248)));
                                    }
                                }
                            });
                        }
                        5 => {
                            // Wake-on-LAN
                            ui.label(tr(lang, "Send Wake-on-LAN (WOL) Magic Packets to power on remote computers:", "Gửi gói tin Wake-on-LAN (WOL) để bật máy tính từ xa:"));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "MAC Address:", "Địa chỉ MAC:"));
                                ui.add(TextEdit::singleline(&mut self.network_tools.wol_mac).desired_width(180.0).hint_text("00:11:22:33:44:55"));
                                ui.label(tr(lang, "UDP Port:", "Cổng UDP:"));
                                ui.add(egui::DragValue::new(&mut self.network_tools.wol_port).range(1..=65535));
                            });
                            ui.add_space(4.0);
                            if ui.button(RichText::new(tr(lang, "⚡ Send Magic Packet", "⚡ Gửi gói Magic Packet")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                                self.network_tools.send_wol();
                            }
                            if let Some(ref st) = self.network_tools.wol_status {
                                ui.add_space(4.0);
                                ui.label(RichText::new(st).color(Color32::from_rgb(80, 240, 120)).strong());
                            }
                        }
                        _ => {}
                    }
                });
            self.show_network_tools = open;
        }

        // Embedded Network Daemons Suite (HTTP, Syslog)
        if self.show_services_modal {
            let mut open = self.show_services_modal;
            let rt_handle = self.tokio_runtime.handle().clone();

            egui::Window::new(tr(lang, "🚀 Embedded Network Daemons", "🚀 Dịch vụ mạng tích hợp"))
                .open(&mut open)
                .default_size(Vec2::new(600.0, 420.0))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.services_tab, 0, tr(lang, "🌐 HTTP Server", "🌐 Máy chủ HTTP"));
                        ui.selectable_value(&mut self.services_tab, 1, tr(lang, "📡 Syslog Server", "📡 Máy chủ Syslog"));
                        ui.selectable_value(&mut self.services_tab, 2, tr(lang, "📁 TFTP Server", "📁 Máy chủ TFTP"));
                    });
                    ui.separator();

                    if self.services_tab == 0 {
                        ui.label(tr(lang, "Share local files across your local network instantly via HTTP:", "Chia sẻ tệp cục bộ qua mạng nội bộ tức thì bằng HTTP:"));
                        ui.separator();

                        ui.horizontal(|ui| {
                            ui.label(tr(lang, "Serving Folder:", "Thư mục chia sẻ:"));
                            let path_str = self.network_tools.http_root.to_string_lossy().to_string();
                            ui.label(RichText::new(path_str).monospace().color(Color32::from_rgb(100, 200, 255)));
                            if ui.button(tr(lang, "Browse...", "Chọn thư mục...")).clicked()
                                && let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                    self.network_tools.http_root = folder;
                                }
                        });

                        ui.horizontal(|ui| {
                            ui.label(tr(lang, "HTTP Port:", "Cổng HTTP:"));
                            ui.add(egui::DragValue::new(&mut self.network_tools.http_port).range(1024..=65535));

                            let is_running = self.network_tools.http_running.load(std::sync::atomic::Ordering::Relaxed);
                            if is_running {
                                if ui.button(RichText::new(tr(lang, "⏹ Stop Server", "⏹ Dừng máy chủ")).color(Color32::from_rgb(255, 100, 100))).clicked() {
                                    self.network_tools.stop_http_server();
                                }
                                ui.label(RichText::new(match lang {
                                    AppLanguage::English => format!("🟢 Online: http://127.0.0.1:{}", self.network_tools.http_port),
                                    AppLanguage::Vietnamese => format!("🟢 Đang chạy: http://127.0.0.1:{}", self.network_tools.http_port),
                                }).color(Color32::from_rgb(80, 240, 120)));
                            } else {
                                if ui.button(RichText::new(tr(lang, "▶ Start Server", "▶ Khởi chạy")).color(Color32::from_rgb(80, 240, 120))).clicked() {
                                    self.network_tools.start_http_server(&rt_handle);
                                }
                                ui.label(RichText::new(tr(lang, "⚪ Offline", "⚪ Đang tắt")).weak());
                            }
                        });

                        ui.separator();
                        ui.label(RichText::new(tr(lang, "HTTP Access Log:", "Nhật ký truy cập HTTP:")).strong());
                        ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                            let logs = self.network_tools.http_logs.lock().clone();
                            for log_line in logs {
                                ui.label(RichText::new(log_line).monospace().size(11.0));
                            }
                        });
                    } else if self.services_tab == 1 {
                        // Syslog
                        ui.label(tr(lang, "Receive and analyze syslog stream from routers, switches, and remote servers:", "Thu nhận và phân tích luồng Syslog từ router, switch và máy chủ từ xa:"));
                        ui.separator();

                        ui.horizontal(|ui| {
                            ui.label(tr(lang, "Syslog UDP Port:", "Cổng UDP Syslog:"));
                            ui.add(egui::DragValue::new(&mut self.network_tools.syslog_port).range(1..=65535));

                            let is_running = self.network_tools.syslog_running.load(std::sync::atomic::Ordering::Relaxed);
                            if is_running {
                                if ui.button(RichText::new(tr(lang, "⏹ Stop Syslog", "⏹ Dừng Syslog")).color(Color32::from_rgb(255, 100, 100))).clicked() {
                                    self.network_tools.stop_syslog_server();
                                }
                                ui.label(RichText::new(tr(lang, "🟢 Listening for UDP packets", "🟢 Đang lắng nghe gói tin UDP")).color(Color32::from_rgb(80, 240, 120)));
                            } else {
                                if ui.button(RichText::new(tr(lang, "▶ Start Syslog", "▶ Chạy Syslog")).color(Color32::from_rgb(80, 240, 120))).clicked() {
                                    self.network_tools.start_syslog_server(&rt_handle);
                                }
                                ui.label(RichText::new(tr(lang, "⚪ Offline", "⚪ Đang tắt")).weak());
                            }
                        });

                        ui.separator();
                        ui.label(RichText::new(tr(lang, "Live Syslog Stream:", "Luồng Syslog trực tiếp:")).strong());
                        ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                            let logs = self.network_tools.syslog_logs.lock().clone();
                            for log_line in logs {
                                ui.label(RichText::new(log_line).monospace().size(11.0));
                            }
                        });
                    } else {
                        // TFTP Server
                        ui.label(tr(lang, "Embedded Micro TFTP Server (RFC 1350) for router/firmware backups:", "Máy chủ Micro TFTP tích hợp (RFC 1350) để sao lưu router/firmware:"));
                        ui.separator();

                        ui.horizontal(|ui| {
                            ui.label(tr(lang, "TFTP Root Folder:", "Thư mục gốc TFTP:"));
                            let path_str = self.network_tools.tftp_root.to_string_lossy().to_string();
                            ui.label(RichText::new(path_str).monospace().color(Color32::from_rgb(100, 200, 255)));
                            if ui.button(tr(lang, "Browse...", "Chọn thư mục...")).clicked()
                                && let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                    self.network_tools.tftp_root = folder;
                                }
                        });

                        ui.horizontal(|ui| {
                            ui.label(tr(lang, "TFTP UDP Port:", "Cổng UDP TFTP:"));
                            ui.add(egui::DragValue::new(&mut self.network_tools.tftp_port).range(1..=65535));

                            let is_running = self.network_tools.tftp_running.load(std::sync::atomic::Ordering::Relaxed);
                            if is_running {
                                if ui.button(RichText::new(tr(lang, "⏹ Stop TFTP", "⏹ Dừng TFTP")).color(Color32::from_rgb(255, 100, 100))).clicked() {
                                    self.network_tools.stop_tftp_server();
                                }
                                ui.label(RichText::new(match lang {
                                    AppLanguage::English => format!("🟢 Listening on UDP port {}", self.network_tools.tftp_port),
                                    AppLanguage::Vietnamese => format!("🟢 Đang lắng nghe cổng UDP {}", self.network_tools.tftp_port),
                                }).color(Color32::from_rgb(80, 240, 120)));
                            } else {
                                if ui.button(RichText::new(tr(lang, "▶ Start TFTP", "▶ Chạy TFTP")).color(Color32::from_rgb(80, 240, 120))).clicked() {
                                    self.network_tools.start_tftp_server(&rt_handle);
                                }
                                ui.label(RichText::new(tr(lang, "⚪ Offline", "⚪ Đang tắt")).weak());
                            }
                        });

                        ui.separator();
                        ui.label(RichText::new(tr(lang, "TFTP Request & Transfer Log:", "Nhật ký yêu cầu & truyền tải TFTP:")).strong());
                        ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                            let logs = self.network_tools.tftp_logs.lock().clone();
                            for log_line in logs {
                                ui.label(RichText::new(log_line).monospace().size(11.0));
                            }
                        });
                    }
                });
            self.show_services_modal = open;
        }


        // =========================================================================
        // SSH TUNNELS / PORT FORWARDING DASHBOARD (Visual Graph Cards like Termius)
        // =========================================================================
        if self.show_tunnels {
            let mut open = self.show_tunnels;
            let rt_handle = self.tokio_runtime.handle().clone();
            let mut tunnel_to_remove: Option<usize> = None;
            let mut tunnel_to_start: Option<usize> = None;
            let mut tunnel_to_stop: Option<usize> = None;
            let mut tunnel_to_edit: Option<usize> = None;

            egui::Window::new(tr(lang, "🔀 SSH Tunnels & Port Forwarding Dashboard", "🔀 Bảng điều khiển Đường hầm SSH & Chuyển tiếp cổng"))
                .open(&mut open)
                .default_size(Vec2::new(840.0, 560.0))
                .resizable(true)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr(lang, "Visual SSH Port Forwarding (Local, Remote & Dynamic SOCKS5)", "Chuyển tiếp cổng SSH trực quan (Cục bộ, Từ xa & SOCKS5 động)")).size(13.0).color(Color32::from_rgb(148, 163, 184)));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button(RichText::new(tr(lang, "➕ New SSH Tunnel", "➕ Tạo đường hầm SSH mới")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                                self.editing_tunnel_idx = None;
                                self.new_tunnel_name = "New Port Forward".to_string();
                                self.new_tunnel_local_port = 8080;
                                self.new_tunnel_remote_host = "127.0.0.1".to_string();
                                self.new_tunnel_remote_port = 80;
                                self.tunnel_ssh_srv = "127.0.0.1".to_string();
                                self.tunnel_ssh_port = 22;
                                self.tunnel_ssh_user = "root".to_string();
                                self.tunnel_ssh_key_path.clear();
                                self.selected_session_fill.clear();
                                self.tunnel_edit_mode = 0;
                                self.show_tunnel_edit = true;
                            }
                        });
                    });

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr(lang, "Filter Mode:", "Bộ lọc:")).strong().size(11.5));
                        let filter_chip = |ui: &mut egui::Ui, label: &str, mode_idx: usize, current: &mut usize| {
                            let is_sel = *current == mode_idx;
                            let bg = if is_sel { Color32::from_rgb(31, 111, 235) } else { Color32::from_rgb(22, 28, 40) };
                            let stroke = if is_sel { egui::Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248)) } else { egui::Stroke::new(1.0_f32, Color32::from_rgb(45, 55, 75)) };
                            let btn = egui::Button::new(RichText::new(label).size(11.0).color(if is_sel { Color32::WHITE } else { Color32::from_rgb(201, 209, 217) }))
                                .fill(bg)
                                .stroke(stroke)
                                .rounding(4.0);
                            if ui.add(btn).clicked() {
                                *current = mode_idx;
                            }
                        };

                        filter_chip(ui, tr(lang, "All Tunnels", "Tất cả"), 0, &mut self.tunnel_filter_mode);
                        filter_chip(ui, tr(lang, "Local Forward (-L)", "Cục bộ (-L)"), 1, &mut self.tunnel_filter_mode);
                        filter_chip(ui, tr(lang, "Remote Forward (-R)", "Từ xa (-R)"), 2, &mut self.tunnel_filter_mode);
                        filter_chip(ui, tr(lang, "Dynamic SOCKS5 (-D)", "SOCKS5 động (-D)"), 3, &mut self.tunnel_filter_mode);
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(6.0);

                    let list_h = (ui.available_height() - 20.0).max(180.0);
                    ScrollArea::vertical()
                        .id_salt("tunnels_card_scroll")
                        .max_height(list_h)
                        .show(ui, |ui| {
                            ui.spacing_mut().item_spacing.y = 10.0;

                            if self.tunnel_manager.tunnels.is_empty() {
                                ui.vertical_centered(|ui| {
                                    ui.add_space(40.0);
                                    ui.label(RichText::new(tr(lang, "No SSH tunnels configured yet.", "Chưa có đường hầm SSH nào được cấu hình.")).size(14.0).weak());
                                    ui.label(tr(lang, "Click '➕ New SSH Tunnel' above to forward local or remote ports securely.", "Nhấn '➕ Tạo đường hầm SSH mới' ở trên để chuyển tiếp cổng an toàn."));
                                });
                            }

                            for (idx, tunnel) in self.tunnel_manager.tunnels.iter().enumerate() {
                                let matches_mode = match self.tunnel_filter_mode {
                                    1 => tunnel.mode == crate::tunneling::TunnelMode::LocalForward,
                                    2 => tunnel.mode == crate::tunneling::TunnelMode::RemoteForward,
                                    3 => tunnel.mode == crate::tunneling::TunnelMode::DynamicSocks5,
                                    _ => true,
                                };
                                if !matches_mode {
                                    continue;
                                }

                                let is_running = self.tunnel_manager.is_running(idx);
                                let card_border = if is_running {
                                    egui::Stroke::new(1.2_f32, Color32::from_rgb(34, 197, 94))
                                } else {
                                    egui::Stroke::new(1.0_f32, Color32::from_rgb(38, 48, 68))
                                };

                                egui::Frame::none()
                                    .fill(Color32::from_rgb(17, 21, 31))
                                    .stroke(card_border)
                                    .rounding(6.0)
                                    .inner_margin(10.0)
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            if is_running {
                                                ui.label(RichText::new(tr(lang, "🟢 Active", "🟢 Đang chạy")).color(Color32::from_rgb(34, 197, 94)).strong());
                                            } else {
                                                ui.label(RichText::new(tr(lang, "⚪ Inactive", "⚪ Đã dừng")).color(Color32::from_rgb(148, 163, 184)));
                                            }

                                            ui.label(RichText::new(&tunnel.name).strong().size(13.5).color(Color32::WHITE));

                                            let (mode_badge, mode_color) = match tunnel.mode {
                                                crate::tunneling::TunnelMode::LocalForward => (tr(lang, "Local Forward (-L)", "Cục bộ (-L)"), Color32::from_rgb(56, 189, 248)),
                                                crate::tunneling::TunnelMode::RemoteForward => (tr(lang, "Remote Forward (-R)", "Từ xa (-R)"), Color32::from_rgb(251, 191, 36)),
                                                crate::tunneling::TunnelMode::DynamicSocks5 => (tr(lang, "Dynamic SOCKS5 (-D)", "SOCKS5 động (-D)"), Color32::from_rgb(192, 132, 252)),
                                            };
                                            ui.label(RichText::new(format!("[{}]", mode_badge)).size(11.0).color(mode_color));

                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                if ui.button(tr(lang, "🗑 Delete", "🗑 Xóa")).clicked() {
                                                    tunnel_to_remove = Some(idx);
                                                }
                                                if ui.button(tr(lang, "✏ Edit", "✏ Sửa")).clicked() {
                                                    tunnel_to_edit = Some(idx);
                                                }
                                                if is_running {
                                                    if ui.button(RichText::new(tr(lang, "⏹ Stop", "⏹ Dừng")).color(Color32::from_rgb(248, 113, 113)).strong()).clicked() {
                                                        tunnel_to_stop = Some(idx);
                                                    }
                                                } else {
                                                    if ui.button(RichText::new(tr(lang, "▶ Start", "▶ Chạy")).color(Color32::from_rgb(74, 222, 128)).strong()).clicked() {
                                                        tunnel_to_start = Some(idx);
                                                    }
                                                }
                                            });
                                        });

                                        ui.add_space(6.0);

                                        egui::Frame::none()
                                            .fill(Color32::from_rgb(12, 15, 23))
                                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(28, 36, 52)))
                                            .rounding(4.0)
                                            .inner_margin(8.0)
                                            .show(ui, |ui| {
                                                ui.horizontal(|ui| {
                                                    match tunnel.mode {
                                                        crate::tunneling::TunnelMode::LocalForward => {
                                                            ui.label(RichText::new(match lang {
                                                                AppLanguage::English => format!("💻 Local :{}", tunnel.local_port),
                                                                AppLanguage::Vietnamese => format!("💻 Cục bộ :{}", tunnel.local_port),
                                                            }).strong().color(Color32::from_rgb(56, 189, 248)));
                                                            ui.label(RichText::new("───➔").weak());
                                                            ui.label(RichText::new(format!("🔐 Gateway {}@{}:{}", tunnel.ssh_user, tunnel.ssh_server, tunnel.ssh_port)).color(Color32::from_rgb(163, 230, 53)));
                                                            ui.label(RichText::new("───➔").weak());
                                                            ui.label(RichText::new(match lang {
                                                                AppLanguage::English => format!("🌐 Remote {}:{}", tunnel.remote_host, tunnel.remote_port),
                                                                AppLanguage::Vietnamese => format!("🌐 Đích từ xa {}:{}", tunnel.remote_host, tunnel.remote_port),
                                                            }).strong().color(Color32::from_rgb(251, 191, 36)));
                                                        }
                                                        crate::tunneling::TunnelMode::RemoteForward => {
                                                            ui.label(RichText::new(match lang {
                                                                AppLanguage::English => format!("🌐 Remote :{}", tunnel.remote_port),
                                                                AppLanguage::Vietnamese => format!("🌐 Từ xa :{}", tunnel.remote_port),
                                                            }).strong().color(Color32::from_rgb(251, 191, 36)));
                                                            ui.label(RichText::new("───➔").weak());
                                                            ui.label(RichText::new(format!("🔐 Gateway {}@{}:{}", tunnel.ssh_user, tunnel.ssh_server, tunnel.ssh_port)).color(Color32::from_rgb(163, 230, 53)));
                                                            ui.label(RichText::new("───➔").weak());
                                                            ui.label(RichText::new(match lang {
                                                                AppLanguage::English => format!("💻 Local {}:{}", tunnel.remote_host, tunnel.local_port),
                                                                AppLanguage::Vietnamese => format!("💻 Cục bộ {}:{}", tunnel.remote_host, tunnel.local_port),
                                                            }).strong().color(Color32::from_rgb(56, 189, 248)));
                                                        }
                                                        crate::tunneling::TunnelMode::DynamicSocks5 => {
                                                            ui.label(RichText::new(format!("💻 SOCKS5 127.0.0.1:{}", tunnel.local_port)).strong().color(Color32::from_rgb(192, 132, 252)));
                                                            ui.label(RichText::new("───➔").weak());
                                                            ui.label(RichText::new(format!("🔐 Gateway {}@{}:{}", tunnel.ssh_user, tunnel.ssh_server, tunnel.ssh_port)).color(Color32::from_rgb(163, 230, 53)));
                                                            ui.label(RichText::new("───➔").weak());
                                                            ui.label(RichText::new(tr(lang, "🌐 Dynamic Internet Target", "🌐 Đích Internet động")).strong().color(Color32::from_rgb(56, 189, 248)));
                                                        }
                                                    }
                                                });
                                            });

                                        ui.add_space(4.0);
                                        ui.horizontal(|ui| {
                                            let msg = &self.tunnel_manager.status_messages[idx];
                                            ui.label(RichText::new(match lang {
                                                AppLanguage::English => format!("Status: {}", msg),
                                                AppLanguage::Vietnamese => format!("Trạng thái: {}", msg),
                                            }).size(11.0).color(if is_running { Color32::from_rgb(74, 222, 128) } else { Color32::from_rgb(148, 163, 184) }));
                                            ui.separator();
                                            let hint = match (tunnel.mode, lang) {
                                                (crate::tunneling::TunnelMode::LocalForward, AppLanguage::English) => format!("Target app: Connect client to 127.0.0.1:{}", tunnel.local_port),
                                                (crate::tunneling::TunnelMode::LocalForward, AppLanguage::Vietnamese) => format!("Ứng dụng đích: Kết nối tới 127.0.0.1:{}", tunnel.local_port),
                                                (crate::tunneling::TunnelMode::RemoteForward, AppLanguage::English) => format!("Remote clients access port :{} on {}", tunnel.remote_port, tunnel.ssh_server),
                                                (crate::tunneling::TunnelMode::RemoteForward, AppLanguage::Vietnamese) => format!("Máy từ xa truy cập cổng :{} trên {}", tunnel.remote_port, tunnel.ssh_server),
                                                (crate::tunneling::TunnelMode::DynamicSocks5, AppLanguage::English) => format!("Configure browser proxy: SOCKS5 127.0.0.1:{}", tunnel.local_port),
                                                (crate::tunneling::TunnelMode::DynamicSocks5, AppLanguage::Vietnamese) => format!("Cấu hình proxy trình duyệt: SOCKS5 127.0.0.1:{}", tunnel.local_port),
                                            };
                                            ui.label(RichText::new(hint).size(10.5).color(Color32::from_rgb(120, 135, 155)));
                                        });
                                    });
                            }
                        });
                });

            if let Some(idx) = tunnel_to_start {
                self.tunnel_manager.start_tunnel(idx, &rt_handle);
            }
            if let Some(idx) = tunnel_to_stop {
                self.tunnel_manager.stop_tunnel(idx);
            }
            if let Some(idx) = tunnel_to_remove {
                self.tunnel_manager.remove_tunnel(idx);
                let _ = self.storage.save_tunnels(&self.tunnel_manager.tunnels);
            }
            if let Some(idx) = tunnel_to_edit
                && idx < self.tunnel_manager.tunnels.len() {
                    let t = &self.tunnel_manager.tunnels[idx];
                    self.editing_tunnel_idx = Some(idx);
                    self.new_tunnel_name = t.name.clone();
                    self.new_tunnel_local_port = t.local_port;
                    self.new_tunnel_remote_host = t.remote_host.clone();
                    self.new_tunnel_remote_port = t.remote_port;
                    self.tunnel_ssh_srv = t.ssh_server.clone();
                    self.tunnel_ssh_port = t.ssh_port;
                    self.tunnel_ssh_user = t.ssh_user.clone();
                    self.tunnel_ssh_key_path = t.ssh_key_path.clone().unwrap_or_default();
                    self.tunnel_edit_mode = match t.mode {
                        crate::tunneling::TunnelMode::LocalForward => 0,
                        crate::tunneling::TunnelMode::RemoteForward => 1,
                        crate::tunneling::TunnelMode::DynamicSocks5 => 2,
                    };
                    self.show_tunnel_edit = true;
                }

            self.show_tunnels = open;
        }

        // New / Edit SSH tunnel creation dialog
        if self.show_tunnel_edit {
            let mut open = self.show_tunnel_edit;
            let mut close_te = false;
            let mut save_te = false;
            egui::Window::new(if self.editing_tunnel_idx.is_some() { tr(lang, "✏ Edit SSH Tunnel", "✏ Sửa đường hầm SSH") } else { tr(lang, "➕ New SSH Tunnel", "➕ Tạo đường hầm SSH mới") })
                .open(&mut open)
                .default_size(Vec2::new(680.0, 480.0))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.tunnel_edit_mode, 0, tr(lang, "Local port forwarding (-L)", "Chuyển tiếp cổng cục bộ (-L)"));
                        ui.radio_value(&mut self.tunnel_edit_mode, 1, tr(lang, "Remote port forwarding (-R)", "Chuyển tiếp cổng từ xa (-R)"));
                        ui.radio_value(&mut self.tunnel_edit_mode, 2, tr(lang, "Dynamic SOCKS5 proxy (-D)", "Proxy SOCKS5 động (-D)"));
                    });
                    ui.separator();
                    ui.add_space(4.0);
                    let desc = match (self.tunnel_edit_mode, lang) {
                        (0, AppLanguage::English) => "Local clients ──(127.0.0.1:ForwardedPort)──► SSH Gateway ──► Remote Server:RemotePort",
                        (0, AppLanguage::Vietnamese) => "Máy cục bộ ──(127.0.0.1:CổngChuyểnTiếp)──► Cổng SSH ──► Máy chủ đích:CổngĐích",
                        (1, AppLanguage::English) => "Remote clients ──(SSH Server:ForwardedPort)──► SSH Gateway ──► Local Target:LocalPort",
                        (1, AppLanguage::Vietnamese) => "Máy từ xa ──(MáyChủSSH:CổngChuyểnTiếp)──► Cổng SSH ──► Đích cục bộ:CổngCụcBộ",
                        (_, AppLanguage::English) => "Local apps (SOCKS5 127.0.0.1:ForwardedPort) ──► SSH Gateway ──► Any Dynamic Internet Host",
                        (_, AppLanguage::Vietnamese) => "Ứng dụng cục bộ (SOCKS5 127.0.0.1:CổngChuyểnTiếp) ──► Cổng SSH ──► Bất kỳ máy chủ Internet nào",
                    };
                    ui.label(RichText::new(desc).monospace().size(11.5).color(Color32::from_rgb(56, 189, 248)));
                    ui.add_space(6.0);

                    // Auto-fill from saved sessions
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr(lang, "Auto-fill from Saved Session:", "Tự điền từ phiên đã lưu:")).size(12.0).color(Color32::from_rgb(148, 163, 184)));
                        let ssh_sessions: Vec<&Session> = self.sessions.iter().filter(|s| matches!(s.session_type, SessionType::Ssh { .. })).collect();
                        egui::ComboBox::from_id_salt("tunnel_session_picker")
                            .selected_text(if self.selected_session_fill.is_empty() { tr(lang, "-- Select SSH session --", "-- Chọn phiên SSH --") } else { &self.selected_session_fill })
                            .width(240.0)
                            .show_ui(ui, |ui| {
                                for s in &ssh_sessions {
                                    if ui.selectable_label(self.selected_session_fill == s.name, &s.name).clicked() {
                                        self.selected_session_fill = s.name.clone();
                                        if let SessionType::Ssh { ref host, port, ref user, ref key_path, .. } = s.session_type {
                                            self.tunnel_ssh_srv = host.clone();
                                            self.tunnel_ssh_port = port;
                                            self.tunnel_ssh_user = user.clone();
                                            self.tunnel_ssh_key_path = key_path.clone().unwrap_or_default();
                                        }
                                    }
                                }
                            });
                    });
                    ui.add_space(8.0);

                    egui::Grid::new("tunnel_edit_grid").num_columns(4).spacing([12.0, 10.0]).show(ui, |ui| {
                        ui.label(tr(lang, "Tunnel name:", "Tên đường hầm:"));
                        ui.add(TextEdit::singleline(&mut self.new_tunnel_name).desired_width(210.0).margin(Margin::symmetric(8.0, 5.0)));
                        ui.label(tr(lang, "Forwarded port:", "Cổng chuyển tiếp:"));
                        ui.add(egui::DragValue::new(&mut self.new_tunnel_local_port).range(1..=65535));
                        ui.end_row();

                        ui.label(tr(lang, "SSH gateway host:", "Máy chủ SSH:"));
                        ui.add(TextEdit::singleline(&mut self.tunnel_ssh_srv).desired_width(210.0).margin(Margin::symmetric(8.0, 5.0)));
                        ui.label(tr(lang, "SSH gateway port:", "Cổng SSH:"));
                        ui.add(egui::DragValue::new(&mut self.tunnel_ssh_port).range(1..=65535));
                        ui.end_row();

                        ui.label(tr(lang, "SSH gateway user:", "Người dùng SSH:"));
                        ui.add(TextEdit::singleline(&mut self.tunnel_ssh_user).desired_width(210.0).margin(Margin::symmetric(8.0, 5.0)));
                        ui.label(tr(lang, "SSH private key:", "Khóa riêng SSH:"));
                        ui.horizontal(|ui| {
                            ui.add(TextEdit::singleline(&mut self.tunnel_ssh_key_path).desired_width(150.0).margin(Margin::symmetric(8.0, 5.0)));
                            if ui.small_button("📂").on_hover_text(tr(lang, "Browse key file", "Chọn tệp khóa")).clicked()
                                && let Some(f) = rfd::FileDialog::new().pick_file() {
                                    self.tunnel_ssh_key_path = f.to_string_lossy().to_string();
                                }
                        });
                        ui.end_row();

                        if self.tunnel_edit_mode != 2 {
                            ui.label(tr(lang, "Remote target host:", "Máy chủ đích từ xa:"));
                            ui.add(TextEdit::singleline(&mut self.new_tunnel_remote_host).desired_width(170.0));
                            ui.label(tr(lang, "Remote target port:", "Cổng đích từ xa:"));
                            ui.add(egui::DragValue::new(&mut self.new_tunnel_remote_port).range(1..=65535));
                            ui.end_row();
                        }
                    });

                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new(tr(lang, "💾 Save Tunnel", "💾 Lưu đường hầm")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                            save_te = true;
                        }
                        if ui.button(tr(lang, "Cancel", "Hủy")).clicked() {
                            close_te = true;
                        }
                    });
                });

            if save_te {
                let name = if self.new_tunnel_name.trim().is_empty() {
                    format!("Tunnel :{}", self.new_tunnel_local_port)
                } else {
                    self.new_tunnel_name.trim().to_string()
                };
                let mode = match self.tunnel_edit_mode {
                    1 => crate::tunneling::TunnelMode::RemoteForward,
                    2 => crate::tunneling::TunnelMode::DynamicSocks5,
                    _ => crate::tunneling::TunnelMode::LocalForward,
                };
                let key_path_opt = if self.tunnel_ssh_key_path.trim().is_empty() {
                    None
                } else {
                    Some(self.tunnel_ssh_key_path.trim().to_string())
                };

                let new_cfg = crate::tunneling::TunnelConfig {
                    id: if let Some(idx) = self.editing_tunnel_idx {
                        self.tunnel_manager.tunnels.get(idx).map(|t| t.id.clone()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
                    } else {
                        uuid::Uuid::new_v4().to_string()
                    },
                    name,
                    mode,
                    local_port: self.new_tunnel_local_port,
                    remote_host: self.new_tunnel_remote_host.trim().to_string(),
                    remote_port: self.new_tunnel_remote_port,
                    ssh_server: self.tunnel_ssh_srv.trim().to_string(),
                    ssh_port: self.tunnel_ssh_port,
                    ssh_user: self.tunnel_ssh_user.trim().to_string(),
                    ssh_key_path: key_path_opt,
                };

                if let Some(idx) = self.editing_tunnel_idx {
                    self.tunnel_manager.update_tunnel(idx, new_cfg);
                } else {
                    self.tunnel_manager.add_tunnel(new_cfg);
                }
                let _ = self.storage.save_tunnels(&self.tunnel_manager.tunnels);
                self.new_tunnel_name.clear();
                self.editing_tunnel_idx = None;
                close_te = true;
            }
            self.show_tunnel_edit = open && !close_te;
        }

        // =========================================================================
        // COMMAND SNIPPETS MANAGER (DevOps & SysAdmin Library)
        // =========================================================================
        if self.show_snippets {
            let mut open = self.show_snippets;
            let mut run_snippet: Option<crate::snippets::Snippet> = None;
            let mut insert_snippet: Option<crate::snippets::Snippet> = None;
            let mut edit_snippet_idx: Option<usize> = None;
            let mut delete_snippet_idx: Option<usize> = None;

            egui::Window::new(tr(lang, "📋 Command Snippets (DevOps & SysAdmin Library)", "📋 Đoạn lệnh mẫu (Thư viện DevOps & SysAdmin)"))
                .open(&mut open)
                .default_size(Vec2::new(840.0, 560.0))
                .resizable(true)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr(lang, "Quick executable DevOps scripts & commands with placeholder variables", "Các lệnh & script DevOps chạy nhanh có hỗ trợ biến tham số")).size(12.5).color(Color32::from_rgb(148, 163, 184)));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button(RichText::new(tr(lang, "➕ Add Snippet", "➕ Thêm đoạn lệnh")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                                self.editing_snippet_idx = None;
                                self.snippet_form_name.clear();
                                self.snippet_form_command.clear();
                                self.snippet_form_category = "General".to_string();
                                self.snippet_form_desc.clear();
                                self.show_snippet_edit = true;
                            }
                        });
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("🔍").size(14.0));
                        ui.add(TextEdit::singleline(&mut self.snippet_search).hint_text(tr(lang, "Search snippets...", "Tìm kiếm đoạn lệnh...")).desired_width(260.0).margin(Margin::symmetric(8.0, 5.0)));

                        ui.add_space(8.0);
                        let cat_chip = |ui: &mut egui::Ui, label: &str, key: &str, current: &mut String| {
                            let is_sel = current == key;
                            let bg = if is_sel { Color32::from_rgb(37, 99, 235) } else { Color32::from_rgb(22, 28, 40) };
                            let stroke = if is_sel { egui::Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248)) } else { egui::Stroke::new(1.0_f32, Color32::from_rgb(51, 65, 85)) };
                            let btn = egui::Button::new(RichText::new(label).size(12.0).color(if is_sel { Color32::WHITE } else { Color32::from_rgb(226, 232, 240) }))
                                .fill(bg)
                                .stroke(stroke)
                                .rounding(6.0);
                            if ui.add(btn).clicked() {
                                *current = key.to_string();
                            }
                        };

                        cat_chip(ui, tr(lang, "All", "Tất cả"), "All", &mut self.snippet_category_filter);
                        cat_chip(ui, "Docker", "Docker", &mut self.snippet_category_filter);
                        cat_chip(ui, "Nginx", "Nginx", &mut self.snippet_category_filter);
                        cat_chip(ui, tr(lang, "System", "Hệ thống"), "System", &mut self.snippet_category_filter);
                        cat_chip(ui, tr(lang, "Database", "Cơ sở dữ liệu"), "Database", &mut self.snippet_category_filter);
                        cat_chip(ui, "Git", "Git", &mut self.snippet_category_filter);
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(6.0);

                    let list_h = (ui.available_height() - 20.0).max(180.0);
                    ScrollArea::vertical()
                        .id_salt("snippets_scroll_area")
                        .max_height(list_h)
                        .show(ui, |ui| {
                            ui.spacing_mut().item_spacing.y = 8.0;

                            let q = self.snippet_search.to_lowercase();
                            for (idx, snip) in self.snippets.iter().enumerate() {
                                if self.snippet_category_filter != "All" && snip.category != self.snippet_category_filter {
                                    continue;
                                }
                                if !q.is_empty() && !snip.name.to_lowercase().contains(&q) && !snip.command.to_lowercase().contains(&q) && !snip.category.to_lowercase().contains(&q) {
                                    continue;
                                }

                                egui::Frame::none()
                                    .fill(Color32::from_rgb(17, 21, 31))
                                    .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(38, 48, 68)))
                                    .rounding(6.0)
                                    .inner_margin(8.0)
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            let cat_col = match snip.category.as_str() {
                                                "Docker" => Color32::from_rgb(56, 189, 248),
                                                "Nginx" => Color32::from_rgb(52, 211, 153),
                                                "System" => Color32::from_rgb(251, 191, 36),
                                                "Database" => Color32::from_rgb(249, 115, 22),
                                                "Git" => Color32::from_rgb(244, 63, 94),
                                                _ => Color32::from_rgb(192, 132, 252),
                                            };
                                            ui.label(RichText::new(format!("[{}]", snip.category)).size(11.0).color(cat_col).strong());
                                            ui.label(RichText::new(&snip.name).strong().size(13.0).color(Color32::WHITE));
                                            if !snip.description.is_empty() {
                                                ui.label(RichText::new(format!("- {}", snip.description)).size(11.0).weak());
                                            }

                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                if ui.small_button("🗑").on_hover_text(tr(lang, "Delete Snippet", "Xóa đoạn lệnh")).clicked() {
                                                    delete_snippet_idx = Some(idx);
                                                }
                                                if ui.small_button("✏").on_hover_text(tr(lang, "Edit Snippet", "Sửa đoạn lệnh")).clicked() {
                                                    edit_snippet_idx = Some(idx);
                                                }
                                                if ui.button(RichText::new(tr(lang, "📋 Insert", "📋 Chèn")).size(11.5)).on_hover_text(tr(lang, "Paste into terminal without running", "Dán vào terminal không tự chạy")).clicked() {
                                                    insert_snippet = Some(snip.clone());
                                                }
                                                if ui.button(RichText::new(tr(lang, "▶ Run", "▶ Chạy")).strong().size(11.5).color(Color32::from_rgb(74, 222, 128))).on_hover_text(tr(lang, "Execute command in active terminal", "Thực thi lệnh trong terminal đang mở")).clicked() {
                                                    run_snippet = Some(snip.clone());
                                                }
                                            });
                                        });

                                        ui.add_space(4.0);
                                        egui::Frame::none()
                                            .fill(Color32::from_rgb(10, 13, 20))
                                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(26, 33, 48)))
                                            .rounding(4.0)
                                            .inner_margin(6.0)
                                            .show(ui, |ui| {
                                                ui.horizontal(|ui| {
                                                    ui.label(RichText::new("$").monospace().size(11.5).color(Color32::from_rgb(110, 120, 140)));
                                                    ui.label(RichText::new(&snip.command).monospace().size(11.5).color(Color32::from_rgb(220, 230, 242)));
                                                });
                                            });
                                    });
                            }
                        });
                });

            // Action: Run or Insert snippet
            if let Some(snip) = run_snippet {
                let vars = crate::snippets::extract_placeholders(&snip.command);
                if vars.is_empty() {
                    let cmd_to_run = format!("{}\n", snip.command);
                    self.execute_terminal_command(&cmd_to_run);
                    self.status_toast = Some((format!("Executed snippet: {}", snip.name), std::time::Instant::now()));
                } else {
                    self.active_var_fields = vars.into_iter().map(|v| (v, String::new())).collect();
                    self.active_var_snippet = Some(snip);
                    self.active_var_is_run = true;
                    self.show_snippet_vars = true;
                }
            }
            if let Some(snip) = insert_snippet {
                let vars = crate::snippets::extract_placeholders(&snip.command);
                if vars.is_empty() {
                    let cmd_to_insert = format!("{} ", snip.command);
                    self.execute_terminal_command(&cmd_to_insert);
                    self.status_toast = Some((format!("Inserted snippet: {}", snip.name), std::time::Instant::now()));
                } else {
                    self.active_var_fields = vars.into_iter().map(|v| (v, String::new())).collect();
                    self.active_var_snippet = Some(snip);
                    self.active_var_is_run = false;
                    self.show_snippet_vars = true;
                }
            }
            if let Some(idx) = delete_snippet_idx
                && idx < self.snippets.len() {
                    self.snippets.remove(idx);
                    let _ = self.storage.save_snippets(&self.snippets);
                }
            if let Some(idx) = edit_snippet_idx
                && idx < self.snippets.len() {
                    let s = &self.snippets[idx];
                    self.editing_snippet_idx = Some(idx);
                    self.snippet_form_name = s.name.clone();
                    self.snippet_form_command = s.command.clone();
                    self.snippet_form_category = s.category.clone();
                    self.snippet_form_desc = s.description.clone();
                    self.show_snippet_edit = true;
                }

            self.show_snippets = open;
        }

        // Snippet Add / Edit Dialog
        if self.show_snippet_edit {
            let mut open = self.show_snippet_edit;
            let mut close_edit = false;
            let mut save_snippet = false;

            egui::Window::new(if self.editing_snippet_idx.is_some() { tr(lang, "✏ Edit Snippet", "✏ Sửa đoạn lệnh") } else { tr(lang, "➕ Add New Snippet", "➕ Thêm đoạn lệnh mới") })
                .open(&mut open)
                .collapsible(false)
                .default_size(Vec2::new(620.0, 460.0))
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label(RichText::new(tr(lang, "Configure Reusable Command Template", "Cấu hình mẫu lệnh dùng lại")).strong().size(13.5));
                    ui.add_space(6.0);

                    egui::Grid::new("snippet_edit_grid").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
                        ui.label(RichText::new(tr(lang, "Name:", "Tên:")).size(12.5).color(Color32::from_rgb(226, 232, 240)));
                        ui.add(TextEdit::singleline(&mut self.snippet_form_name).desired_width(420.0).margin(Margin::symmetric(8.0, 5.0)));
                        ui.end_row();

                        ui.label(RichText::new(tr(lang, "Category:", "Nhóm:")).size(12.5).color(Color32::from_rgb(226, 232, 240)));
                        ui.horizontal(|ui| {
                            ui.add(TextEdit::singleline(&mut self.snippet_form_category).desired_width(200.0).margin(Margin::symmetric(8.0, 5.0)));
                            ui.label(RichText::new(tr(lang, "(e.g. Docker, Nginx, System, Database, Git)", "(VD: Docker, Nginx, System, Database, Git)")).size(11.5).color(Color32::from_rgb(148, 163, 184)));
                        });
                        ui.end_row();

                        ui.label(RichText::new(tr(lang, "Description:", "Mô tả:")).size(12.5).color(Color32::from_rgb(226, 232, 240)));
                        ui.add(TextEdit::singleline(&mut self.snippet_form_desc).desired_width(420.0).margin(Margin::symmetric(8.0, 5.0)));
                        ui.end_row();

                        ui.label(RichText::new(tr(lang, "Command:", "Câu lệnh:")).size(12.5).color(Color32::from_rgb(226, 232, 240)));
                        ui.add(
                            TextEdit::multiline(&mut self.snippet_form_command)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(420.0)
                                .desired_rows(6)
                                .margin(Margin::symmetric(8.0, 6.0)),
                        );
                        ui.end_row();
                    });

                    ui.add_space(6.0);
                    ui.label(RichText::new(tr(lang, "Tip: Insert {{variable_name}} to prompt for dynamic arguments at runtime!", "Mẹo: Chèn {{ten_bien}} để nhập tham số động khi chạy!")).size(11.0).color(Color32::from_rgb(56, 189, 248)));
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);

                    ui.horizontal(|ui| {
                        if ui.button(RichText::new(tr(lang, "💾 Save Snippet", "💾 Lưu đoạn lệnh")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                            save_snippet = true;
                        }
                        if ui.button(tr(lang, "✖ Cancel", "✖ Hủy")).clicked() {
                            close_edit = true;
                        }
                    });
                });

            if save_snippet {
                let name = if self.snippet_form_name.trim().is_empty() {
                    "Untitled Snippet".to_string()
                } else {
                    self.snippet_form_name.trim().to_string()
                };
                let category = if self.snippet_form_category.trim().is_empty() {
                    "General".to_string()
                } else {
                    self.snippet_form_category.trim().to_string()
                };
                let snip = crate::snippets::Snippet {
                    id: if let Some(idx) = self.editing_snippet_idx {
                        self.snippets.get(idx).map(|s| s.id.clone()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
                    } else {
                        uuid::Uuid::new_v4().to_string()
                    },
                    name,
                    command: self.snippet_form_command.trim().to_string(),
                    category,
                    description: self.snippet_form_desc.trim().to_string(),
                };

                if let Some(idx) = self.editing_snippet_idx {
                    if idx < self.snippets.len() {
                        self.snippets[idx] = snip;
                    }
                } else {
                    self.snippets.push(snip);
                }
                let _ = self.storage.save_snippets(&self.snippets);
                self.editing_snippet_idx = None;
                close_edit = true;
            }
            self.show_snippet_edit = open && !close_edit;
        }

        // Snippet Variable Filler Dialog
        if self.show_snippet_vars {
            let mut open = self.show_snippet_vars;
            let mut close_vars = false;
            let mut submit_vars = false;
            let active_snip = self.active_var_snippet.clone();

            if let Some(ref snip) = active_snip {
                let win_title = match lang {
                    AppLanguage::English => format!("📝 Fill Parameters - {}", snip.name),
                    AppLanguage::Vietnamese => format!("📝 Nhập tham số - {}", snip.name),
                };
                egui::Window::new(win_title)
                    .open(&mut open)
                    .collapsible(false)
                    .default_size(Vec2::new(480.0, 260.0))
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.label(RichText::new(tr(lang, "Provide values for command template:", "Nhập giá trị cho mẫu lệnh:")).strong());
                        ui.add_space(4.0);

                        egui::Frame::none()
                            .fill(Color32::from_rgb(10, 13, 20))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(28, 36, 52)))
                            .rounding(4.0)
                            .inner_margin(6.0)
                            .show(ui, |ui| {
                                ui.label(RichText::new(&snip.command).monospace().size(11.5).color(Color32::from_rgb(56, 189, 248)));
                            });

                        ui.add_space(6.0);
                        egui::Grid::new("snippet_var_fields_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                            for (var_name, var_val) in &mut self.active_var_fields {
                                ui.label(RichText::new(format!("{{{{{}}}}}:", var_name)).strong().color(Color32::from_rgb(251, 191, 36)));
                                ui.add(TextEdit::singleline(var_val).desired_width(260.0));
                                ui.end_row();
                            }
                        });

                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(4.0);

                        ui.horizontal(|ui| {
                            let action_label = if self.active_var_is_run { tr(lang, "▶ Run Command", "▶ Chạy lệnh") } else { tr(lang, "📋 Insert Command", "📋 Chèn lệnh") };
                            if ui.button(RichText::new(action_label).strong().color(Color32::from_rgb(74, 222, 128))).clicked() {
                                submit_vars = true;
                            }
                            if ui.button(tr(lang, "✖ Cancel", "✖ Hủy")).clicked() {
                                close_vars = true;
                            }
                        });
                    });

                if submit_vars {
                    let replaced_cmd = crate::snippets::replace_placeholders(&snip.command, &self.active_var_fields);
                    if self.active_var_is_run {
                        let cmd_to_run = format!("{}\n", replaced_cmd);
                        self.execute_terminal_command(&cmd_to_run);
                        self.status_toast = Some((format!("Executed snippet: {}", snip.name), std::time::Instant::now()));
                    } else {
                        let cmd_to_insert = format!("{} ", replaced_cmd);
                        self.execute_terminal_command(&cmd_to_insert);
                        self.status_toast = Some((format!("Inserted snippet: {}", snip.name), std::time::Instant::now()));
                    }
                    close_vars = true;
                }
            }
            self.show_snippet_vars = open && !close_vars;
        }

        // =========================================================================
        // AUTO-HIGHLIGHT KEYWORD RULES DIALOG (ZOC Terminal Feature)
        // =========================================================================
        if self.show_highlight_modal {
            let mut open = self.show_highlight_modal;
            let mut delete_rule_idx: Option<usize> = None;
            let mut reset_defaults = false;

            egui::Window::new(tr(lang, "🎨 Auto-Highlight Keywords (ZOC Style)", "🎨 Tự động tô màu từ khóa (kiểu ZOC)"))
                .open(&mut open)
                .default_size(Vec2::new(720.0, 560.0))
                .min_width(660.0)
                .max_width(740.0)
                .resizable(true)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        let prev_enabled = self.highlight_rules_enabled;
                        ui.checkbox(&mut self.highlight_rules_enabled, RichText::new(tr(lang, "Enable Real-Time Auto-Highlight in Terminal", "Bật tô màu tự động theo thời gian thực trong Terminal")).strong());
                        if prev_enabled != self.highlight_rules_enabled {
                            let _ = self.storage.save_highlight_rules(&self.highlight_rules, self.highlight_rules_enabled);
                        }

                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button(tr(lang, "🔄 Reset Default Rules", "🔄 Khôi phục mặc định")).on_hover_text(tr(lang, "Reset to standard Error, Warn, Success & Info rules", "Đặt lại các quy tắc Error, Warn, Success & Info mặc định")).clicked() {
                                reset_defaults = true;
                            }
                        });
                    });

                    ui.label(RichText::new(tr(lang, "Automatically highlights critical log phrases (errors, warnings, successes, IPs) in real-time without modifying server shells.", "Tự động tô sáng các cụm từ nhật ký quan trọng (lỗi, cảnh báo, thành công, IP) theo thời gian thực mà không tác động tới shell máy chủ.")).size(12.0).color(Color32::from_rgb(148, 163, 184)));

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);

                    // Add / Edit Rule Row
                    egui::Frame::none()
                        .fill(Color32::from_rgb(17, 21, 31))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(38, 48, 68)))
                        .rounding(6.0)
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(if self.editing_highlight_idx.is_some() { tr(lang, "✏ Edit Keyword:", "✏ Sửa từ khóa:") } else { tr(lang, "➕ Add Keyword:", "➕ Thêm từ khóa:") }).strong().color(Color32::from_rgb(56, 189, 248)));
                                ui.add(TextEdit::singleline(&mut self.highlight_kw_input).hint_text(tr(lang, "e.g. TIMEOUT, CRITICAL...", "VD: TIMEOUT, CRITICAL...")).desired_width(140.0));

                                ui.label(tr(lang, "Color:", "Màu:"));
                                egui::ComboBox::from_id_salt("hl_color_picker")
                                    .selected_text(match self.highlight_color_idx {
                                        0 => tr(lang, "🔴 Red (Error)", "🔴 Đỏ (Lỗi)"),
                                        1 => tr(lang, "🟡 Yellow (Warn)", "🟡 Vàng (Cảnh báo)"),
                                        2 => tr(lang, "🟢 Green (Success)", "🟢 Xanh lá (Thành công)"),
                                        3 => tr(lang, "🔵 Cyan (Notice)", "🔵 Xanh lơ (Thông báo)"),
                                        4 => tr(lang, "🟣 Magenta (Special)", "🟣 Tím (Đặc biệt)"),
                                        _ => tr(lang, "⚪ White", "⚪ Trắng"),
                                    })
                                    .width(130.0)
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(&mut self.highlight_color_idx, 0, tr(lang, "🔴 Red (Error)", "🔴 Đỏ (Lỗi)"));
                                        ui.selectable_value(&mut self.highlight_color_idx, 1, tr(lang, "🟡 Yellow (Warn)", "🟡 Vàng (Cảnh báo)"));
                                        ui.selectable_value(&mut self.highlight_color_idx, 2, tr(lang, "🟢 Green (Success)", "🟢 Xanh lá (Thành công)"));
                                        ui.selectable_value(&mut self.highlight_color_idx, 3, tr(lang, "🔵 Cyan (Notice)", "🔵 Xanh lơ (Thông báo)"));
                                        ui.selectable_value(&mut self.highlight_color_idx, 4, tr(lang, "🟣 Magenta (Special)", "🟣 Tím (Đặc biệt)"));
                                    });

                                let btn_label = if self.editing_highlight_idx.is_some() { tr(lang, "💾 Update", "💾 Cập nhật") } else { tr(lang, "➕ Add Rule", "➕ Thêm quy tắc") };
                                if ui.button(RichText::new(btn_label).strong().color(Color32::from_rgb(74, 222, 128))).clicked() {
                                    let kw = self.highlight_kw_input.trim();
                                    if !kw.is_empty() {
                                        let rgb = match self.highlight_color_idx {
                                            0 => [255, 90, 90],
                                            1 => [255, 210, 60],
                                            2 => [80, 230, 120],
                                            3 => [80, 210, 245],
                                            4 => [216, 112, 240],
                                            _ => [240, 240, 240],
                                        };
                                        if let Some(idx) = self.editing_highlight_idx {
                                            if idx < self.highlight_rules.len() {
                                                self.highlight_rules[idx].keyword = kw.to_string();
                                                self.highlight_rules[idx].color_rgb = rgb;
                                                self.highlight_rules[idx].whole_word = self.highlight_whole_word;
                                                self.highlight_rules[idx].match_case = self.highlight_match_case;
                                            }
                                            self.editing_highlight_idx = None;
                                        } else {
                                            let mut r = crate::terminal::HighlightRule::new(kw, rgb[0], rgb[1], rgb[2]);
                                            r.whole_word = self.highlight_whole_word;
                                            r.match_case = self.highlight_match_case;
                                            self.highlight_rules.push(r);
                                        }
                                        let _ = self.storage.save_highlight_rules(&self.highlight_rules, self.highlight_rules_enabled);
                                        self.highlight_kw_input.clear();
                                    }
                                }
                                if self.editing_highlight_idx.is_some()
                                    && ui.button(tr(lang, "✖ Cancel", "✖ Hủy")).clicked() {
                                        self.editing_highlight_idx = None;
                                        self.highlight_kw_input.clear();
                                    }
                            });

                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(tr(lang, "Options:", "Tùy chọn:")).size(11.0).weak());
                                ui.checkbox(&mut self.highlight_whole_word, tr(lang, "Match whole word only", "Chỉ khớp nguyên từ")).on_hover_text(tr(lang, "Avoid matching inside other words (e.g. 'error' won't match inside 'terror')", "Tránh khớp bên trong từ khác (VD: 'error' không khớp với 'terror')"));
                                ui.checkbox(&mut self.highlight_match_case, tr(lang, "Match case sensitive", "Phân biệt chữ hoa/thường")).on_hover_text(tr(lang, "Match exact casing only", "Chỉ khớp đúng chữ hoa/thường"));
                            });
                        });

                    ui.add_space(8.0);

                    // Rules List
                    ui.label(RichText::new(tr(lang, "Configured Keyword Rules:", "Danh sách quy tắc từ khóa:")).strong().size(12.5));
                    let list_h = 170.0;
                    ScrollArea::vertical()
                        .id_salt("highlight_rules_scroll")
                        .max_height(list_h)
                        .show(ui, |ui| {
                            egui::Grid::new("hl_rules_grid")
                                .striped(true)
                                .min_col_width(50.0)
                                .spacing(vec2(10.0, 6.0))
                                .show(ui, |ui| {
                                    ui.label(RichText::new(tr(lang, "Active", "Bật")).strong());
                                    ui.label(RichText::new(tr(lang, "Color", "Màu")).strong());
                                    ui.label(RichText::new(tr(lang, "Keyword", "Từ khóa")).strong());
                                    ui.label(RichText::new(tr(lang, "Matching Mode", "Kiểu khớp")).strong());
                                    ui.label(RichText::new(tr(lang, "Actions", "Thao tác")).strong());
                                    ui.end_row();

                                    let mut state_changed = false;
                                    for (idx, rule) in self.highlight_rules.iter_mut().enumerate() {
                                        let mut active = rule.enabled;
                                        if ui.checkbox(&mut active, "").changed() {
                                            rule.enabled = active;
                                            state_changed = true;
                                        }

                                        let col = Color32::from_rgb(rule.color_rgb[0], rule.color_rgb[1], rule.color_rgb[2]);
                                        ui.horizontal(|ui| {
                                            let (rect, _) = ui.allocate_exact_size(vec2(14.0, 14.0), egui::Sense::hover());
                                            ui.painter().rect_filled(rect, 3.0, col);
                                        });

                                        ui.label(RichText::new(&rule.keyword).strong().color(col));

                                        let mode_desc = match (rule.whole_word, rule.match_case) {
                                            (true, true) => tr(lang, "Whole Word + Case Sensitive", "Nguyên từ + Phân biệt hoa/thường"),
                                            (true, false) => tr(lang, "Whole Word (Any Case)", "Nguyên từ (Không phân biệt hoa/thường)"),
                                            (false, true) => tr(lang, "Substring + Case Sensitive", "Chuỗi con + Phân biệt hoa/thường"),
                                            (false, false) => tr(lang, "Substring (Any Case)", "Chuỗi con (Không phân biệt hoa/thường)"),
                                        };
                                        ui.label(RichText::new(mode_desc).size(11.0).color(Color32::from_rgb(148, 163, 184)));

                                        ui.horizontal(|ui| {
                                            if ui.small_button(tr(lang, "✏ Edit", "✏ Sửa")).clicked() {
                                                self.editing_highlight_idx = Some(idx);
                                                self.highlight_kw_input = rule.keyword.clone();
                                                self.highlight_whole_word = rule.whole_word;
                                                self.highlight_match_case = rule.match_case;
                                                self.highlight_color_idx = match rule.color_rgb {
                                                    [255, 90, 90] => 0,
                                                    [255, 210, 60] => 1,
                                                    [80, 230, 120] => 2,
                                                    [80, 210, 245] => 3,
                                                    [216, 112, 240] => 4,
                                                    _ => 0,
                                                };
                                            }
                                            if ui.small_button("🗑").on_hover_text(tr(lang, "Delete keyword", "Xóa từ khóa")).clicked() {
                                                delete_rule_idx = Some(idx);
                                            }
                                        });
                                        ui.end_row();
                                    }

                                    if state_changed {
                                        let _ = self.storage.save_highlight_rules(&self.highlight_rules, self.highlight_rules_enabled);
                                    }
                                });
                        });

                    if let Some(idx) = delete_rule_idx
                        && idx < self.highlight_rules.len() {
                            self.highlight_rules.remove(idx);
                            let _ = self.storage.save_highlight_rules(&self.highlight_rules, self.highlight_rules_enabled);
                        }

                    if reset_defaults {
                        self.highlight_rules = crate::terminal::highlight::default_highlight_rules();
                        let _ = self.storage.save_highlight_rules(&self.highlight_rules, self.highlight_rules_enabled);
                    }

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);

                    // Real-Time Live Preview Pane
                    ui.label(RichText::new(tr(lang, "🔬 Real-Time Terminal Rendering Preview:", "🔬 Xem trước hiển thị trên Terminal:")).strong().size(12.0).color(Color32::from_rgb(56, 189, 248)));
                    ui.add_space(2.0);

                    egui::Frame::none()
                        .fill(Color32::from_rgb(10, 13, 20))
                        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(26, 33, 48)))
                        .rounding(4.0)
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            for line in self.highlight_preview_text.lines() {
                                let highlights = crate::terminal::widget::compute_row_syntax_highlights_with_rules(
                                    line,
                                    line.chars().count(),
                                    Some(&self.highlight_rules),
                                    self.highlight_rules_enabled,
                                );
                                ui.horizontal(|ui| {
                                    let chars: Vec<char> = line.chars().collect();
                                    let mut i = 0;
                                    while i < chars.len() {
                                        let color = highlights.get(i).copied().flatten().unwrap_or(Color32::from_rgb(201, 209, 217));
                                        let mut j = i + 1;
                                        while j < chars.len() && highlights.get(j).copied().flatten() == highlights.get(i).copied().flatten() {
                                            j += 1;
                                        }
                                        let chunk: String = chars[i..j].iter().collect();
                                        ui.label(RichText::new(chunk).monospace().size(12.0).color(color));
                                        i = j;
                                    }
                                });
                            }
                        });

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr(lang, "Edit test log:", "Sửa dòng thử:")).size(11.0).weak());
                        ui.add(TextEdit::multiline(&mut self.highlight_preview_text).desired_rows(2).desired_width(560.0));
                    });
                });

            self.show_highlight_modal = open;
        }

        // KEYGEN DIALOG (RustyBox KeyGen)
        if self.show_keygen {
            let mut open = self.show_keygen;
            let mut close_kg = false;
            egui::Window::new(tr(lang, "🔑 RustyBox KeyGen - SSH Key Generator", "🔑 RustyBox KeyGen - Trình tạo khóa SSH"))
                .open(&mut open)
                .default_size(Vec2::new(560.0, 440.0))
                .show(ctx, |ui| {
                    ui.label(RichText::new(tr(lang, "Generate OpenSSH Public / Private Key Pairs", "Tạo cặp khóa công khai / riêng tư chuẩn OpenSSH")).strong());
                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Key Type:", "Loại khóa:"));
                        ui.radio_value(&mut self.keygen_type, 0, tr(lang, "Ed25519 (Modern & Fast)", "Ed25519 (Hiện đại & Nhanh)"));
                        ui.radio_value(&mut self.keygen_type, 1, tr(lang, "RSA (4096-bit Standard)", "RSA (Chuẩn 4096-bit)"));
                    });

                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Key Comment:", "Ghi chú khóa:"));
                        ui.text_edit_singleline(&mut self.keygen_comment);
                    });

                    ui.add_space(4.0);
                    if ui.button(RichText::new(tr(lang, "⚡ Generate New Key Pair", "⚡ Tạo cặp khóa mới")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                        self.generate_ssh_key_pair();
                    }

                    if !self.keygen_public.is_empty() {
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(tr(lang, "Public Key (authorized_keys format):", "Khóa công khai (định dạng authorized_keys):")).strong());
                            if ui.button(tr(lang, "📋 Copy", "📋 Sao chép")).clicked() {
                                ctx.copy_text(self.keygen_public.clone());
                            }
                        });
                        ui.add(egui::TextEdit::multiline(&mut self.keygen_public).desired_rows(3).font(egui::TextStyle::Monospace));

                        if !self.keygen_fingerprint.is_empty() {
                            ui.label(match lang {
                                AppLanguage::English => format!("Key Fingerprint: {}", self.keygen_fingerprint),
                                AppLanguage::Vietnamese => format!("Dấu vân tay khóa: {}", self.keygen_fingerprint),
                            });
                        }

                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.button(tr(lang, "💾 Save Public Key (.pub)...", "💾 Lưu khóa công khai (.pub)...")).clicked()
                                && let Some(path) = rfd::FileDialog::new().add_filter("Public Key", &["pub"]).save_file() {
                                    let _ = std::fs::write(&path, &self.keygen_public);
                                }
                            if ui.button(tr(lang, "🔒 Save Private Key...", "🔒 Lưu khóa riêng tư...")).clicked()
                                && let Some(path) = rfd::FileDialog::new().save_file() {
                                    let _ = std::fs::write(&path, &self.keygen_private);
                                }
                        });
                    }
                    ui.add_space(8.0);
                    ui.separator();
                    if ui.button(tr(lang, "Close", "Đóng")).clicked() {
                        close_kg = true;
                    }
                });
            self.show_keygen = open && !close_kg;
        }

        // RANDOM PASSWORD GENERATOR
        if self.show_pwdgen {
            let mut open = self.show_pwdgen;
            let mut close_pg = false;
            egui::Window::new(tr(lang, "🗝 Random Password Generator", "🗝 Trình tạo mật khẩu ngẫu nhiên"))
                .open(&mut open)
                .default_size(Vec2::new(480.0, 320.0))
                .show(ctx, |ui| {
                    ui.label(RichText::new(tr(lang, "Generate Cryptographically Strong Passwords", "Tạo mật khẩu ngẫu nhiên độ an toàn cao")).strong());
                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Password Length:", "Độ dài mật khẩu:"));
                        ui.add(egui::DragValue::new(&mut self.pwdgen_len).range(8..=64));
                    });

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.pwdgen_upper, tr(lang, "Uppercase (A-Z)", "Chữ hoa (A-Z)"));
                        ui.checkbox(&mut self.pwdgen_lower, tr(lang, "Lowercase (a-z)", "Chữ thường (a-z)"));
                    });
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.pwdgen_digits, tr(lang, "Numbers (0-9)", "Chữ số (0-9)"));
                        ui.checkbox(&mut self.pwdgen_symbols, tr(lang, "Symbols (!@#$%)", "Ký tự đặc biệt (!@#$%)"));
                    });

                    ui.add_space(6.0);
                    if ui.button(RichText::new(tr(lang, "⚡ Generate Password", "⚡ Tạo mật khẩu")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                        self.generate_random_password();
                    }

                    if !self.pwdgen_output.is_empty() {
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.pwdgen_output).font(egui::TextStyle::Monospace).desired_width(280.0));
                            if ui.button(tr(lang, "📋 Copy", "📋 Sao chép")).clicked() {
                                ctx.copy_text(self.pwdgen_output.clone());
                            }
                        });
                    }
                    ui.add_space(8.0);
                    ui.separator();
                    if ui.button(tr(lang, "Close", "Đóng")).clicked() {
                        close_pg = true;
                    }
                });
            self.show_pwdgen = open && !close_pg;
        }

        // FILE COMPARISON (RustyBox Diff)
        if self.show_diff {
            let mut open = self.show_diff;
            let mut close_df = false;
            egui::Window::new(tr(lang, "📄 File Comparison (RustyBox Diff)", "📄 So sánh tệp & văn bản (RustyBox Diff)"))
                .open(&mut open)
                .default_size(Vec2::new(660.0, 480.0))
                .show(ctx, |ui| {
                    ui.label(RichText::new(tr(lang, "Visual Text & Configuration Diff Tool", "Công cụ so sánh trực quan văn bản & tệp cấu hình")).strong());
                    ui.separator();

                    ui.columns(2, |cols| {
                        cols[0].label(RichText::new(tr(lang, "Original Text / File A:", "Văn bản gốc / Tệp A:")).strong());
                        cols[0].add(egui::TextEdit::multiline(&mut self.diff_text_a).desired_rows(8).font(egui::TextStyle::Monospace));
                        if cols[0].button(tr(lang, "Load File A...", "Mở Tệp A...")).clicked()
                            && let Some(path) = rfd::FileDialog::new().pick_file()
                                && let Ok(s) = std::fs::read_to_string(&path) {
                                    self.diff_text_a = s;
                                }

                        cols[1].label(RichText::new(tr(lang, "Modified Text / File B:", "Văn bản sửa / Tệp B:")).strong());
                        cols[1].add(egui::TextEdit::multiline(&mut self.diff_text_b).desired_rows(8).font(egui::TextStyle::Monospace));
                        if cols[1].button(tr(lang, "Load File B...", "Mở Tệp B...")).clicked()
                            && let Some(path) = rfd::FileDialog::new().pick_file()
                                && let Ok(s) = std::fs::read_to_string(&path) {
                                    self.diff_text_b = s;
                                }
                    });

                    ui.add_space(6.0);
                    if ui.button(RichText::new(tr(lang, "🔍 Compare Texts / Files", "🔍 So sánh văn bản / tệp")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                        self.compute_diff();
                    }

                    if !self.diff_result.is_empty() {
                        ui.separator();
                        ui.label(RichText::new(tr(lang, "Diff Results (- removed, + added):", "Kết quả so sánh (- đã xóa, + đã thêm):")).strong());
                        ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                            for line in &self.diff_result {
                                if line.starts_with('+') {
                                    ui.label(RichText::new(line).color(Color32::from_rgb(46, 160, 67)).monospace());
                                } else if line.starts_with('-') {
                                    ui.label(RichText::new(line).color(Color32::from_rgb(248, 81, 73)).monospace());
                                } else {
                                    ui.label(RichText::new(line).monospace());
                                }
                            }
                        });
                    }
                    ui.add_space(8.0);
                    ui.separator();
                    if ui.button(tr(lang, "Close", "Đóng")).clicked() {
                        close_df = true;
                    }
                });
            self.show_diff = open && !close_df;
        }

        // RUSTYBOX APT PACKAGE MANAGER (TFormMobApt)
        if self.show_mobapt {
            let mut open = self.show_mobapt;
            let mut close_apt = false;
            let packages = [
                ("openssh", "9.8p1", "Secure Shell client and key utilities", true),
                ("curl", "8.9.1", "Command line tool for transferring data with URLs", true),
                ("git", "2.46.0", "Fast, scalable, distributed revision control system", true),
                ("tmux", "3.4", "Terminal multiplexer", false),
                ("htop", "3.3.0", "Interactive processes viewer", true),
                ("nmap", "7.95", "Network exploration tool and security / port scanner", false),
                ("rsync", "3.3.0", "Fast, versatile, remote file-copying tool", true),
                ("jq", "1.7.1", "Lightweight and flexible command-line JSON processor", true),
                ("iperf3", "3.17", "TCP, UDP, and SCTP network bandwidth measurement tool", false),
                ("mtr", "0.95", "Network diagnostic tool combining ping and traceroute", false),
            ];

            egui::Window::new(tr(lang, "📦 RustyBox Apt Package Manager", "📦 Trình quản lý gói RustyBox Apt"))
                .open(&mut open)
                .default_size(Vec2::new(620.0, 440.0))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Filter packages:", "Lọc gói:"));
                        ui.add(TextEdit::singleline(&mut self.mobapt_search).desired_width(200.0).hint_text("curl, git, tmux, htop, nmap..."));
                    });
                    ui.separator();

                    ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                        egui::Grid::new("apt_pkg_grid")
                            .striped(true)
                            .min_col_width(70.0)
                            .spacing(vec2(12.0, 6.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new(tr(lang, "Package", "Tên gói")).strong());
                                ui.label(RichText::new(tr(lang, "Version", "Phiên bản")).strong());
                                ui.label(RichText::new(tr(lang, "Description", "Mô tả")).strong());
                                ui.label(RichText::new(tr(lang, "Status", "Trạng thái")).strong());
                                ui.end_row();

                                for (pkg, ver, desc, installed) in &packages {
                                    if !self.mobapt_search.trim().is_empty()
                                        && !pkg.contains(&self.mobapt_search.to_lowercase())
                                        && !desc.to_lowercase().contains(&self.mobapt_search.to_lowercase())
                                    {
                                        continue;
                                    }

                                    ui.label(RichText::new(*pkg).strong());
                                    ui.label(*ver);
                                    ui.label(*desc);
                                    if *installed {
                                        ui.label(RichText::new(tr(lang, "Installed", "Đã cài đặt")).color(Color32::from_rgb(46, 160, 67)).strong());
                                    } else {
                                        ui.label(RichText::new(tr(lang, "Available", "Khả dụng")).color(Color32::from_rgb(56, 189, 248)));
                                    }
                                    ui.end_row();
                                }
                            });
                    });
                    ui.add_space(8.0);
                    ui.separator();
                    if ui.button(tr(lang, "Close", "Đóng")).clicked() {
                        close_apt = true;
                    }
                });
            self.show_mobapt = open && !close_apt;
        }

        // Macro Manager Modal (MobaXterm TFORMMANAGEMACROS)
        if self.show_macro_manager {
            let mut open = self.show_macro_manager;
            let mut delete_idx: Option<usize> = None;

            egui::Window::new(tr(lang, "⚡ Manage Sysadmin Quick Macros", "⚡ Quản lý Macro thao tác nhanh"))
                .open(&mut open)
                .default_size(Vec2::new(480.0, 360.0))
                .show(ctx, |ui| {
                    ui.label(tr(lang, "Add, remove, or customize single-click terminal macros:", "Thêm, xóa hoặc tùy chỉnh các lệnh Macro chạy chỉ với 1 lần nhấn:"));
                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Name:", "Tên:"));
                        ui.add(TextEdit::singleline(&mut self.new_macro_name).desired_width(100.0).hint_text("ps aux"));
                        ui.label(tr(lang, "Command:", "Lệnh:"));
                        ui.add(TextEdit::singleline(&mut self.new_macro_cmd).desired_width(160.0).hint_text("ps aux\n"));
                        if ui.button(tr(lang, "➕ Add", "➕ Thêm")).clicked()
                            && !self.new_macro_name.trim().is_empty() && !self.new_macro_cmd.is_empty() {
                                let mut cmd = self.new_macro_cmd.clone();
                                if !cmd.ends_with('\n') {
                                    cmd.push('\n');
                                }
                                self.quick_macros.push((self.new_macro_name.trim().to_string(), cmd));
                                let _ = self.storage.save_quick_macros(&self.quick_macros);
                                self.new_macro_name.clear();
                                self.new_macro_cmd.clear();
                            }
                    });

                    ui.separator();
                    ui.label(RichText::new(tr(lang, "Existing Macros:", "Danh sách Macro hiện có:")).strong());

                    ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                        for (idx, (name, cmd)) in self.quick_macros.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(name).strong());
                                ui.label(RichText::new(cmd.trim()).monospace().color(Color32::from_rgb(100, 200, 255)));
                                if ui.small_button("🗑").clicked() {
                                    delete_idx = Some(idx);
                                }
                            });
                        }
                    });
                });

            if let Some(idx) = delete_idx
                && idx < self.quick_macros.len() {
                    self.quick_macros.remove(idx);
                    let _ = self.storage.save_quick_macros(&self.quick_macros);
                }
            self.show_macro_manager = open;
        }

        // Master Password Vault Modal
        if self.show_vault {
            let mut open = self.show_vault;
            let mut close_vault = false;
            let lang = self.language;
            let is_vault_configured = self.storage.is_vault_configured();
            let is_unlocked = self.storage.is_vault_unlocked();

            egui::Window::new(tr(lang, "🔒 Master Password & AES-256 Vault", "🔒 Mật khẩu chính & Két AES-256"))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .fixed_size(Vec2::new(480.0, 0.0))
                .pivot(egui::Align2::CENTER_CENTER)
                .default_pos(ctx.screen_rect().center())
                .show(ctx, |ui| {
                    ui.heading(RichText::new(tr(lang, "RustyBox Credentials Vault", "Két bảo mật RustyBox")).color(Color32::from_rgb(56, 189, 248)));
                    ui.label(
                        RichText::new(tr(
                            lang,
                            "Military-grade AES-256-GCM encryption with Argon2id key derivation.",
                            "Mã hóa AES-256-GCM kết hợp dẫn xuất khóa Argon2id an toàn tuyệt đối.",
                        ))
                        .size(12.0)
                        .color(Color32::from_rgb(180, 195, 215)),
                    );
                    ui.add_space(8.0);

                    let mut trigger_setup = false;
                    let mut trigger_unlock = false;

                    if !is_vault_configured {
                        // Case A: No Master Password set yet
                        ui.group(|ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(tr(lang, "Status: Unencrypted (Plaintext)", "Trạng thái: Chưa mã hóa (Văn bản rõ)")).color(Color32::from_rgb(248, 113, 113)).strong());
                            ui.add_space(2.0);
                            ui.label(tr(
                                lang,
                                "Set a master password to encrypt all session and credential passwords in data/RustyBox.json.",
                                "Đặt mật khẩu chính để mã hóa toàn bộ mật khẩu phiên và tài khoản trong data/RustyBox.json.",
                            ));
                            ui.add_space(10.0);

                            egui::Grid::new("vault_setup_grid")
                                .num_columns(2)
                                .spacing([12.0, 8.0])
                                .show(ui, |ui| {
                                    ui.label(tr(lang, "New Master Password:", "Mật khẩu chính mới:"));
                                    ui.add(
                                        TextEdit::singleline(&mut self.master_password)
                                            .password(true)
                                            .desired_width(250.0),
                                    );
                                    ui.end_row();

                                    ui.label(tr(lang, "Confirm Master Password:", "Nhập lại mật khẩu:"));
                                    let confirm_edit = ui.add(
                                        TextEdit::singleline(&mut self.master_password_confirm)
                                            .password(true)
                                            .desired_width(250.0),
                                    );
                                    if confirm_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                        trigger_setup = true;
                                    }
                                    ui.end_row();
                                });
                            ui.add_space(4.0);
                        });
                    } else if !is_unlocked {
                        // Case B: Vault is configured on disk, but currently LOCKED
                        ui.group(|ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(tr(lang, "Status: 🔒 LOCKED (AES-256-GCM Encrypted on disk)", "Trạng thái: 🔒 ĐANG KHÓA (Đã mã hóa AES-256-GCM)")).color(Color32::from_rgb(251, 191, 36)).strong());
                            ui.add_space(2.0);
                            ui.label(tr(
                                lang,
                                "Enter your master password to unlock credentials for session use and management.",
                                "Nhập mật khẩu chính để mở khóa thông tin đăng nhập cho các phiên kết nối.",
                            ));
                            ui.add_space(10.0);

                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Master Password:", "Mật khẩu chính:"));
                                ui.add_space(6.0);
                                let pass_edit = ui.add(
                                    TextEdit::singleline(&mut self.master_password)
                                        .password(true)
                                        .desired_width(ui.available_width()),
                                );
                                if pass_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                    trigger_unlock = true;
                                }
                            });
                            ui.add_space(4.0);
                        });
                    } else {
                        // Case C: Vault is configured and currently UNLOCKED
                        ui.group(|ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(tr(lang, "Status: 🔓 UNLOCKED (Active in memory, AES-256-GCM on disk)", "Trạng thái: 🔓 ĐÃ MỞ KHÓA (Đang hoạt động, mã hóa trên đĩa)")).color(Color32::from_rgb(34, 197, 94)).strong());
                            ui.add_space(2.0);
                            ui.label(tr(
                                lang,
                                "Credentials in data/RustyBox.json remain securely encrypted with AES-256-GCM.",
                                "Dữ liệu trong data/RustyBox.json luôn được mã hóa an toàn bằng AES-256-GCM.",
                            ));
                            ui.add_space(10.0);

                            ui.horizontal(|ui| {
                                if ui
                                    .add_sized([165.0, 28.0], egui::Button::new(RichText::new(tr(lang, "🔒 Lock Vault Now", "🔒 Khóa két ngay")).strong()))
                                    .clicked()
                                {
                                    self.storage.set_vault_key(None);
                                    self.sessions = self.storage.load_sessions();
                                    self.credentials = self.storage.load_credentials();
                                    self.vault_status = Some((tr(lang, "🔒 Vault locked. Passwords masked in memory.", "🔒 Đã khóa két. Mật khẩu đã được ẩn.").into(), false));
                                }
                                ui.add_space(8.0);
                                if ui
                                    .add_sized(
                                        [245.0, 28.0],
                                        egui::Button::new(
                                            RichText::new(tr(lang, "🔓 Remove Master Password", "🔓 Gỡ bỏ mật khẩu chính"))
                                                .color(Color32::from_rgb(248, 113, 113)),
                                        ),
                                    )
                                    .clicked()
                                {
                                    let mut new_cfg = self.storage.load_config();
                                    new_cfg.vault = None;
                                    self.storage.set_vault_key(None);
                                    self.storage.set_vault_configured(false);
                                    new_cfg.sessions = self.sessions.clone();
                                    new_cfg.credentials = self.credentials.clone();
                                    let _ = self.storage.save_config(&new_cfg);
                                    self.vault_status = Some((tr(lang, "ℹ Master password removed. Passwords stored in standard format.", "ℹ Đã gỡ mật khẩu chính.").into(), false));
                                }
                            });
                        });
                    }

                    if let Some((ref st, is_err)) = self.vault_status {
                        ui.add_space(8.0);
                        let color = if is_err { Color32::from_rgb(239, 68, 68) } else { Color32::from_rgb(34, 197, 94) };
                        ui.label(RichText::new(st).color(color).strong());
                    }

                    ui.add_space(12.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.add_sized([96.0, 30.0], egui::Button::new(tr(lang, "Close", "Đóng"))).clicked() {
                            close_vault = true;
                        }
                        ui.add_space(8.0);

                        if !is_vault_configured {
                            if ui.add_sized(
                                [230.0, 30.0],
                                egui::Button::new(RichText::new(tr(lang, "🔐 Enable & Encrypt Vault", "🔐 Bật mật khẩu & Mã hóa")).strong().color(Color32::WHITE))
                                    .fill(Color32::from_rgb(34, 197, 94)),
                            ).clicked()
                                || trigger_setup
                            {
                                if self.master_password.is_empty() {
                                    self.vault_status = Some((tr(lang, "❌ Master password cannot be empty!", "❌ Mật khẩu chính không được để trống!").into(), true));
                                } else if self.master_password != self.master_password_confirm {
                                    self.vault_status = Some((tr(lang, "❌ Passwords do not match! Please re-type.", "❌ Mật khẩu nhập lại không khớp!").into(), true));
                                } else {
                                    match create_vault(&self.master_password) {
                                        Ok((meta, key)) => {
                                            self.storage.set_vault_key(Some(key));
                                            self.storage.set_vault_configured(true);
                                            let mut new_cfg = self.storage.load_config();
                                            new_cfg.vault = Some(meta);
                                            new_cfg.sessions = self.sessions.clone();
                                            new_cfg.credentials = self.credentials.clone();
                                            match self.storage.save_config(&new_cfg) {
                                                Ok(_) => {
                                                    self.master_password.clear();
                                                    self.master_password_confirm.clear();
                                                    self.vault_status = Some((tr(lang, "✅ Master Password enabled! All credentials are now encrypted with AES-256-GCM.", "✅ Đã bật mật khẩu chính! Toàn bộ mật khẩu đã được mã hóa AES-256-GCM.").into(), false));
                                                }
                                                Err(e) => {
                                                    self.vault_status = Some((format!("❌ Failed to save encrypted configuration: {}", e), true));
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            self.vault_status = Some((format!("❌ Key derivation error: {}", e), true));
                                        }
                                    }
                                }
                            }
                        } else if !is_unlocked
                            && (ui.add_sized(
                                [140.0, 30.0],
                                egui::Button::new(RichText::new(tr(lang, "🔓 Unlock Vault", "🔓 Mở khóa két")).strong().color(Color32::WHITE))
                                    .fill(Color32::from_rgb(56, 189, 248)),
                            ).clicked()
                                || trigger_unlock)
                            && let Some(ref meta) = self.storage.load_config().vault
                        {
                            match unlock_vault(meta, &self.master_password) {
                                Ok(key) => {
                                    self.storage.set_vault_key(Some(key));
                                    for s in &mut self.sessions {
                                        if let Some(ref p) = s.password
                                            && is_encrypted(p)
                                            && let Ok(dec) = decrypt_str(&key, p)
                                        {
                                            s.password = Some(dec);
                                        }
                                    }
                                    for c in &mut self.credentials {
                                        if is_encrypted(&c.password)
                                            && let Ok(dec) = decrypt_str(&key, &c.password)
                                        {
                                            c.password = dec;
                                        }
                                    }
                                    self.master_password.clear();
                                    self.vault_status = Some((tr(lang, "✅ Vault successfully unlocked! Credentials decrypted in memory.", "✅ Đã mở khóa két thành công!").into(), false));
                                    close_vault = true;
                                }
                                Err(_) => {
                                    self.vault_status = Some((tr(lang, "❌ Incorrect master password!", "❌ Sai mật khẩu chính!").into(), true));
                                }
                            }
                        }
                    });
                });
            if close_vault {
                open = false;
            }
            self.show_vault = open;
        }

        // Manage Passwords Modal (MobaXterm TFormManagePasswords: "RustyBox passwords settings")
        if self.show_manage_passwords {
            let mut open = self.show_manage_passwords;
            let mut close_dialog = false;
            let screen_center = ctx.screen_rect().center();
            egui::Window::new(tr(lang, "RustyBox passwords settings", "Quản lý mật khẩu RustyBox"))
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_size(Vec2::new(740.0, 580.0))
                .min_size(Vec2::new(600.0, 420.0))
                .pivot(egui::Align2::CENTER_CENTER)
                .default_pos(screen_center)
                .show(ctx, |ui| {
                    // 1. Radio: Save sessions passwords
                    let is_vault_configured = self.storage.is_vault_configured();
                    let is_vault_unlocked = self.storage.is_vault_unlocked();

                    if is_vault_configured && !is_vault_unlocked {
                        egui::Frame::none()
                            .fill(Color32::from_rgb(38, 28, 12))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(245, 158, 11)))
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(tr(lang, "🔒 Credentials Vault is LOCKED. Passwords on disk are encrypted with AES-256-GCM.", "🔒 Két bảo mật ĐANG KHÓA. Mật khẩu trên đĩa đang được mã hóa AES-256-GCM.")).color(Color32::from_rgb(251, 191, 36)).strong());
                                    if ui.add(
                                        egui::Button::new(RichText::new(tr(lang, "🔓 Unlock Vault...", "🔓 Mở khóa két...")).strong().color(Color32::WHITE))
                                            .fill(Color32::from_rgb(217, 119, 6))
                                    ).clicked() {
                                        self.show_vault = true;
                                    }
                                });
                            });
                        ui.add_space(4.0);
                    }

                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr(lang, "Save sessions passwords:", "Lưu mật khẩu phiên:")).strong());
                        ui.radio_value(&mut self.manage_passwords_save_mode, 0, tr(lang, "Always", "Luôn lưu"));
                        ui.radio_value(&mut self.manage_passwords_save_mode, 1, tr(lang, "Never", "Không bao giờ"));
                        ui.radio_value(&mut self.manage_passwords_save_mode, 2, tr(lang, "Ask", "Luôn hỏi"));
                    });
                    ui.checkbox(&mut self.manage_passwords_save_ssh_keys, tr(lang, "Save SSH keys passphrases as well", "Lưu cả cụm mật khẩu khóa SSH"));
                    ui.add_space(6.0);

                    // 2. Tabs: Passwords / Credentials
                    ui.horizontal(|ui| {
                        if ui.selectable_label(self.manage_passwords_tab == 0, tr(lang, "🔑 Passwords", "🔑 Mật khẩu đã lưu")).clicked() {
                            self.manage_passwords_tab = 0;
                        }
                        if ui.selectable_label(self.manage_passwords_tab == 1, tr(lang, "👥 Credentials", "👥 Hồ sơ đăng nhập")).clicked() {
                            self.manage_passwords_tab = 1;
                        }
                    });
                    ui.separator();

                    if self.manage_passwords_tab == 0 {
                        // 3. Search Filter & Show Passwords Toggle
                        ui.horizontal(|ui| {
                            ui.label(tr(lang, "🔍 Filter:", "🔍 Lọc:"));
                            ui.add(
                                TextEdit::singleline(&mut self.manage_passwords_search)
                                    .hint_text(tr(lang, "Search username or IP / server...", "Tìm tên người dùng hoặc IP / máy chủ..."))
                                    .desired_width(220.0),
                            );
                            if !self.manage_passwords_search.is_empty() && ui.small_button("✖").clicked() {
                                self.manage_passwords_search.clear();
                            }

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.checkbox(&mut self.manage_passwords_show_all, tr(lang, "👁 Show passwords", "👁 Hiện mật khẩu"));
                            });
                        });
                        ui.add_space(4.0);

                        // 4. Passwords Table
                        let search_term = self.manage_passwords_search.to_lowercase().trim().to_string();
                        let mut to_delete_id: Option<String> = None;
                        let table_h = (ui.available_height() - 110.0).max(180.0);
                        let table_w = (ui.available_width() - 16.0).max(500.0);

                        egui::Frame::none()
                            .fill(Color32::from_rgb(13, 17, 23))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 61)))
                            .rounding(4.0)
                            .inner_margin(egui::Margin::same(8.0))
                            .show(ui, |ui| {
                                ScrollArea::vertical()
                                    .id_salt("manage_passwords_scroll")
                                    .max_height(table_h)
                                    .min_scrolled_height(table_h)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        ui.set_min_width(table_w);
                                        egui::Grid::new("manage_passwords_grid")
                                        .num_columns(5)
                                        .striped(true)
                                        .spacing([14.0, 6.0])
                                        .show(ui, |ui| {
                                            ui.label(RichText::new(tr(lang, "Protocol", "Giao thức")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.label(RichText::new(tr(lang, "Username", "Tài khoản")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.label(RichText::new(tr(lang, "Servername", "Máy chủ")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.label(RichText::new(tr(lang, "Password", "Mật khẩu")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.label(RichText::new(tr(lang, "Action", "Thao tác")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.end_row();

                                            let mut row_count = 0;
                                            for sess in &self.sessions {
                                                let (proto, user, host) = match &sess.session_type {
                                                    SessionType::Ssh { user, host, .. } => ("SSH", user.clone(), host.clone()),
                                                    SessionType::Rdp { user, host, .. } => ("RDP", user.clone(), host.clone()),
                                                    SessionType::Ftp { user, host, .. } => ("FTP", user.clone(), host.clone()),
                                                    SessionType::Vnc { host, .. } => ("VNC", "-".into(), host.clone()),
                                                    SessionType::Telnet { host, .. } => ("TELNET", "-".into(), host.clone()),
                                                    _ => continue,
                                                };

                                                if let Some(ref pw) = sess.password {
                                                    // Search filter matches either username or host/IP
                                                    if !search_term.is_empty()
                                                        && !user.to_lowercase().contains(&search_term)
                                                        && !host.to_lowercase().contains(&search_term)
                                                    {
                                                        continue;
                                                    }
                                                    row_count += 1;

                                                    ui.label(proto);
                                                    ui.label(if user.is_empty() { "-" } else { &user });
                                                    ui.label(&host);

                                                    // Password Show/Hide & Copy
                                                    let is_pw_enc = is_encrypted(pw);
                                                    let decrypted_pw = if is_pw_enc {
                                                        if is_vault_unlocked {
                                                            self.storage.vault_key().and_then(|k| decrypt_str(&k, pw).ok())
                                                        } else {
                                                            None
                                                        }
                                                    } else {
                                                        Some(pw.clone())
                                                    };

                                                    let is_unmasked = self.manage_passwords_show_all
                                                        || self.manage_passwords_unmasked_ids.contains(&sess.id);
                                                    let (pw_display, pw_col) = if is_pw_enc && !is_vault_unlocked {
                                                        ("[🔒 AES-256 Encrypted]".to_string(), Color32::from_rgb(251, 191, 36))
                                                    } else if is_unmasked {
                                                        (decrypted_pw.clone().unwrap_or_else(|| pw.clone()), Color32::from_rgb(226, 232, 240))
                                                    } else {
                                                        ("••••••••••••".to_string(), Color32::from_rgb(148, 163, 184))
                                                    };

                                                    ui.horizontal(|ui| {
                                                        ui.label(RichText::new(pw_display).family(egui::FontFamily::Monospace).color(pw_col));
                                                        if let Some(ref plain) = decrypted_pw {
                                                            let eye_icon = if is_unmasked { "🔒" } else { "👁" };
                                                            if ui.small_button(eye_icon).on_hover_text(tr(lang, "Toggle password visibility for this row", "Hiện / ẩn mật khẩu cho dòng này")).clicked() {
                                                                if let Some(pos) = self.manage_passwords_unmasked_ids.iter().position(|id| id == &sess.id) {
                                                                    self.manage_passwords_unmasked_ids.remove(pos);
                                                                } else {
                                                                    self.manage_passwords_unmasked_ids.push(sess.id.clone());
                                                                }
                                                            }
                                                            if ui.small_button("📋").on_hover_text(tr(lang, "Copy password to clipboard", "Sao chép mật khẩu vào clipboard")).clicked() {
                                                                copy_text_to_clipboard(ui, plain);
                                                                self.status_toast = Some((tr(lang, "Password copied to clipboard", "Đã sao chép mật khẩu vào clipboard").into(), std::time::Instant::now()));
                                                            }
                                                        } else {
                                                            if ui.small_button("🔓").on_hover_text(tr(lang, "Unlock Vault to view and copy decrypted password", "Mở khóa Két để xem và sao chép mật khẩu")).clicked() {
                                                                self.show_vault = true;
                                                            }
                                                        }
                                                    });

                                                    ui.horizontal(|ui| {
                                                        ui.add_space(28.0);
                                                        if ui.add(egui::Button::new(RichText::new("🗑").color(Color32::from_rgb(248, 113, 113))).small())
                                                            .on_hover_text(tr(lang, "Delete saved password", "Xóa mật khẩu đã lưu"))
                                                            .clicked()
                                                        {
                                                            to_delete_id = Some(sess.id.clone());
                                                        }
                                                    });
                                                    ui.end_row();
                                                }
                                            }

                                            if row_count == 0 {
                                                ui.label(RichText::new(tr(lang, "No saved passwords matching filter.", "Không tìm thấy mật khẩu nào khớp bộ lọc.")).weak());
                                                ui.end_row();
                                            }
                                        });
                                });
                            });

                        if let Some(del_id) = to_delete_id {
                            for s in &mut self.sessions {
                                if s.id == del_id {
                                    s.password = None;
                                }
                            }
                            let _ = self.storage.save_sessions(&self.sessions);
                        }

                        ui.add_space(4.0);
                        // Action buttons
                        ui.horizontal(|ui| {
                            if ui.button(tr(lang, "⚡ Delete all", "⚡ Xóa tất cả")).clicked() {
                                for s in &mut self.sessions {
                                    s.password = None;
                                }
                                let _ = self.storage.save_sessions(&self.sessions);
                            }
                            if ui.button(tr(lang, "📁 Export to file", "📁 Xuất ra tệp")).clicked() {
                                // Export action
                            }
                        });
                    } else {
                        // Credentials Tab (MobaXterm User Credentials Profiles)
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(tr(lang, "Shared Credentials & User Profiles", "Hồ sơ tài khoản & mật khẩu dùng chung")).strong());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.button(RichText::new(tr(lang, "➕ New credential / user", "➕ Thêm tài khoản mới")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                                    self.new_cred_name.clear();
                                    self.new_cred_user.clear();
                                    self.new_cred_password.clear();
                                    self.show_new_cred_modal = true;
                                }
                            });
                        });
                        ui.add_space(4.0);

                        let mut to_delete_cred_idx: Option<usize> = None;
                        let table_h = (ui.available_height() - 80.0).max(180.0);
                        let table_w = (ui.available_width() - 16.0).max(500.0);
                        egui::Frame::none()
                            .fill(Color32::from_rgb(13, 17, 23))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 61)))
                            .rounding(4.0)
                            .inner_margin(egui::Margin::same(8.0))
                            .show(ui, |ui| {
                                ScrollArea::vertical()
                                    .id_salt("manage_credentials_scroll")
                                    .max_height(table_h)
                                    .min_scrolled_height(table_h)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        ui.set_min_width(table_w);
                                        egui::Grid::new("manage_credentials_grid")
                                        .num_columns(5)
                                        .striped(true)
                                        .spacing([14.0, 6.0])
                                        .show(ui, |ui| {
                                            ui.label(RichText::new(tr(lang, "Profile Name", "Tên hồ sơ")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.label(RichText::new(tr(lang, "Username", "Tài khoản")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.label(RichText::new(tr(lang, "Password", "Mật khẩu")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.label(RichText::new(tr(lang, "Action", "Thao tác")).strong().color(Color32::from_rgb(56, 189, 248)));
                                            ui.end_row();

                                            for (c_idx, cred) in self.credentials.iter().enumerate() {
                                                ui.label(&cred.name);
                                                ui.label(&cred.username);
                                                let is_cred_enc = is_encrypted(&cred.password);
                                                let decrypted_cred_pw = if is_cred_enc {
                                                    if is_vault_unlocked {
                                                        self.storage.vault_key().and_then(|k| decrypt_str(&k, &cred.password).ok())
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    Some(cred.password.clone())
                                                };

                                                let cred_unmasked = self.manage_passwords_show_all
                                                    || self.manage_passwords_unmasked_ids.contains(&format!("cred_{}", c_idx));
                                                let (c_display, c_col) = if is_cred_enc && !is_vault_unlocked {
                                                    ("[🔒 AES-256 Encrypted]".to_string(), Color32::from_rgb(251, 191, 36))
                                                } else if cred_unmasked {
                                                    (decrypted_cred_pw.clone().unwrap_or_else(|| cred.password.clone()), Color32::from_rgb(226, 232, 240))
                                                } else {
                                                    ("••••••••••••".to_string(), Color32::from_rgb(148, 163, 184))
                                                };
                                                ui.horizontal(|ui| {
                                                    ui.label(RichText::new(c_display).family(egui::FontFamily::Monospace).color(c_col));
                                                    if let Some(ref plain) = decrypted_cred_pw {
                                                        let eye = if cred_unmasked { "🔒" } else { "👁" };
                                                        if ui.small_button(eye).on_hover_text(tr(lang, "Toggle password visibility", "Hiện / ẩn mật khẩu")).clicked() {
                                                            let key = format!("cred_{}", c_idx);
                                                            if let Some(pos) = self.manage_passwords_unmasked_ids.iter().position(|id| id == &key) {
                                                                self.manage_passwords_unmasked_ids.remove(pos);
                                                            } else {
                                                                self.manage_passwords_unmasked_ids.push(key);
                                                            }
                                                        }
                                                        if ui.small_button("📋").on_hover_text(tr(lang, "Copy password to clipboard", "Sao chép mật khẩu vào clipboard")).clicked() {
                                                            copy_text_to_clipboard(ui, plain);
                                                            self.status_toast = Some((tr(lang, "Credential password copied to clipboard", "Đã sao chép mật khẩu tài khoản vào clipboard").into(), std::time::Instant::now()));
                                                        }
                                                    } else {
                                                        if ui.small_button("🔓").on_hover_text(tr(lang, "Unlock Vault to view and copy decrypted password", "Mở khóa Két để xem và sao chép mật khẩu")).clicked() {
                                                            self.show_vault = true;
                                                        }
                                                    }
                                                });
                                                ui.horizontal(|ui| {
                                                    ui.add_space(28.0);
                                                    if ui.add(egui::Button::new(RichText::new("🗑").color(Color32::from_rgb(248, 113, 113))).small())
                                                        .on_hover_text(tr(lang, "Delete credential", "Xóa hồ sơ đăng nhập"))
                                                        .clicked()
                                                    {
                                                        to_delete_cred_idx = Some(c_idx);
                                                    }
                                                });
                                                ui.end_row();
                                            }

                                            if self.credentials.is_empty() {
                                                ui.label(RichText::new(tr(lang, "No shared credentials configured. Click '+ New credential / user' above to add one.", "Chưa có hồ sơ đăng nhập nào. Nhấn '+ Thêm tài khoản mới' ở trên để tạo.")).weak());
                                                ui.end_row();
                                            }
                                        });
                                });
                            });

                        if let Some(del_idx) = to_delete_cred_idx
                            && del_idx < self.credentials.len() {
                                self.credentials.remove(del_idx);
                                let _ = self.storage.save_credentials(&self.credentials);
                            }
                    }

                    ui.separator();
                    // 5. Storage Location & Master Password
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Where passwords are saved:", "Nơi lưu mật khẩu:"));
                        ui.label(RichText::new(tr(lang, "Configuration file (data/RustyBox.json)", "Tệp cấu hình (data/RustyBox.json)")).strong().color(Color32::from_rgb(100, 220, 100)));
                        let (vault_txt, vault_col) = if !is_vault_configured {
                            (tr(lang, "🔒 Set Master Password...", "🔒 Đặt mật khẩu chính..."), Color32::from_rgb(56, 189, 248))
                        } else if is_vault_unlocked {
                            (tr(lang, "🔓 Master Password (Unlocked)", "🔓 Mật khẩu chính (Đã mở khóa)"), Color32::from_rgb(34, 197, 94))
                        } else {
                            (tr(lang, "🔒 Master Password (Locked)", "🔒 Mật khẩu chính (Đang khóa)"), Color32::from_rgb(251, 191, 36))
                        };
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button(RichText::new(vault_txt).color(vault_col).strong()).clicked() {
                                self.show_vault = true;
                            }
                        });
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button(tr(lang, "✖ Cancel", "✖ Hủy")).clicked() {
                                close_dialog = true;
                            }
                            if ui.button(tr(lang, "✔ OK", "✔ Đồng ý")).clicked() {
                                let _ = self.storage.save_sessions(&self.sessions);
                                let _ = self.storage.save_credentials(&self.credentials);
                                let _ = self.storage.save_password_settings(
                                    self.manage_passwords_save_mode as u8,
                                    self.manage_passwords_save_ssh_keys,
                                );
                                close_dialog = true;
                            }
                        });
                    });
                });
            if close_dialog {
                open = false;
            }
            self.show_manage_passwords = open;
        }

        // Add New Credential / User Profile Modal
        if self.show_new_cred_modal {
            let mut open = self.show_new_cred_modal;
            egui::Window::new(tr(lang, "➕ New User Credential Profile", "➕ Tạo hồ sơ đăng nhập mới"))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_size(Vec2::new(480.0, 300.0))
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.group(|ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(tr(lang, "Enter user credentials details:", "Nhập thông tin tài khoản:")).strong().size(13.5));
                        ui.add_space(6.0);

                        egui::Grid::new("new_cred_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                            ui.label(RichText::new(tr(lang, "Profile name:", "Tên hồ sơ:")).size(12.5).color(Color32::from_rgb(226, 232, 240)));
                            ui.add(TextEdit::singleline(&mut self.new_cred_name).desired_width(260.0).margin(Margin::symmetric(8.0, 5.0)).hint_text(tr(lang, "e.g. Root VPS", "VD: Root VPS")));
                            ui.end_row();

                            // Filter out bracket characters [] {} () to prevent INI/JSON section parsing corruption
                            if self.new_cred_name.contains(['[', ']', '{', '}', '<', '>']) {
                                self.new_cred_name.retain(|c| !matches!(c, '[' | ']' | '{' | '}' | '<' | '>'));
                            }

                            ui.label(RichText::new(tr(lang, "Username:", "Tên đăng nhập:")).size(12.5).color(Color32::from_rgb(226, 232, 240)));
                            ui.add(TextEdit::singleline(&mut self.new_cred_user).desired_width(260.0).margin(Margin::symmetric(8.0, 5.0)).hint_text(tr(lang, "e.g. root / admin", "VD: root / admin")));
                            ui.end_row();

                            ui.label(RichText::new(tr(lang, "Password:", "Mật khẩu:")).size(12.5).color(Color32::from_rgb(226, 232, 240)));
                            ui.add(TextEdit::singleline(&mut self.new_cred_password).password(true).desired_width(260.0).margin(Margin::symmetric(8.0, 5.0)).hint_text(tr(lang, "Password", "Mật khẩu")));
                            ui.end_row();
                        });
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if (ui.button(tr(lang, "✔ Save Credential", "✔ Lưu hồ sơ")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)))
                            && !self.new_cred_user.trim().is_empty() {
                                let name = if self.new_cred_name.trim().is_empty() {
                                    self.new_cred_user.trim().to_string()
                                } else {
                                    self.new_cred_name.trim().to_string()
                                };
                                self.credentials.push(Credential {
                                    name,
                                    username: self.new_cred_user.trim().to_string(),
                                    password: self.new_cred_password.clone(),
                                });
                                let _ = self.storage.save_credentials(&self.credentials);
                                self.show_new_cred_modal = false;
                            }
                        if ui.button(tr(lang, "✖ Cancel", "✖ Hủy")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            self.show_new_cred_modal = false;
                        }
                    });
                });
            self.show_new_cred_modal = open;
        }

        // Global Settings & Preferences Modal (MobaXterm TFORMPARAMS)
        if self.show_settings_dialog {
            let mut open = self.show_settings_dialog;
            let mut close_dialog = false;
            let lang = self.language;
            egui::Window::new(tr(lang, "⚙ RustyBox Configuration & Preferences", "⚙ Cấu hình & Tùy chọn RustyBox"))
                .open(&mut open)
                .default_size(Vec2::new(760.0, 540.0))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.settings_tab, 0, tr(lang, "📁 General", "📁 Chung"));
                        ui.selectable_value(&mut self.settings_tab, 1, "💻 Terminal");
                        ui.selectable_value(&mut self.settings_tab, 2, "🖥 X11");
                        ui.selectable_value(&mut self.settings_tab, 3, "🔑 SSH");
                        ui.selectable_value(&mut self.settings_tab, 4, "🖥 RDP");
                        ui.selectable_value(&mut self.settings_tab, 5, tr(lang, "🎨 Display", "🎨 Hiển thị"));
                        ui.selectable_value(&mut self.settings_tab, 6, tr(lang, "⚙ Misc", "⚙ Khác"));
                    });
                    ui.separator();

                    match self.settings_tab {
                        0 => {
                            // General Tab
                            ui.label(RichText::new(tr(lang, "Language / Ngôn ngữ", "Ngôn ngữ / Language")).strong());
                            ui.horizontal(|ui| {
                                let mut lang_changed = false;
                                lang_changed |= ui
                                    .selectable_value(&mut self.language, AppLanguage::English, "🇬🇧 English")
                                    .changed();
                                lang_changed |= ui
                                    .selectable_value(&mut self.language, AppLanguage::Vietnamese, "🇻🇳 Tiếng Việt")
                                    .changed();
                                if lang_changed {
                                    let cfg = self.build_full_export_config();
                                    let _ = self.storage.save_config(&cfg);
                                }
                            });
                            ui.add_space(6.0);
                            ui.separator();
                            ui.label(RichText::new(tr(lang, "General Directories & Storage Settings", "Thư mục lưu trữ & Cấu hình chung")).strong());
                            ui.add_space(4.0);
                            ui.label(tr(lang, "Persistent Home directory: ./data/home (Relative workspace)", "Thư mục Home cố định: ./data/home"));
                            ui.label(tr(lang, "Configuration file: data/RustyBox.json", "Tệp cấu hình: data/RustyBox.json"));
                            ui.label(tr(lang, "Automatic backup rule: data/RustyBox.json.<unixtime> (Keep 3 newest)", "Sao lưu tự động: data/RustyBox.json.<unixtime> (Giữ 3 bản mới nhất)"));
                            ui.add_space(6.0);
                            ui.separator();
                            ui.label(RichText::new(tr(lang, "Backup, Export, or Import RustyBox Sessions & Configuration", "Sao lưu, Xuất hoặc Nhập phiên & cấu hình RustyBox")).strong());
                            ui.horizontal(|ui| {
                                if ui.button(tr(lang, "📤 Export Config (RustyBox.json)...", "📤 Xuất cấu hình (RustyBox.json)...")).clicked()
                                    && let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).save_file() {
                                        let cfg = self.build_full_export_config();
                                        let _ = self.storage.export_to_file(&path, &cfg);
                                    }
                                if ui.button(tr(lang, "📥 Import Config (RustyBox.json)...", "📥 Nhập cấu hình (RustyBox.json)...")).clicked()
                                    && let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file()
                                        && let Ok(imported) = self.storage.import_from_file(&path) {
                                            self.apply_imported_config(ui.ctx(), imported);
                                        }
                            });
                        }
                        1 => {
                            // Terminal Tab
                            ui.label(RichText::new(tr(lang, "Default Terminal Settings", "Cài đặt Terminal mặc định")).strong());
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Terminal Font:", "Phông chữ Terminal:"));
                                let prev_font = self.terminal_font_family.clone();
                                egui::ComboBox::from_id_salt("global_settings_terminal_font")
                                    .selected_text(crate::terminal::fonts::terminal_font_display_name(&self.terminal_font_family))
                                    .width(220.0)
                                    .show_ui(ui, |ui| {
                                        for opt in crate::terminal::fonts::AVAILABLE_TERMINAL_FONTS {
                                            let is_selected = self.terminal_font_family == opt.id;
                                            if ui.selectable_label(is_selected, format!("{} — {}", opt.name, opt.description)).clicked() {
                                                self.terminal_font_family = opt.id.to_string();
                                            }
                                        }
                                    });
                                if self.terminal_font_family != prev_font {
                                    crate::terminal::fonts::setup_terminal_fonts(ui.ctx(), &self.terminal_font_family);
                                }
                            });
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Default Terminal Font Size:", "Cỡ chữ Terminal mặc định:"));
                                ui.add(egui::DragValue::new(&mut self.font_size).range(9.0..=28.0).speed(0.5));
                                ui.label("px");
                            });
                            ui.add_space(2.0);
                            ui.group(|ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(tr(lang, "Font Preview:", "Xem trước phông chữ:")).weak().size(11.0));
                                    ui.label(RichText::new(format!("({} @ {:.0}px)", crate::terminal::fonts::terminal_font_display_name(&self.terminal_font_family), self.font_size)).weak().size(11.0));
                                });
                                ui.add_space(2.0);
                                ui.label(
                                    RichText::new("The quick brown fox jumps over the lazy dog\n0123456789 |-> != == <= >= && ||\nTiếng Việt: Thử nghiệm font chữ hiển thị chuẩn Unicode tiếng Việt (á, ế, ơ, ư, ộ, ễ)")
                                        .family(egui::FontFamily::Monospace)
                                        .size(self.font_size.min(16.0))
                                        .color(Color32::from_rgb(56, 189, 248))
                                );
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Terminal Color Scheme:", "Bảng màu Terminal:"));
                                for t in crate::terminal::vt_screen::TerminalTheme::all() {
                                    if ui.selectable_value(&mut self.theme, *t, t.name()).clicked() {
                                        if let Some(tab) = self.open_tabs.get_mut(self.active_tab_idx)
                                            && let Some(ref mut s) = tab.session_def {
                                                s.terminal_color_scheme = t.name().to_string();
                                            }
                                        let _ = self.persist_preferences();
                                        ui.ctx().request_repaint();
                                    }
                                }
                            });
                            ui.add_space(6.0);
                            ui.checkbox(&mut self.paste_protection_enabled, tr(lang, "Display confirmation dialog when pasting multiple lines", "Hiển thị hộp thoại xác nhận khi dán nhiều dòng"));
                            if ui.checkbox(&mut self.copy_on_select, tr(lang, "Automatically copy selected text to clipboard (Copy on select)", "Tự động sao chép vùng chọn vào clipboard")).changed() {
                                let _ = self.persist_preferences();
                            }
                            ui.add_space(6.0);
                            if ui.checkbox(&mut self.auto_log_sessions, tr(lang, "Automatically log all terminal sessions to file", "Tự động ghi nhật ký tất cả phiên Terminal ra tệp")).changed() {
                                let _ = self.storage.save_logging_settings(self.auto_log_sessions, &self.default_log_directory);
                            }
                            if self.auto_log_sessions {
                                ui.horizontal(|ui| {
                                    let placeholder = self.storage.data_dir().join("logs").to_string_lossy().to_string();
                                    ui.label(tr(lang, "Log directory:", "Thư mục nhật ký:"));
                                    let log_dir_resp = ui.add(
                                        TextEdit::singleline(&mut self.default_log_directory)
                                            .hint_text(&placeholder)
                                            .desired_width(260.0)
                                    );
                                    if log_dir_resp.lost_focus() || log_dir_resp.changed() {
                                        let _ = self.storage.save_logging_settings(self.auto_log_sessions, &self.default_log_directory);
                                    }
                                    if ui.small_button(tr(lang, "📂 Open Logs", "📂 Mở nhật ký")).on_hover_text(tr(lang, "Open log folder in File Explorer", "Mở thư mục nhật ký trong trình quản lý tệp")).clicked() {
                                        let target = if !self.default_log_directory.trim().is_empty() {
                                            std::path::PathBuf::from(self.default_log_directory.trim())
                                        } else {
                                            self.storage.data_dir().join("logs")
                                        };
                                        let _ = std::fs::create_dir_all(&target);
                                        #[cfg(windows)]
                                        {
                                            use std::os::windows::process::CommandExt;
                                            let _ = std::process::Command::new("explorer.exe")
                                                .arg(&target)
                                                .creation_flags(0x08000000)
                                                .spawn();
                                        }
                                        #[cfg(not(windows))]
                                        {
                                            let _ = std::process::Command::new("xdg-open")
                                                .arg(&target)
                                                .spawn();
                                        }
                                    }
                                });
                                ui.label(RichText::new(tr(lang, "ℹ Logs are organized by day (YYYY-MM-DD) and retained for up to 5 days.", "ℹ Nhật ký được phân loại theo ngày (YYYY-MM-DD) và lưu tối đa 5 ngày.")).weak().size(11.0));
                            }
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                let mut hl_en = self.highlight_rules_enabled;
                                if ui.checkbox(&mut hl_en, tr(lang, "Enable Auto-Highlight Keywords in Terminal (ZOC Style)", "Bật tự động tô màu từ khóa trong Terminal (kiểu ZOC)")).changed() {
                                    self.highlight_rules_enabled = hl_en;
                                    let _ = self.storage.save_highlight_rules(&self.highlight_rules, self.highlight_rules_enabled);
                                }
                                if ui.button(tr(lang, "🎨 Configure Highlight Rules...", "🎨 Cấu hình quy tắc tô màu...")).clicked() {
                                    self.show_highlight_modal = true;
                                }
                            });
                        }
                        2 => {
                            // X11 Tab
                            ui.label(RichText::new(tr(lang, "Embedded X11 Server Configuration", "Cấu hình máy chủ X11 tích hợp")).strong());
                            ui.add_space(4.0);
                            ui.label(tr(lang, "• Automatically start X server at RustyBox startup", "• Tự động khởi chạy máy chủ X khi mở RustyBox"));
                            ui.label(tr(lang, "• Hardware-accelerated OpenGL rendering (WGL)", "• Tăng tốc phần cứng OpenGL (WGL)"));
                            ui.label(tr(lang, "• Multiwindow mode (transparent desktop integration)", "• Chế độ đa cửa sổ (tích hợp trực tiếp vào màn hình nền)"));
                        }
                        3 => {
                            // SSH Tab
                            ui.label(RichText::new(tr(lang, "Global SSH Engine & Agent Settings", "Cài đặt SSH & Agent toàn cục")).strong());
                            ui.add_space(4.0);
                            ui.label(tr(lang, "• Send SSH keepalive packets every 60 seconds (prevent connection drops)", "• Gửi gói giữ kết nối SSH mỗi 60 giây (tránh rớt mạng)"));
                            ui.label(tr(lang, "• Use external Pageant / Windows OpenSSH Agent", "• Dùng Pageant / Windows OpenSSH Agent bên ngoài"));
                            ui.label(tr(lang, "• Use internal RustyBox Agent SSH key agent at startup", "• Dùng RustyBox Agent nội bộ khi khởi động"));
                        }
                        4 => {
                            // RDP Tab
                            ui.label(RichText::new(tr(lang, "Global Remote Desktop (RDP) Settings", "Cài đặt Remote Desktop (RDP) toàn cục")).strong());
                            ui.add_space(4.0);
                            ui.label(tr(lang, "• Redirect local clipboard to remote Windows sessions", "• Đồng bộ clipboard cục bộ vào phiên Windows từ xa"));
                            ui.label(tr(lang, "• Auto-reconnect on transient network drop", "• Tự động kết nối lại khi mất mạng tạm thời"));
                        }
                        5 => {
                            // Display Tab
                            ui.label(RichText::new(tr(lang, "Interface & Display Preferences", "Tùy chọn giao diện & hiển thị")).strong());
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "UI Font & Interface Zoom:", "Tỉ lệ phóng to giao diện:"));
                                let mut pct = (self.ui_scale * 100.0).round() as i32;
                                if ui.add(egui::Slider::new(&mut pct, 70..=200).suffix("%").step_by(5.0)).changed() {
                                    self.ui_scale = pct as f32 / 100.0;
                                }
                                if ui.button(tr(lang, "↺ Reset 100%", "↺ Đặt lại 100%")).clicked() {
                                    self.ui_scale = 1.0;
                                }
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(tr(lang, "Preset UI Scales:", "Mức thu phóng nhanh:"));
                                for s in [0.8, 0.9, 1.0, 1.1, 1.25, 1.5] {
                                    let label = format!("{:.0}%", s * 100.0);
                                    if ui.selectable_label((self.ui_scale - s).abs() < 0.02, label).clicked() {
                                        self.ui_scale = s;
                                    }
                                }
                            });
                            ui.add_space(6.0);
                            ui.label(tr(lang, "• Display left sidebar at startup", "• Hiển thị thanh bên trái khi khởi động"));
                            ui.label(tr(lang, "• Use compact tab bar height", "• Dùng thanh tab gọn nhẹ"));
                            ui.label(tr(lang, "• Ask for confirmation when closing window with active sessions", "• Hỏi xác nhận khi đóng cửa sổ có phiên đang chạy"));
                        }
                        6 => {
                            // Misc Tab
                            ui.label(RichText::new(tr(lang, "Miscellaneous Settings", "Cài đặt khác")).strong());
                            ui.add_space(4.0);
                            ui.label(tr(lang, "Integrate RustyBox into Windows Explorer context menu:", "Tích hợp RustyBox vào menu chuột phải Windows Explorer:"));
                            ui.label(tr(lang, "• Add 'Open RustyBox terminal here' on folders", "• Thêm 'Mở Terminal RustyBox tại đây' cho thư mục"));
                            ui.label(tr(lang, "• Add 'Run script with RustyBox shell' on .sh files", "• Thêm 'Chạy script bằng RustyBox' cho tệp .sh"));
                            ui.label(tr(lang, "• Add 'Edit with RustyBox Quick Editor' on text/config files", "• Thêm 'Sửa bằng Trình soạn thảo RustyBox' cho tệp văn bản/cấu hình"));
                        }
                        _ => {}
                    }

                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new(tr(lang, "💾 Save Preferences", "💾 Lưu tùy chọn")).strong().color(Color32::from_rgb(56, 189, 248))).clicked() {
                            let _ = self.storage.save_sessions(&self.sessions);
                            let _ = self.persist_preferences();
                            close_dialog = true;
                        }
                        if ui.button(tr(lang, "Close", "Đóng")).clicked() {
                            close_dialog = true;
                        }
                    });
                });
            if close_dialog {
                open = false;
            }
            self.show_settings_dialog = open;
        }

        // Keyboard Shortcuts (Hotkeys Cheatsheet) Modal (MobaXterm TFORMHOTKEYS)
        if self.show_hotkeys_dialog {
            let mut open = self.show_hotkeys_dialog;
            let mut close_dialog = false;
            egui::Window::new(tr(lang, "⌨ Keyboard Shortcuts (Hotkeys Reference)", "⌨ Phím tắt hệ thống (Tra cứu nhanh)"))
                .open(&mut open)
                .default_size(Vec2::new(480.0, 380.0))
                .show(ctx, |ui| {
                    ui.label(RichText::new(tr(lang, "Default Keyboard Shortcuts:", "Phím tắt mặc định:")).strong());
                    ui.separator();

                    ScrollArea::vertical().show(ui, |ui| {
                        let shortcuts = [
                            ("Ctrl + T", tr(lang, "Open new Local Terminal tab", "Mở tab Terminal cục bộ mới")),
                            ("Ctrl + Shift + W", tr(lang, "Close active tab (or Ctrl+W if exited)", "Đóng tab đang mở (hoặc Ctrl+W nếu đã thoát)")),
                            ("Ctrl + PageUp/Down", tr(lang, "Switch between terminal tabs", "Chuyển đổi qua lại giữa các tab Terminal")),
                            ("Ctrl + Shift + C/V", tr(lang, "Copy / Paste terminal text", "Sao chép / Dán văn bản Terminal")),
                            ("Ctrl + F", tr(lang, "Find in active terminal screen buffer", "Tìm kiếm trong bộ đệm Terminal hiện tại")),
                            ("Ctrl + L", tr(lang, "Clear terminal screen buffer", "Xóa trắng màn hình Terminal")),
                            ("Ctrl + C", tr(lang, "Send SIGINT interrupt signal to process", "Gửi tín hiệu ngắt SIGINT tới tiến trình")),
                            ("Ctrl + D", tr(lang, "Send EOF (End of File) / logout", "Gửi EOF (Kết thúc tệp) / đăng xuất")),
                            ("Ctrl + Z", tr(lang, "Send SIGTSTP suspend signal", "Gửi tín hiệu tạm dừng SIGTSTP")),
                            ("Ctrl + A", tr(lang, "Move cursor to beginning of line", "Di chuyển con trỏ về đầu dòng")),
                            ("Ctrl + E", tr(lang, "Move cursor to end of line", "Di chuyển con trỏ về cuối dòng")),
                            ("Ctrl + K", tr(lang, "Cut text from cursor to end of line", "Cắt văn bản từ con trỏ đến cuối dòng")),
                            ("Ctrl + U", tr(lang, "Cut whole line before cursor", "Cắt toàn bộ dòng trước con trỏ")),
                            ("Ctrl + + / -", tr(lang, "Zoom in / out terminal font size", "Phóng to / thu nhỏ cỡ chữ Terminal")),
                            ("Ctrl + Shift + +/-", tr(lang, "Scale entire application UI", "Phóng to / thu nhỏ toàn bộ giao diện")),
                            (tr(lang, "Right Click", "Chuột phải"), tr(lang, "Context Menu: Copy, Paste, Clear, Save output", "Menu ngữ cảnh: Sao chép, Dán, Xóa, Lưu đầu ra")),
                        ];

                        for (key, desc) in shortcuts {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{:15}", key)).monospace().color(Color32::from_rgb(100, 200, 255)).strong());
                                ui.label(desc);
                            });
                        }
                    });

                    ui.separator();
                    if ui.button(tr(lang, "Close", "Đóng")).clicked() {
                        close_dialog = true;
                    }
                });
            if close_dialog {
                open = false;
            }
            self.show_hotkeys_dialog = open;
        }

        // About Modal
        if self.show_about {
            let mut open = self.show_about;
            let lang = self.language;
            egui::Window::new(tr(lang, "ℹ About RustyBox", "ℹ Giới thiệu RustyBox"))
                .open(&mut open)
                .default_size(Vec2::new(480.0, 320.0))
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("🚀 RustyBox");
                        ui.label(RichText::new(tr(lang, "Complete Remote Toolbox & Terminal Suite in Pure Rust", "Bộ công cụ Terminal & Quản trị từ xa toàn diện viết bằng Rust")).strong());
                        ui.add_space(4.0);
                        ui.label(RichText::new(tr(lang, "Version v1.4.14", "Phiên bản v1.4.14")).color(Color32::from_rgb(147, 197, 253)).strong());
                        ui.add_space(8.0);
                        ui.label(tr(lang, "High-performance, zero-install, lightweight remote terminal toolbox.", "Gọn nhẹ, hiệu năng cao, không cần cài đặt."));
                        ui.label(tr(lang, "Runs natively on Windows, macOS, and Linux.", "Chạy trực tiếp trên Windows, macOS và Linux."));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Nickname:").strong());
                            ui.label("longanhvn");
                        });
                        ui.add_space(3.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("GitHub Repository:").strong());
                            ui.hyperlink_to(
                                RichText::new("https://github.com/longanhvn/rustybox")
                                    .color(Color32::from_rgb(56, 189, 248))
                                    .underline(),
                                "https://github.com/longanhvn/rustybox",
                            );
                        });
                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(4.0);
                        ui.label(RichText::new(tr(lang, "Integrated Features:", "Tính năng tích hợp:")).strong());
                        ui.label(tr(lang, "• Multi-tab & Multi-Split Terminal (ConPTY / Unix PTY / VT100)", "• Terminal đa tab & chia đôi màn hình (ConPTY / Unix PTY / VT100)"));
                        ui.label(tr(lang, "• Realtime Multi-Execution (Command Broadcasting)", "• Thực thi đồng thời nhiều phiên (Gửi lệnh hàng loạt)"));
                        ui.label(tr(lang, "• Multi-line Paste Safety Confirmation (Anti-accidental execution)", "• Cảnh báo an toàn khi dán nhiều dòng (Chống chạy nhầm lệnh)"));
                        ui.label(tr(lang, "• Terminal Themes (RustyBox Dark, Dracula, Solarized, Monokai, Nord, Matrix)", "• Đa dạng giao diện màu Terminal (Dracula, Solarized, Monokai, Nord, Matrix)"));
                        ui.label(tr(lang, "• Interactive Quick Macros / Sysadmin Toolbar & Manager", "• Thanh công cụ & Trình quản lý Macro thao tác nhanh"));
                        ui.label(tr(lang, "• Embedded Services Hub (Micro HTTP Daemon, Syslog UDP Server)", "• Dịch vụ mạng tích hợp (HTTP Daemon, Syslog UDP, TFTP)"));
                        ui.label(tr(lang, "• Graphical SFTP Explorer with Advanced Built-in Code Editor", "• Trình duyệt SFTP trực quan kèm trình soạn thảo mã tích hợp"));
                        ui.label(tr(lang, "• High-Speed SFTP Transfer (512KB Buffers & 2MB Sockets)", "• Truyền tải SFTP tốc độ cao (Bộ đệm 512KB & Socket 2MB)"));
                        ui.label(tr(lang, "• SSH Port Forwarding / Tunneling Manager", "• Trình quản lý chuyển tiếp cổng / Đường hầm SSH"));
                        ui.label(tr(lang, "• Network Tools (NetScan Subnet Scanner, Port Scanner, Ping, Netstat)", "• Công cụ mạng (Quét mạng nội bộ, Quét cổng, Ping, Netstat)"));
                        ui.label(tr(lang, "• AES-256-GCM Master Password Encrypted Vault", "• Két bảo mật mã hóa mật khẩu chính chuẩn AES-256-GCM"));
                        ui.label(tr(lang, "• 5-Day Daily Auto-Rotating Terminal Session Logs", "• Tự động ghi và xoay vòng nhật ký phiên Terminal theo ngày (5 ngày)"));
                    });
                });
            self.show_about = open;
        }

        // Modal: Connect as...
        if let Some((target_session, mut cur_user)) = self.connect_as_target.clone() {
            let mut close_modal = false;
            let mut do_launch = false;
            egui::Window::new(tr(lang, "👤 Connect as...", "👤 Kết nối bằng tài khoản khác..."))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .default_width(320.0)
                .show(ctx, |ui| {
                    ui.label(RichText::new(match lang {
                        AppLanguage::English => format!("Session: {}", target_session.name),
                        AppLanguage::Vietnamese => format!("Phiên: {}", target_session.name),
                    }).strong());
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "Username:", "Tên người dùng:"));
                        ui.text_edit_singleline(&mut cur_user);
                    });
                    ui.add_space(8.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new(tr(lang, "▶ Connect", "▶ Kết nối")).strong()).clicked() {
                            do_launch = true;
                            close_modal = true;
                        }
                        if ui.button(tr(lang, "Cancel", "Hủy")).clicked() {
                            close_modal = true;
                        }
                    });
                });
            if do_launch {
                let mut s = target_session;
                if let SessionType::Ssh { ref mut user, .. } = s.session_type {
                    *user = cur_user.trim().to_string();
                }
                self.launch_generic_session(s);
            }
            if close_modal {
                self.connect_as_target = None;
            } else if let Some((_, ref mut u)) = self.connect_as_target {
                *u = cur_user;
            }
        }

        // Modal: Rename session
        if let Some((target_id, mut new_name)) = self.rename_session_target.clone() {
            let mut close_modal = false;
            let mut do_rename = false;
            egui::Window::new(tr(lang, "✏️ Rename session", "✏️ Đổi tên phiên"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .default_width(320.0)
                .show(ctx, |ui| {
                    ui.label(tr(lang, "New session name:", "Tên phiên mới:"));
                    ui.text_edit_singleline(&mut new_name);
                    ui.add_space(8.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new(tr(lang, "✓ Rename", "✓ Đổi tên")).strong()).clicked() {
                            do_rename = true;
                            close_modal = true;
                        }
                        if ui.button(tr(lang, "Cancel", "Hủy")).clicked() {
                            close_modal = true;
                        }
                    });
                });
            if do_rename {
                let clean_name = new_name.trim().to_string();
                if !clean_name.is_empty() {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.id == target_id) {
                        s.name = clean_name;
                    }
                    let _ = self.storage.save_sessions(&self.sessions);
                }
            }
            if close_modal {
                self.rename_session_target = None;
            } else if let Some((_, ref mut n)) = self.rename_session_target {
                *n = new_name;
            }
        }

        // Modal: Rename folder
        if let Some((old_folder, mut new_folder)) = self.rename_folder_target.clone() {
            let mut close_modal = false;
            let mut do_rename = false;
            egui::Window::new(tr(lang, "📁 Rename folder", "📁 Đổi tên thư mục"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .default_width(320.0)
                .show(ctx, |ui| {
                    ui.label(tr(lang, "New folder name:", "Tên thư mục mới:"));
                    ui.text_edit_singleline(&mut new_folder);
                    ui.add_space(8.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new(tr(lang, "✓ Rename", "✓ Đổi tên")).strong()).clicked() {
                            do_rename = true;
                            close_modal = true;
                        }
                        if ui.button(tr(lang, "Cancel", "Hủy")).clicked() {
                            close_modal = true;
                        }
                    });
                });
            if do_rename {
                let clean_folder = new_folder.trim().to_string();
                if !clean_folder.is_empty() {
                    for s in &mut self.sessions {
                        if s.folder == old_folder {
                            s.folder = clean_folder.clone();
                        }
                    }
                    let _ = self.storage.save_sessions(&self.sessions);
                }
            }
            if close_modal {
                self.rename_folder_target = None;
            } else if let Some((_, ref mut f)) = self.rename_folder_target {
                *f = new_folder;
            }
        }

        // Modal: Rename Tab
        if let Some((tab_idx, mut new_tab_name)) = self.rename_tab_target.clone() {
            let mut close_modal = false;
            let mut do_rename = false;
            egui::Window::new(tr(lang, "✏ Rename Tab", "✏ Đổi tên Tab"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .default_width(320.0)
                .show(ctx, |ui| {
                    ui.label(tr(lang, "Enter new tab title:", "Nhập tiêu đề Tab mới:"));
                    ui.text_edit_singleline(&mut new_tab_name);
                    ui.add_space(8.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new(tr(lang, "✓ Rename", "✓ Đổi tên")).strong()).clicked() {
                            do_rename = true;
                            close_modal = true;
                        }
                        if ui.button(tr(lang, "Cancel", "Hủy")).clicked() {
                            close_modal = true;
                        }
                    });
                });
            if do_rename {
                let clean_name = new_tab_name.trim().to_string();
                if !clean_name.is_empty()
                    && let Some(tab) = self.open_tabs.get_mut(tab_idx) {
                        tab.title = clean_name;
                    }
            }
            if close_modal {
                self.rename_tab_target = None;
            } else if let Some((_, ref mut n)) = self.rename_tab_target {
                *n = new_tab_name;
            }
        }

        // Modal: Import Sessions (MobaXterm / .txt / .ini / .mxtpro / JSON)
        self.render_import_dialog(ctx);

        // Status Toast Notification
        if let Some((msg, created_at)) = &self.status_toast
            && created_at.elapsed().as_secs() < 3 {
                egui::Area::new(egui::Id::new("status_toast"))
                    .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-20.0, -40.0))
                    .show(ctx, |ui| {
                        egui::Frame::none()
                            .fill(Color32::from_rgb(31, 111, 235))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248)))
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new(msg).color(Color32::WHITE).strong());
                            });
                    });
            }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown_cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cwd_from_title() {
        // Unix bash style title
        assert_eq!(extract_cwd_from_title("root@51.79.157.8: /var/log"), Some("/var/log".to_string()));
        assert_eq!(extract_cwd_from_title("user@host: ~/projects/rustybox"), Some("~/projects/rustybox".to_string()));
        assert_eq!(extract_cwd_from_title("admin@remote: /etc/nginx - bash"), Some("/etc/nginx".to_string()));
        assert_eq!(extract_cwd_from_title("/home/deploy/app"), Some("/home/deploy/app".to_string()));

        // Windows title
        assert_eq!(extract_cwd_from_title("cmd.exe - C:\\Users\\Long\\Downloads"), Some("C:\\Users\\Long\\Downloads".to_string()));
        assert_eq!(extract_cwd_from_title("D:\\temp\\RustyBox"), Some("D:\\temp\\RustyBox".to_string()));
    }

    #[test]
    fn test_extract_cwd_from_screen() {
        // Linux / SSH prompt format A
        let screen_a = "total 12\ndrwxr-xr-x 2 root root 4096 Nov 5 10:00 .\nroot@ubuntu-srv:/var/www/html# ";
        assert_eq!(extract_cwd_from_screen(screen_a), Some("/var/www/html".to_string()));

        let screen_b = "deploy@vps:~/my-website$ ls\nindex.html package.json\ndeploy@vps:~/my-website$ ";
        assert_eq!(extract_cwd_from_screen(screen_b), Some("~/my-website".to_string()));

        // Linux prompt format B: [user@host /opt/docker]#
        let screen_c = "[root@centos /opt/docker]# ";
        assert_eq!(extract_cwd_from_screen(screen_c), Some("/opt/docker".to_string()));

        // Linux prompt format C: user@host (~/app) $
        let screen_d = "developer@srv (~/app) $ ";
        assert_eq!(extract_cwd_from_screen(screen_d), Some("~/app".to_string()));

        // Windows Command Prompt / PowerShell
        let win_cmd = "Microsoft Windows [Version 10.0.19045.5011]\n\nC:\\Users\\Long\\Projects> ";
        assert_eq!(extract_cwd_from_screen(win_cmd), Some("C:\\Users\\Long\\Projects".to_string()));

        let win_ps = "PS D:\\temp\\RustyBox> Get-ChildItem\n";
        assert_eq!(extract_cwd_from_screen(win_ps), Some("D:\\temp\\RustyBox".to_string()));
    }

    #[test]
    fn test_open_tab_remembers_sftp_path() {
        let test_shell = if cfg!(windows) { Some("cmd.exe") } else { Some("/bin/sh") };
        let mut tab = OpenTab {
            id: "test-tab-1".to_string(),
            title: "SSH: Web Server".to_string(),
            session: PtySession::spawn_local(24, 80, test_shell, None).unwrap(),
            session_def: None,
            custom_cmd: None,
            workdir: Some("/home/ubuntu".to_string()),
            telemetry: TabTelemetry::new_local(),
            last_synced_cwd: None,
            last_sftp_path: None,
        };

        assert_eq!(tab.last_sftp_path, None);
        tab.last_sftp_path = Some("/etc/nginx/sites-available".to_string());
        assert_eq!(tab.last_sftp_path.as_deref(), Some("/etc/nginx/sites-available"));
    }

    #[test]
    fn test_local_telemetry_initialization_and_real_data() {
        let telem = TabTelemetry::new_local();
        assert!(!telem.host.is_empty(), "Local host must not be empty");
        assert!(!telem.user.is_empty(), "Local user must not be empty");
        assert!(!telem.is_remote);
        assert!(telem.is_connected);

        #[cfg(unix)]
        {
            assert!(telem.cores.is_some(), "Cores should be detected on Unix");
            assert!(telem.disk_pct.is_some(), "Disk pct should be detected on Unix");
            if let Some(pct) = telem.disk_pct {
                assert!(pct <= 100, "Disk percentage should be <= 100%");
            }
        }

        // Before update, dynamic metrics must be None to avoid showing fake mockup data
        assert_eq!(telem.cpu_pct, None);
        assert_eq!(telem.ram_used_gb, None);
        assert_eq!(telem.ram_total_gb, None);
        assert_eq!(telem.net_rate, None);
    }

    #[test]
    fn test_remote_telemetry_does_not_use_mockups() {
        let session = Session::new_ssh("Production VPS", "Servers", "103.57.220.111", 22, "admin");

        let telem = TabTelemetry::new_remote(&session);
        assert_eq!(telem.host, "Production VPS");
        assert_eq!(telem.user, "admin");
        assert!(telem.is_remote);

        // When remote session has no active data yet, all metrics must be None (not fake hashed numbers)
        assert_eq!(telem.cores, None);
        assert_eq!(telem.cpu_pct, None);
        assert_eq!(telem.ram_used_gb, None);
        assert_eq!(telem.ram_total_gb, None);
        assert_eq!(telem.ram_pct, None);
        assert_eq!(telem.uptime, None);
        assert_eq!(telem.uptime_secs, None);
        assert_eq!(telem.disk_pct, None);
        assert_eq!(telem.net_rate, None);
    }

    #[test]
    fn test_read_local_disk_pct_and_net_bytes() {
        #[cfg(unix)]
        {
            let disk = crate::telemetry::read_local_disk_pct();
            assert!(disk.is_some(), "Should read root filesystem disk usage");
            let pct = disk.unwrap();
            assert!(pct > 0 && pct <= 100, "Disk usage {}% should be in 1..=100", pct);
        }
        #[cfg(target_os = "linux")]
        {
            let net = crate::telemetry::read_local_net_bytes();
            assert!(net.is_some(), "Should read /proc/net/dev on Linux");
            let (rx, tx) = net.unwrap();
            assert!(rx > 0 || tx > 0, "Network bytes should be non-zero");
        }
    }

    #[test]
    fn test_remote_tab_applies_metrics_cleanly() {
        let session_def = Session::new_ssh("My VPS", "Servers", "192.0.2.1", 22, "ubuntu");
        let test_shell = if cfg!(windows) { Some("cmd.exe") } else { Some("/bin/sh") };
        let pty = PtySession::spawn_local(24, 80, test_shell, None).unwrap();

        let mut tab = OpenTab {
            id: "ssh-tab-1".to_string(),
            title: "SSH: My VPS".to_string(),
            session: pty,
            session_def: Some(session_def.clone()),
            custom_cmd: None,
            workdir: None,
            telemetry: TabTelemetry::new_remote(&session_def),
            last_synced_cwd: None,
            last_sftp_path: None,
        };

        // Before probe: metrics are None (safe placeholders)
        assert_eq!(tab.telemetry.cores, None);
        assert_eq!(tab.telemetry.cpu_pct, None);
        assert_eq!(tab.telemetry.ram_pct, None);
        assert_eq!(tab.telemetry.disk_pct, None);
        assert_eq!(tab.telemetry.uptime, None);

        // Apply probe metrics
        let metrics = crate::telemetry::RemoteSystemMetrics {
            cores: Some(8),
            cpu_pct: Some(5),
            ram_total_gb: Some(24.0),
            ram_used_gb: Some(14.6),
            ram_pct: Some(61),
            disk_pct: Some(86),
            uptime: Some("Up: 19h 11m".into()),
            net_rate: Some("▲254.0K  ▼79.0K".into()),
            ..Default::default()
        };

        tab.telemetry.apply_metrics(&metrics);

        assert_eq!(tab.telemetry.cores, Some(8));
        assert_eq!(tab.telemetry.cpu_pct, Some(5));
        assert_eq!(tab.telemetry.ram_total_gb, Some(24.0));
        assert_eq!(tab.telemetry.ram_used_gb, Some(14.6));
        assert_eq!(tab.telemetry.ram_pct, Some(61));
        assert_eq!(tab.telemetry.disk_pct, Some(86));
        assert_eq!(tab.telemetry.uptime, Some("Up: 19h 11m".into()));
        assert_eq!(tab.telemetry.net_rate, Some("▲254.0K  ▼79.0K".into()));
    }

    #[test]
    fn test_cleanup_old_log_folders() {
        let base = std::env::temp_dir().join(format!("test_logs_clean_{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&base);
        // Create 7 day folders
        let days = vec![
            "2026-11-01",
            "2026-11-02",
            "2026-11-03",
            "2026-11-04",
            "2026-11-05",
            "2026-11-06",
            "2026-11-07",
        ];
        for d in &days {
            let p = base.join(d);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("sample.log"), "log text").unwrap();
        }

        // Keep max 5 days
        RustyBoxApp::cleanup_old_log_folders(&base, 5);

        // Check: 2026-11-01 and 2026-11-02 should be pruned
        assert!(!base.join("2026-11-01").exists());
        assert!(!base.join("2026-11-02").exists());

        // Newest 5 days should remain
        assert!(base.join("2026-11-03").exists());
        assert!(base.join("2026-11-04").exists());
        assert!(base.join("2026-11-05").exists());
        assert!(base.join("2026-11-06").exists());
        assert!(base.join("2026-11-07").exists());

        let _ = std::fs::remove_dir_all(&base);
    }
}
