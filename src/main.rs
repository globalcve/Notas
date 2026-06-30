mod core;
mod theme;
mod toolkit;

use gtk4 as gtk;
use gtk::{
    prelude::*,
    glib,
    Application, ApplicationWindow, Label, ListBoxRow,
};
use libadwaita as adw;
use adw::prelude::*;
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use core::manager::CoreManager;
use core::data::{AppSettings, AppTheme, EditorFont};

static CORE_MANAGER: OnceCell<Arc<Mutex<CoreManager>>> = OnceCell::new();
static TOKIO_RUNTIME: OnceCell<tokio::runtime::Runtime> = OnceCell::new();

const APP_ID: &str = "com.jegly.Notas";

thread_local! {
    static LAST_ACTIVITY: RefCell<Instant> = RefCell::new(Instant::now());
    static CLIPBOARD_TIMER: RefCell<Option<glib::SourceId>> = RefCell::new(None);
    // Debounce timer for autosave: restarted on each edit, fires once when typing
    // pauses. SAVED_FLASH clears the transient "Saved ✓" indicator after a moment.
    static AUTOSAVE_TIMER: RefCell<Option<glib::SourceId>> = RefCell::new(None);
    // The single auto-lock poll timer. Tracked (not fire-and-forget) so it can be
    // cancelled at every lock transition — otherwise each unlock leaks a timer that
    // keeps polling and, because the closed main window survives via closure
    // reference cycles, can fire a SECOND show_password_screen (two lock screens).
    static AUTO_LOCK_TIMER: RefCell<Option<glib::SourceId>> = RefCell::new(None);
    static SAVED_FLASH: RefCell<Option<glib::SourceId>> = RefCell::new(None);
    static CURRENT_THEME: RefCell<AppTheme> = RefCell::new(AppTheme::Dark);
    static CSS_PROVIDER: RefCell<Option<gtk::CssProvider>> = RefCell::new(None);
    static EDITOR_FONT: RefCell<EditorFont> = RefCell::new(EditorFont::default());
    static EDITOR_FONT_SIZE: RefCell<u32> = RefCell::new(12);
    static SHOW_NOTE_TITLE: RefCell<bool> = RefCell::new(true);
    static SHOW_NOTE_PREVIEWS: RefCell<bool> = RefCell::new(true);
    static SHOW_WORD_COUNT: RefCell<bool> = RefCell::new(true);
    // Rainbow ("lolcat") editor text — read by the content-change handler.
    static RAINBOW_TEXT: RefCell<bool> = RefCell::new(false);
    // Dedicated CSS provider that overrides the editor text colour (None = theme
    // default). Kept separate from the theme provider so a colour change doesn't
    // disturb the rest of the stylesheet.
    static EDITOR_COLOR_PROVIDER: RefCell<Option<gtk::CssProvider>> = RefCell::new(None);
}

/// The DotGothic16 font is bundled in the repo and compiled into the binary so
/// the app is self-contained: the `.lock-title`/`.app-title`/`.headerbar-title`
/// CSS asks for `'DotGothic16'`, which only resolves if the font is known to
/// fontconfig. The .deb installs it to /usr/share/fonts + runs fc-cache, but a
/// directly-run binary (e.g. `./target/debug/notas`) has no such step, so
/// "Notas" silently fell back to Noto Sans. We register it ourselves instead.
const DOTGOTHIC16_TTF: &[u8] = include_bytes!("../fonts/DotGothic16-Regular.ttf");

mod fontconfig_sys {
    use std::os::raw::{c_int, c_uchar};
    #[allow(non_camel_case_types)]
    pub enum FcConfig {}
    #[link(name = "fontconfig")]
    extern "C" {
        pub fn FcConfigGetCurrent() -> *mut FcConfig;
        pub fn FcConfigAppFontAddFile(config: *mut FcConfig, file: *const c_uchar) -> c_int;
    }
}

/// Make the bundled DotGothic16 font available to fontconfig (and therefore
/// Pango/GTK) at runtime, without requiring a system-wide install. Must run
/// before GTK/Pango build their font map (i.e. before `adw::init()` and any
/// widget creation), otherwise the new font won't appear in the cache.
fn register_bundled_font() {
    use std::os::unix::ffi::OsStrExt;

    let Some(cache_root) = dirs::cache_dir() else { return };
    let font_dir = cache_root.join("notas").join("fonts");
    let font_path = font_dir.join("DotGothic16-Regular.ttf");

    // Materialise the embedded font to a stable on-disk path so fontconfig can
    // load it by file name. Only rewrite when missing or a different size.
    let up_to_date = std::fs::metadata(&font_path)
        .map(|m| m.len() == DOTGOTHIC16_TTF.len() as u64)
        .unwrap_or(false);
    if !up_to_date {
        if std::fs::create_dir_all(&font_dir).is_err() {
            return;
        }
        if std::fs::write(&font_path, DOTGOTHIC16_TTF).is_err() {
            return;
        }
    }

    if let Ok(c_path) = std::ffi::CString::new(font_path.as_os_str().as_bytes()) {
        unsafe {
            let config = fontconfig_sys::FcConfigGetCurrent();
            if !config.is_null() {
                fontconfig_sys::FcConfigAppFontAddFile(config, c_path.as_ptr() as *const _);
            }
        }
    }
}

/// Stop other processes from scraping our memory (decrypted notes + cached key)
/// and stop a crash from leaking secrets to a core dump. Best-effort; the vault
/// is encrypted at rest regardless. Must run before any secret material exists.
fn harden_process() {
    unsafe {
        // No core dumps — they would contain decrypted notes / the key.
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);

        // Mark the process non-dumpable. This denies other same-user processes
        // both `ptrace` AND reads of `/proc/<pid>/mem` — the latter is the real
        // protection, since Yama `ptrace_scope` only restricts ATTACH, not READ,
        // so it does NOT stop a same-user app from passively scraping our memory.
        // Side effect: /proc/<pid> becomes root-owned, so xdg-desktop-portal logs
        // a harmless warning about reading appearance settings (Notas uses its own
        // themes, and its file dialogs are in-app, so nothing actually breaks).
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

fn main() -> glib::ExitCode {
    // Lock other same-user processes out of our memory before anything else runs.
    harden_process();

    // Register the bundled DotGothic16 font before anything touches Pango.
    register_bundled_font();

    let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    if TOKIO_RUNTIME.set(runtime).is_err() {
        eprintln!("Failed to set tokio runtime");
        return glib::ExitCode::FAILURE;
    }

    match CoreManager::new() {
        Ok(manager) => {
            let settings = manager.get_settings();
            CURRENT_THEME.with(|t| *t.borrow_mut() = settings.theme.clone());
            EDITOR_FONT.with(|f| *f.borrow_mut() = settings.editor_font.clone());
            EDITOR_FONT_SIZE.with(|s| *s.borrow_mut() = settings.editor_font_size);
            SHOW_NOTE_TITLE.with(|s| *s.borrow_mut() = settings.show_note_title);
            SHOW_NOTE_PREVIEWS.with(|s| *s.borrow_mut() = settings.show_note_previews);
            SHOW_WORD_COUNT.with(|s| *s.borrow_mut() = settings.show_word_count);
            RAINBOW_TEXT.with(|s| *s.borrow_mut() = settings.rainbow_text);
            if CORE_MANAGER.set(Arc::new(Mutex::new(manager))).is_err() {
                eprintln!("Failed to set CoreManager");
                return glib::ExitCode::FAILURE;
            }
        },
        Err(e) => {
            eprintln!("Failed to initialize CoreManager: {}", e);
            return glib::ExitCode::FAILURE;
        }
    }

    let application = Application::builder()
        .application_id(APP_ID)
        .build();

    application.connect_startup(|_| {
        adw::init().expect("Failed to initialize libadwaita");
        let theme = CURRENT_THEME.with(|t| t.borrow().clone());
        load_css(&theme);
    });

    application.connect_activate(build_ui);

    application.run()
}

fn get_editor_font_css() -> String {
    let font_family = EDITOR_FONT.with(|f| f.borrow().to_css_family().to_string());
    let font_size = EDITOR_FONT_SIZE.with(|s| *s.borrow());
    format!(
        ".content-view {{ font-family: {}; font-size: {}pt; }}
         .content-view text {{ font-family: {}; font-size: {}pt; }}",
        font_family, font_size, font_family, font_size
    )
}

/// Styling for popovers (right-click note menu, dropdowns, the editor's built-in
/// context menu). Without this, popovers fall back to a default that paints an
/// opaque square behind the rounded contents — the "square bleeding through the
/// corners" artifact. Appended to every theme so menus match the active palette.
/// Plain CSS (single braces) — concatenated AFTER the format! blocks, not inside.
pub(crate) const MENU_CSS: &str = r#"
        popover { background-color: transparent; padding: 0; }
        popover > contents, popover contents {
            background-color: @overlay_color;
            color: @text_color;
            border: 1px solid @border_color;
            border-radius: 10px;
            padding: 4px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.45);
        }
        popover > arrow { background: transparent; border: none; min-width: 0; min-height: 0; }
        .context-menu { min-width: 132px; }
        .menu-item { background-color: transparent; background-image: none; border: none; box-shadow: none; border-radius: 6px; padding: 7px 12px; color: @text_color; font-size: 0.9em; min-height: 0; }
        .menu-item:hover { background-color: alpha(@text_color, 0.12); }
        .menu-item-danger { color: #e0686b; }
        .menu-item-danger:hover { background-color: alpha(#e0686b, 0.18); }
        /* The top-bar note picker uses the bundled pixel font. */
        .note-switcher { font-family: 'DotGothic16', 'Noto Sans', monospace; }
        /* Compact top-bar action buttons: smaller + snug so a row of three stays tidy. */
        .hbtn { min-width: 22px; min-height: 22px; padding: 1px 5px; font-size: 0.9em; }
        /* The ⏻ power glyph sits higher in the font than ◑/⚙; nudge it down to align. */
        .glyph-nudge-down { padding-top: 3px; padding-bottom: 0px; }
        /* Password strength meter + generator preview. */
        .strength-bar, .strength-bar trough, .strength-bar progress { min-height: 4px; }
        .strength-label { font-size: 0.85em; }
        .gen-preview { font-family: monospace; font-size: 0.95em; }
        .find-bar { padding: 5px 8px; background-color: @overlay_color; border-bottom: 1px solid @border_color; }
"#;

fn get_dark_css() -> String {
    let editor_css = get_editor_font_css();
    format!(r#"
        /* Dark Theme - Smooth gradients, subtle styling */
        @define-color bg_color #080808;
        @define-color bg_mid #101014;
        @define-color bg_light #18181c;
        @define-color surface_color #0e0e12;
        @define-color overlay_color #1a1a1f;
        @define-color text_color #d8d8d8;
        @define-color subtext_color #707070;
        @define-color accent_gray #505050;
        @define-color accent_light #888888;
        @define-color border_color #252528;
        @define-color focus_color #404045;

        /* ========== AGGRESSIVE FOCUS REMOVAL ========== */
        *, *:focus, *:focus-within, *:focus-visible {{
            outline: none;
            outline-width: 0;
            outline-style: none;
            box-shadow: none;
            -gtk-outline-radius: 0;
        }}
        
        entry, entry:focus, entry:focus-within,
        textview, textview:focus, textview:focus-within,
        text, text:focus,
        password-entry, password-entry:focus {{
            outline: none;
            outline-width: 0;
            box-shadow: none;
            -gtk-outline-radius: 0;
        }}
        
        .password-entry, .password-entry:focus, .password-entry:focus-within,
        .title-entry, .title-entry:focus, .title-entry:focus-within,
        .search-entry, .search-entry:focus, .search-entry:focus-within {{
            outline: none;
            outline-width: 0;
            box-shadow: none;
            border-color: @focus_color;
        }}

        /* Smooth gradient background */
        window, .background {{ 
            background: linear-gradient(160deg, 
                #18181c 0%, 
                #101014 25%, 
                #0c0c0f 50%, 
                #080808 75%,
                #050506 100%
            );
            color: @text_color; 
        }}
        
        /* ========== CUSTOM HEADER BAR ========== */
        .custom-headerbar {{
            background: linear-gradient(180deg, #1a1a1e 0%, #101014 100%);
            border-bottom: 1px solid @border_color;
            padding: 4px 8px;
            min-height: 32px;
        }}
        
        .headerbar-title {{
            font-family: 'DotGothic16', 'Noto Sans', monospace;
            font-size: 0.95em;
            font-weight: 600;
            color: @text_color;
        }}
        
        /* Traffic light buttons - perfect circles */
        .traffic-btn {{
            min-width: 13px;
            min-height: 13px;
            padding: 0;
            margin: 0 4px;
            border-radius: 999px;
            border: none;
            font-size: 0;
            background: @accent_gray;
            -gtk-icon-size: 0;
        }}
        
        .traffic-btn:hover {{
            opacity: 0.8;
        }}
        
        .traffic-close {{
            background-color: #ff5f57;
            background-image: none;
        }}
        .traffic-close:hover {{
            background-color: #ff3b30;
            background-image: none;
        }}
        
        .traffic-minimize {{
            background-color: #ffbd2e;
            background-image: none;
        }}
        .traffic-minimize:hover {{
            background-color: #ff9500;
            background-image: none;
        }}
        
        .traffic-maximize {{
            background-color: #28c840;
            background-image: none;
        }}
        .traffic-maximize:hover {{
            background-color: #00b341;
            background-image: none;
        }}
        
        /* Title toggle switch */
        .title-toggle {{
            min-width: 36px;
            min-height: 18px;
            border-radius: 9px;
            background-color: @surface_color;
            border: 1px solid @border_color;
        }}
        .title-toggle:checked {{
            background-color: @accent_gray;
        }}
        .title-toggle slider {{
            min-width: 14px;
            min-height: 14px;
            border-radius: 7px;
            background-color: @subtext_color;
        }}
        .title-toggle:checked slider {{
            background-color: @text_color;
        }}
        
        /* Compact sidebar */
        .sidebar {{ 
            background: linear-gradient(180deg, 
                #141416 0%, 
                #101012 30%,
                #0c0c0e 60%,
                #08080a 100%
            );
            border-right: 1px solid @border_color; 
        }}
        
        .sidebar-header {{ 
            padding: 10px 10px; 
            border-bottom: 1px solid @border_color;
            background: transparent;
        }}
        
        .app-title {{ 
            font-family: 'DotGothic16', 'Noto Sans', monospace;
            font-size: 1.3em; 
            font-weight: bold;
            color: #e0e0e0;
        }}
        
        .lock-title {{ 
            font-family: 'DotGothic16', 'Noto Sans', monospace;
            font-size: 3.2em; 
            font-weight: bold;
            color: #f0f0f0;
            margin-bottom: 12px; 
        }}
        
        .lock-screen {{ 
            background: linear-gradient(160deg, 
                #1a1a1e 0%, 
                #121215 20%,
                #0a0a0c 45%,
                #060608 70%,
                #040405 100%
            );
        }}
        
        .search-entry {{ 
            background-color: @surface_color; 
            border: 1px solid @border_color; 
            border-radius: 5px; 
            padding: 6px 8px; 
            margin: 6px 8px; 
            color: @text_color; 
            outline: none;
        }}
        .search-entry:focus {{ 
            border-color: @focus_color; 
            outline: none;
            box-shadow: none;
        }}
        
        .note-list {{ background-color: transparent; }}
        .note-list row {{ 
            padding: 8px 10px; 
            margin: 1px 4px; 
            border-radius: 5px; 
            background-color: transparent; 
            border: 1px solid transparent;
        }}
        .note-list row:hover {{ 
            background-color: alpha(@overlay_color, 0.6);
            border-color: @border_color;
        }}
        .note-list row:selected {{ 
            background-color: @overlay_color;
            border-color: @accent_gray;
        }}
        
        .note-title {{ font-weight: 600; font-size: 0.9em; color: @text_color; }}
        .note-preview {{ font-size: 0.78em; color: @subtext_color; margin-top: 2px; }}
        .note-date {{ font-size: 0.7em; color: alpha(@subtext_color, 0.6); margin-top: 2px; }}
        .note-pinned {{ color: #a08050; }}
        
        .editor-area {{ 
            background: linear-gradient(160deg, 
                #18181c 0%, 
                #101014 25%, 
                #0c0c0f 50%, 
                #080808 75%,
                #050506 100%
            );
            padding: 16px; 
        }}
        
        .title-entry {{ 
            font-size: 1.3em; 
            font-weight: bold; 
            background-color: transparent; 
            border: none; 
            border-bottom: 1px solid @border_color; 
            border-radius: 0; 
            padding: 6px 4px; 
            margin-bottom: 12px; 
            color: @text_color;
            outline: none;
        }}
        .title-entry:focus {{ 
            border-bottom-color: @focus_color;
            outline: none;
            box-shadow: none;
        }}
        
        .content-view {{ 
            background-color: @surface_color; 
            border-radius: 6px; 
            padding: 12px; 
            color: @text_color;
            border: 1px solid @border_color;
            outline: none;
        }}
        .content-view text {{ background-color: transparent; color: @text_color; }}
        .content-view text selection {{ background-color: alpha(@accent_gray, 0.4); color: @text_color; }}
        .content-view:focus {{ 
            border-color: @focus_color;
            outline: none;
            box-shadow: none;
        }}
        
        {}
        
        .status-bar {{ 
            background: linear-gradient(180deg, @surface_color 0%, #060608 100%);
            padding: 6px 10px; 
            border-top: 1px solid @border_color; 
        }}
        .status-text {{ color: @subtext_color; font-size: 0.8em; }}
        
        .action-button {{ 
            background: linear-gradient(180deg, #1c1c20 0%, #101014 100%);
            color: @text_color; 
            border: 1px solid @accent_gray; 
            border-radius: 5px; 
            padding: 7px 14px; 
            font-weight: 600;
            font-size: 0.9em;
            outline: none;
        }}
        .action-button:hover {{ 
            background: linear-gradient(180deg, #222226 0%, #161618 100%);
            border-color: @accent_light;
        }}
        .action-button:focus {{
            outline: none;
            box-shadow: none;
        }}
        
        .secondary-button {{ 
            background: linear-gradient(180deg, #161618 0%, #0e0e10 100%);
            color: @subtext_color; 
            border: 1px solid @border_color; 
            border-radius: 5px; 
            padding: 6px 10px;
            font-weight: 500;
            font-size: 0.85em;
            outline: none;
        }}
        .secondary-button:hover {{ 
            color: @text_color;
            border-color: @accent_gray;
            background: linear-gradient(180deg, #1c1c1e 0%, #121214 100%);
        }}
        .secondary-button:focus {{
            outline: none;
            box-shadow: none;
        }}
        
        .status-button {{
            background: linear-gradient(180deg, #161618 0%, #0e0e10 100%);
            color: @subtext_color;
            border: 1px solid @border_color;
            border-radius: 4px;
            padding: 4px 10px;
            font-weight: 500;
            font-size: 0.8em;
            min-height: 0;
            min-width: 0;
            outline: none;
        }}
        .status-button:hover {{
            color: @text_color;
            border-color: @accent_gray;
            background: linear-gradient(180deg, #1c1c1e 0%, #121214 100%);
        }}
        .status-button:focus {{
            outline: none;
            box-shadow: none;
        }}
        
        .icon-button {{ 
            background-color: transparent; 
            border: none; 
            border-radius: 5px; 
            padding: 6px; 
            min-width: 28px; 
            min-height: 28px;
            color: @subtext_color;
            font-size: 0.95em;
            outline: none;
        }}
        .icon-button:hover {{ 
            background-color: @overlay_color;
            color: @text_color;
        }}
        .icon-button:focus {{
            outline: none;
            box-shadow: none;
        }}
        
        .lock-subtitle {{ 
            color: @subtext_color; 
            margin-bottom: 22px; 
            font-size: 0.95em; 
        }}
        
        .password-entry {{ 
            background-color: @surface_color; 
            border: 1px solid @border_color; 
            border-radius: 6px; 
            padding: 12px 16px; 
            font-size: 1.05em; 
            min-width: 280px; 
            color: @text_color;
            outline: none;
        }}
        .password-entry:focus {{ 
            border-color: @focus_color;
            outline: none;
            box-shadow: none;
        }}
        
        .unlock-button {{ 
            background: linear-gradient(180deg, #1c1c20 0%, #101014 100%);
            color: @text_color; 
            border: 1px solid @accent_gray; 
            border-radius: 6px; 
            padding: 12px 32px; 
            font-size: 1.05em; 
            font-weight: 600; 
            margin-top: 14px;
            outline: none;
        }}
        .unlock-button:hover {{ 
            background: linear-gradient(180deg, #222226 0%, #161618 100%);
            border-color: @accent_light;
        }}
        .unlock-button:focus {{
            outline: none;
            box-shadow: none;
        }}
        
        .error-label {{ color: #a06060; font-size: 0.88em; }}
        .success-label {{ color: #60a060; font-size: 0.88em; }}
        
        .preferences-group {{ 
            background: linear-gradient(180deg, @surface_color 0%, #08080a 100%);
            border-radius: 6px; 
            padding: 12px; 
            margin: 6px 0;
            border: 1px solid @border_color;
        }}
        .preferences-title {{ 
            font-weight: 600; 
            font-size: 0.7em; 
            color: @subtext_color; 
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        spinbutton {{ 
            background-color: @surface_color; 
            border: 1px solid @border_color; 
            border-radius: 4px; 
            color: @text_color;
            outline: none;
        }}
        spinbutton:focus {{
            border-color: @focus_color;
            outline: none;
            box-shadow: none;
        }}
        
        entry {{ 
            background-color: @surface_color; 
            border: 1px solid @border_color; 
            border-radius: 4px; 
            padding: 6px 8px; 
            color: @text_color;
            outline: none;
        }}
        entry:focus {{ 
            border-color: @focus_color;
            outline: none;
            box-shadow: none;
        }}
        
        checkbutton {{
            color: @text_color;
        }}
        checkbutton check {{
            background-color: @surface_color;
            border: 1px solid @border_color;
            border-radius: 3px;
        }}
        checkbutton:checked check {{
            background-color: @accent_gray;
            border-color: @accent_light;
        }}
        
        switch {{
            background-color: @surface_color;
            border: 1px solid @border_color;
        }}
        switch:checked {{
            background-color: @accent_gray;
        }}
        
        dropdown button {{
            background-color: @surface_color;
            border: 1px solid @border_color;
            color: @text_color;
            border-radius: 4px;
            padding: 4px 8px;
            outline: none;
        }}
        dropdown button:focus {{
            border-color: @focus_color;
            outline: none;
            box-shadow: none;
        }}
    "#, editor_css) + MENU_CSS
}

fn get_light_css() -> String {
    let editor_css = get_editor_font_css();
    format!(r#"
        /* Light Theme */
        @define-color bg_color #f2f2f2;
        @define-color surface_color #ffffff;
        @define-color overlay_color #e6e6e6;
        @define-color text_color #1a1a1a;
        @define-color subtext_color #555555;
        @define-color accent_gray #404040;
        @define-color accent_light #606060;
        @define-color border_color #cccccc;
        @define-color focus_color #888888;

        /* Aggressive focus removal */
        *, *:focus, *:focus-within, *:focus-visible {{
            outline: none;
            outline-width: 0;
            box-shadow: none;
        }}

        window, .background {{ background-color: @bg_color; color: @text_color; }}
        
        .custom-headerbar {{
            background: linear-gradient(180deg, #f8f8f8 0%, #e8e8e8 100%);
            border-bottom: 1px solid @border_color;
            padding: 4px 8px;
            min-height: 32px;
        }}
        
        .headerbar-title {{
            font-family: 'DotGothic16', 'Noto Sans', monospace;
            font-size: 0.95em;
            font-weight: 600;
            color: @text_color;
        }}
        
        .traffic-btn {{
            min-width: 13px;
            min-height: 13px;
            padding: 0;
            margin: 0 4px;
            border-radius: 999px;
            border: none;
            font-size: 0;
            -gtk-icon-size: 0;
        }}
        .traffic-btn:hover {{ opacity: 0.8; }}
        .traffic-close {{ background-color: #ff5f57; background-image: none; }}
        .traffic-close:hover {{ background-color: #ff3b30; background-image: none; }}
        .traffic-minimize {{ background-color: #ffbd2e; background-image: none; }}
        .traffic-minimize:hover {{ background-color: #ff9500; background-image: none; }}
        .traffic-maximize {{ background-color: #28c840; background-image: none; }}
        .traffic-maximize:hover {{ background-color: #00b341; background-image: none; }}
        
        .title-toggle {{
            min-width: 36px;
            min-height: 18px;
            border-radius: 9px;
            background-color: @overlay_color;
            border: 1px solid @border_color;
        }}
        .title-toggle:checked {{ background-color: @accent_gray; }}
        .title-toggle slider {{ min-width: 14px; min-height: 14px; border-radius: 7px; background-color: @subtext_color; }}
        .title-toggle:checked slider {{ background-color: @surface_color; }}
        
        .sidebar {{ background-color: @surface_color; border-right: 1px solid @border_color; }}
        .sidebar-header {{ padding: 10px 10px; border-bottom: 1px solid @border_color; background: transparent; }}
        
        .app-title {{ font-family: 'DotGothic16', 'Noto Sans', monospace; font-size: 1.3em; font-weight: bold; color: @text_color; }}
        .lock-title {{ font-family: 'DotGothic16', 'Noto Sans', monospace; font-size: 3.2em; font-weight: bold; color: @text_color; margin-bottom: 12px; }}
        .lock-screen {{ background-color: @bg_color; }}
        
        .search-entry {{ background-color: @bg_color; border: 1px solid @border_color; border-radius: 5px; padding: 6px 8px; margin: 6px 8px; color: @text_color; outline: none; }}
        .search-entry:focus {{ border-color: @focus_color; outline: none; box-shadow: none; }}
        
        .note-list {{ background-color: transparent; }}
        .note-list row {{ padding: 8px 10px; margin: 1px 4px; border-radius: 5px; background-color: transparent; border: 1px solid transparent; }}
        .note-list row:hover {{ background-color: @overlay_color; }}
        .note-list row:selected {{ background-color: @overlay_color; border-color: @accent_gray; }}
        
        .note-title {{ font-weight: 600; font-size: 0.9em; color: @text_color; }}
        .note-preview {{ font-size: 0.78em; color: @subtext_color; margin-top: 2px; }}
        .note-date {{ font-size: 0.7em; color: alpha(@subtext_color, 0.7); margin-top: 2px; }}
        
        .editor-area {{ background-color: @bg_color; padding: 16px; }}
        .title-entry {{ font-size: 1.3em; font-weight: bold; background-color: transparent; border: none; border-bottom: 1px solid @border_color; border-radius: 0; padding: 6px 4px; margin-bottom: 12px; color: @text_color; outline: none; }}
        .title-entry:focus {{ border-bottom-color: @focus_color; outline: none; box-shadow: none; }}
        
        .content-view {{ background-color: @surface_color; border-radius: 6px; padding: 12px; color: @text_color; border: 1px solid @border_color; outline: none; }}
        .content-view text {{ background-color: transparent; color: @text_color; }}
        .content-view:focus {{ border-color: @focus_color; outline: none; box-shadow: none; }}
        
        {}
        
        .status-bar {{ background-color: @surface_color; padding: 6px 10px; border-top: 1px solid @border_color; }}
        .status-text {{ color: @subtext_color; font-size: 0.8em; }}
        
        .action-button {{ background: @surface_color; color: @text_color; border: 1px solid @accent_gray; border-radius: 5px; padding: 7px 14px; font-weight: 600; font-size: 0.9em; outline: none; }}
        .action-button:hover {{ background: @overlay_color; }}
        .action-button:focus {{ outline: none; box-shadow: none; }}
        
        .secondary-button {{ background: @surface_color; color: @subtext_color; border: 1px solid @border_color; border-radius: 5px; padding: 6px 10px; font-size: 0.85em; outline: none; }}
        .secondary-button:hover {{ border-color: @accent_gray; color: @text_color; }}
        .secondary-button:focus {{ outline: none; box-shadow: none; }}
        
        .status-button {{ background: @surface_color; color: @subtext_color; border: 1px solid @border_color; border-radius: 4px; padding: 4px 10px; font-size: 0.8em; min-height: 0; min-width: 0; outline: none; }}
        .status-button:hover {{ border-color: @accent_gray; color: @text_color; }}
        .status-button:focus {{ outline: none; box-shadow: none; }}
        
        .icon-button {{ background-color: transparent; border: none; border-radius: 5px; padding: 6px; min-width: 28px; min-height: 28px; color: @subtext_color; font-size: 0.95em; outline: none; }}
        .icon-button:hover {{ background-color: @overlay_color; color: @text_color; }}
        .icon-button:focus {{ outline: none; box-shadow: none; }}
        
        .lock-subtitle {{ color: @subtext_color; margin-bottom: 22px; font-size: 0.95em; }}
        .password-entry {{ background-color: @surface_color; border: 1px solid @border_color; border-radius: 6px; padding: 12px 16px; font-size: 1.05em; min-width: 280px; color: @text_color; outline: none; }}
        .password-entry:focus {{ border-color: @focus_color; outline: none; box-shadow: none; }}
        
        .unlock-button {{ background: @surface_color; color: @text_color; border: 1px solid @accent_gray; border-radius: 6px; padding: 12px 32px; font-size: 1.05em; font-weight: 600; margin-top: 14px; outline: none; }}
        .unlock-button:hover {{ background: @overlay_color; }}
        .unlock-button:focus {{ outline: none; box-shadow: none; }}
        
        .error-label {{ color: #a04040; font-size: 0.88em; }}
        .success-label {{ color: #40a040; font-size: 0.88em; }}
        .preferences-group {{ background: @surface_color; border-radius: 6px; padding: 12px; margin: 6px 0; border: 1px solid @border_color; }}
        .preferences-title {{ font-weight: 600; font-size: 0.7em; color: @subtext_color; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px; }}
        
        spinbutton {{ background-color: @surface_color; border: 1px solid @border_color; border-radius: 4px; color: @text_color; outline: none; }}
        spinbutton:focus {{ border-color: @focus_color; outline: none; box-shadow: none; }}
        entry {{ background-color: @surface_color; border: 1px solid @border_color; border-radius: 4px; padding: 6px 8px; color: @text_color; outline: none; }}
        entry:focus {{ border-color: @focus_color; outline: none; box-shadow: none; }}
        
        checkbutton {{ color: @text_color; }}
        checkbutton check {{ background-color: @surface_color; border: 1px solid @border_color; border-radius: 3px; }}
        checkbutton:checked check {{ background-color: @accent_gray; }}
        
        switch {{ background-color: @overlay_color; border: 1px solid @border_color; }}
        switch:checked {{ background-color: @accent_gray; }}
    "#, editor_css) + MENU_CSS
}

fn load_css(theme: &AppTheme) {
    CSS_PROVIDER.with(|provider_cell| {
        let provider = provider_cell.borrow_mut().get_or_insert_with(gtk::CssProvider::new).clone();
        let css = match theme {
            AppTheme::Dark => get_dark_css(),
            AppTheme::Light => get_light_css(),
            AppTheme::Palette(id) => crate::theme::compile_css(
                &crate::theme::find_theme(id),
                &get_editor_font_css(),
            ),
        };
        provider.load_from_data(&css);
        gtk::style_context_add_provider_for_display(
            &gtk::gdk::Display::default().expect("Could not connect to a display."),
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    });
}

fn switch_theme(theme: &AppTheme) {
    CURRENT_THEME.with(|t| *t.borrow_mut() = theme.clone());
    reload_css();
}

fn reload_css() {
    let theme = CURRENT_THEME.with(|t| t.borrow().clone());
    let css = match theme {
        AppTheme::Dark => get_dark_css(),
        AppTheme::Light => get_light_css(),
        AppTheme::Palette(id) => crate::theme::compile_css(
            &crate::theme::find_theme(&id),
            &get_editor_font_css(),
        ),
    };
    CSS_PROVIDER.with(|provider_cell| {
        let display = match gtk::gdk::Display::default() {
            Some(d) => d,
            None => return,
        };
        // Replace the provider outright so the whole display re-cascades.
        // Reloading data into the existing provider does not reliably restyle
        // already-realized widgets, which made live theme switches appear inert.
        if let Some(old) = provider_cell.borrow_mut().take() {
            gtk::style_context_remove_provider_for_display(&display, &old);
        }
        let provider = gtk::CssProvider::new();
        provider.load_from_data(&css);
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        *provider_cell.borrow_mut() = Some(provider);
    });
}

/// Ordered list of selectable themes: the two built-in Notas themes followed by
/// the ported tesseract palettes. Index maps directly to the settings dropdown.
fn theme_choices() -> Vec<(String, AppTheme)> {
    let mut choices = vec![
        ("Notas Dark".to_string(), AppTheme::Dark),
        ("Notas Light".to_string(), AppTheme::Light),
    ];
    for p in crate::theme::builtin_themes() {
        choices.push((p.name.clone(), AppTheme::Palette(p.id.clone())));
    }
    choices
}

fn reset_activity_timer() {
    LAST_ACTIVITY.with(|last| {
        *last.borrow_mut() = Instant::now();
    });
}

/// Remove the active auto-lock poll timer, if any. Called at every lock
/// transition (manual or auto) so old timers can't outlive their window and
/// pop a duplicate lock screen.
fn cancel_auto_lock_timer() {
    AUTO_LOCK_TIMER.with(|cell| {
        if let Some(id) = cell.borrow_mut().take() {
            id.remove();
        }
    });
}

/// Briefly show "Saved ✓" in the status line, then fade it back to empty. A
/// single shared timer is reset on each call so rapid autosaves don't stack.
fn flash_saved(label: &Label) {
    label.set_text("Saved ✓");
    let label = label.clone();
    SAVED_FLASH.with(|cell| {
        if let Some(old) = cell.borrow_mut().take() {
            old.remove();
        }
        let id = glib::timeout_add_local_once(Duration::from_millis(1800), move || {
            SAVED_FLASH.with(|c| *c.borrow_mut() = None);
            if label.text() == "Saved ✓" {
                label.set_text("");
            }
        });
        *cell.borrow_mut() = Some(id);
    });
}

// ── Editor text colour ───────────────────────────────────────────────────────

/// Convert a gdk RGBA to a "#rrggbb" hex string (alpha dropped).
fn rgba_to_hex(rgba: &gtk::gdk::RGBA) -> String {
    let to_u8 = |c: f32| (c.clamp(0.0, 1.0) * 255.0).round() as u8;
    format!("#{:02x}{:02x}{:02x}", to_u8(rgba.red()), to_u8(rgba.green()), to_u8(rgba.blue()))
}

/// Apply (or clear) a custom editor text colour via a dedicated display-wide CSS
/// provider at USER priority, so it overrides the theme's `.content-view text`
/// colour without touching the rest of the stylesheet. `None` removes it.
fn apply_editor_text_color(color: Option<&str>) {
    let display = match gtk::gdk::Display::default() {
        Some(d) => d,
        None => return,
    };
    EDITOR_COLOR_PROVIDER.with(|cell| {
        // Swap the provider out each time (reloading data into an existing
        // provider doesn't reliably re-cascade onto realized widgets).
        if let Some(old) = cell.borrow_mut().take() {
            gtk::style_context_remove_provider_for_display(&display, &old);
        }
        if let Some(hex) = color {
            // Validate before injecting so a bad value can't break the editor CSS.
            if gtk::gdk::RGBA::parse(hex).is_ok() {
                let css = format!(".content-view, .content-view text {{ color: {hex}; }}");
                let provider = gtk::CssProvider::new();
                provider.load_from_data(&css);
                gtk::style_context_add_provider_for_display(
                    &display,
                    &provider,
                    gtk::STYLE_PROVIDER_PRIORITY_USER,
                );
                *cell.borrow_mut() = Some(provider);
            }
        }
    });
}

// ── Rainbow ("lolcat") editor text ───────────────────────────────────────────

/// Max note length we'll colour (per-character tagging is O(n) on every edit;
/// cap it so big notes don't lag while typing).
const RAINBOW_MAX_CHARS: i32 = 6000;

/// Catppuccin (Frappé) pastel accents, hue-ordered into a smooth cycle. Used for
/// the lolcat/rainbow mode instead of vivid primaries.
const CATPPUCCIN_PASTELS: [&str; 11] = [
    "#e78284", // red
    "#ef9f76", // peach
    "#e5c890", // yellow
    "#a6d189", // green
    "#81c8be", // teal
    "#99d1db", // sky
    "#85c1dc", // sapphire
    "#8caaee", // blue
    "#babbf1", // lavender
    "#ca9ee6", // mauve
    "#f4b8e4", // pink
];

/// The reusable set of pastel colour tags for this buffer (created once, then
/// looked up from the tag table on subsequent calls).
fn rainbow_tags(buffer: &gtk::TextBuffer) -> Vec<gtk::TextTag> {
    let table = buffer.tag_table();
    CATPPUCCIN_PASTELS
        .iter()
        .enumerate()
        .map(|(i, hex)| {
            let name = format!("rainbow-{i}");
            table.lookup(&name).unwrap_or_else(|| {
                let tag = gtk::TextTag::builder().name(&name).foreground(*hex).build();
                table.add(&tag);
                tag
            })
        })
        .collect()
}

/// Re-colour the buffer for rainbow mode. Clears any prior rainbow tags first
/// (the editor uses no other tags). A no-op clear when `enabled` is false, which
/// restores the normal/custom text colour.
fn apply_rainbow(buffer: &gtk::TextBuffer, enabled: bool) {
    let start = buffer.start_iter();
    let end = buffer.end_iter();
    buffer.remove_all_tags(&start, &end);
    if !enabled {
        return;
    }
    let n = buffer.char_count();
    if n == 0 || n > RAINBOW_MAX_CHARS {
        return;
    }
    let tags = rainbow_tags(buffer);
    for ci in 0..n {
        let s = buffer.iter_at_offset(ci);
        let e = buffer.iter_at_offset(ci + 1);
        buffer.apply_tag(&tags[ci as usize % tags.len()], &s, &e);
    }
}

fn build_ui(app: &Application) {
    reset_activity_timer();
    
    if !CoreManager::is_unlocked() {
        show_password_screen(app);
    } else {
        show_main_window(app);
    }
}

/// Pin a traffic-light button to a fixed square and center it, so the CSS
/// circle radius renders as a real circle (GTK4 ignores max-width/max-height,
/// and a Fill alignment would otherwise stretch it into a pill).
fn shape_traffic_button(btn: &gtk::Button) {
    btn.set_size_request(13, 13);
    btn.set_valign(gtk::Align::Center);
    btn.set_halign(gtk::Align::Center);
}

fn create_traffic_light_buttons(window: &ApplicationWindow) -> gtk::Box {
    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 2);
    btn_box.set_margin_end(8);

    // Close button (red)
    let close_btn = gtk::Button::new();
    close_btn.add_css_class("traffic-btn");
    close_btn.add_css_class("traffic-close");
    close_btn.set_tooltip_text(Some("Close"));
    
    // Minimize button (yellow)
    let minimize_btn = gtk::Button::new();
    minimize_btn.add_css_class("traffic-btn");
    minimize_btn.add_css_class("traffic-minimize");
    minimize_btn.set_tooltip_text(Some("Minimize"));
    
    // Maximize button (green)
    let maximize_btn = gtk::Button::new();
    maximize_btn.add_css_class("traffic-btn");
    maximize_btn.add_css_class("traffic-maximize");
    maximize_btn.set_tooltip_text(Some("Maximize"));

    shape_traffic_button(&close_btn);
    shape_traffic_button(&minimize_btn);
    shape_traffic_button(&maximize_btn);

    // Connect close
    let window_clone = window.clone();
    close_btn.connect_clicked(move |_| {
        window_clone.close();
    });
    
    // Connect minimize
    let window_clone = window.clone();
    minimize_btn.connect_clicked(move |_| {
        window_clone.minimize();
    });
    
    // Connect maximize/unmaximize toggle
    let window_clone = window.clone();
    maximize_btn.connect_clicked(move |_| {
        if window_clone.is_maximized() {
            window_clone.unmaximize();
        } else {
            window_clone.maximize();
        }
    });
    
    // Right-side window controls: minimize, maximize, then close at the edge.
    btn_box.append(&minimize_btn);
    btn_box.append(&maximize_btn);
    btn_box.append(&close_btn);

    btn_box
}

/// Derive a note's title from the first non-empty line of its body (trimmed,
/// length-capped). Falls back to "Untitled" for an empty note. With the
/// "first line = title" model this is the single source of truth for the title.
fn derive_title(content: &str) -> String {
    content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.chars().take(80).collect::<String>())
        .unwrap_or_else(|| "Untitled".to_string())
}

/// Char index of the inner character of the first `[ ]` / `[x]` / `[X]` checkbox
/// in a line, or None if the line has no checkbox.
fn checkbox_inner_index(line: &str) -> Option<usize> {
    let chars: Vec<char> = line.chars().collect();
    if chars.len() < 3 {
        return None;
    }
    for i in 0..=chars.len() - 3 {
        if chars[i] == '[' && chars[i + 2] == ']'
            && (chars[i + 1] == ' ' || chars[i + 1] == 'x' || chars[i + 1] == 'X')
        {
            return Some(i + 1);
        }
    }
    None
}

/// Sidebar preview = the first non-empty line AFTER the title line, condensed,
/// so the row doesn't just repeat the title.
fn derive_preview(content: &str) -> String {
    let mut lines = content.lines().map(str::trim).filter(|l| !l.is_empty());
    lines.next(); // skip the title line
    lines.next().unwrap_or("").chars().take(40).collect()
}

/// XML-escape text so it's safe to embed in Pango markup. Done BEFORE any markup
/// tags are inserted, so `Label::set_markup` can never choke on user input.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Parse inline Markdown spans into Pango markup. INPUT MUST ALREADY BE XML-
/// ESCAPED. Handles links `[t](url)`, inline code `` `c` ``, `**bold**`, and
/// `*italic*` / `_italic_`. Recurses for nesting; well-formed input only — any
/// unmatched delimiter is emitted literally, so output stays valid markup.
fn md_inline(s: &str) -> String {
    let ch: Vec<char> = s.chars().collect();
    let find = |from: usize, c: char| ch[from..].iter().position(|&x| x == c).map(|p| p + from);
    let find_dstar = |from: usize| {
        let mut i = from;
        while i + 1 < ch.len() {
            if ch[i] == '*' && ch[i + 1] == '*' {
                return Some(i);
            }
            i += 1;
        }
        None
    };
    let mut out = String::new();
    let mut i = 0;
    while i < ch.len() {
        let c = ch[i];
        // [text](url)
        if c == '[' {
            if let Some(rb) = find(i + 1, ']') {
                if rb + 1 < ch.len() && ch[rb + 1] == '(' {
                    if let Some(rp) = find(rb + 2, ')') {
                        let text: String = ch[i + 1..rb].iter().collect();
                        let url: String = ch[rb + 2..rp].iter().collect();
                        out.push_str(&format!(
                            "<a href=\"{}\">{}</a>",
                            url.replace('"', "&quot;"),
                            md_inline(&text)
                        ));
                        i = rp + 1;
                        continue;
                    }
                }
            }
        }
        // `code`
        if c == '`' {
            if let Some(cb) = find(i + 1, '`') {
                let code: String = ch[i + 1..cb].iter().collect();
                out.push_str(&format!("<tt>{}</tt>", code));
                i = cb + 1;
                continue;
            }
        }
        // **bold**
        if c == '*' && i + 1 < ch.len() && ch[i + 1] == '*' {
            if let Some(cb) = find_dstar(i + 2) {
                let inner: String = ch[i + 2..cb].iter().collect();
                out.push_str(&format!("<b>{}</b>", md_inline(&inner)));
                i = cb + 2;
                continue;
            }
        }
        // *italic* or _italic_
        if c == '*' || c == '_' {
            if let Some(cb) = find(i + 1, c) {
                if cb > i + 1 {
                    let inner: String = ch[i + 1..cb].iter().collect();
                    out.push_str(&format!("<i>{}</i>", md_inline(&inner)));
                    i = cb + 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Match a checklist line ("- [ ] text" / "- [x] text", also `*`/`+` bullets).
/// Returns (checked, remaining text). Must be tried BEFORE the plain-bullet case.
fn checklist_rest(line: &str) -> Option<(bool, &str)> {
    let after_bullet = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))?;
    let after_box = after_bullet.strip_prefix('[')?;
    let mark = after_box.chars().next()?;
    let rest = after_box[mark.len_utf8()..].strip_prefix(']')?;
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    let checked = mark == 'x' || mark == 'X';
    if mark == ' ' || checked {
        Some((checked, rest))
    } else {
        None
    }
}

/// Minimal in-process Markdown → Pango-markup renderer for the live preview pane.
/// Covers the common subset: headings (`#`..`######`), `**bold**`, `*italic*`,
/// inline `` `code` ``, links, bullet + checklist items, block quotes, fenced
/// code blocks, and horizontal rules. No external renderer dependency.
fn markdown_to_pango(src: &str) -> String {
    let mut out = String::new();
    let mut in_fence = false;
    let mut code = String::new();
    let push = |out: &mut String, s: &str| {
        out.push_str(s);
        out.push('\n');
    };
    for raw in src.lines() {
        let trimmed = raw.trim_start();
        // Fenced code block ``` … ```
        if trimmed.starts_with("```") {
            if in_fence {
                push(&mut out, &format!("<tt>{}</tt>", xml_escape(code.trim_end_matches('\n'))));
                code.clear();
                in_fence = false;
            } else {
                in_fence = true;
            }
            continue;
        }
        if in_fence {
            code.push_str(raw);
            code.push('\n');
            continue;
        }
        // Horizontal rule
        if trimmed == "---" || trimmed == "***" || trimmed == "___" {
            push(&mut out, "<span foreground=\"#888888\">────────────────────</span>");
            continue;
        }
        // Heading
        let hashes = trimmed.chars().take_while(|&c| c == '#').count();
        if (1..=6).contains(&hashes) && trimmed.chars().nth(hashes) == Some(' ') {
            let text = &trimmed[hashes + 1..];
            let size = match hashes {
                1 => "xx-large",
                2 => "x-large",
                3 => "large",
                _ => "medium",
            };
            push(&mut out, &format!(
                "<span size=\"{}\" weight=\"bold\">{}</span>",
                size,
                md_inline(&xml_escape(text))
            ));
            continue;
        }
        // Checklist (before the plain-bullet case)
        if let Some((checked, text)) = checklist_rest(trimmed) {
            let box_glyph = if checked { "■" } else { "□" };
            push(&mut out, &format!("{}  {}", box_glyph, md_inline(&xml_escape(text))));
            continue;
        }
        // Bullet list
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") || trimmed.starts_with("+ ") {
            let text = &trimmed[2..];
            push(&mut out, &format!("  •  {}", md_inline(&xml_escape(text))));
            continue;
        }
        // Block quote
        if let Some(text) = trimmed.strip_prefix("> ") {
            push(&mut out, &format!(
                "<span foreground=\"#888888\">│</span> <i>{}</i>",
                md_inline(&xml_escape(text))
            ));
            continue;
        }
        // Normal paragraph line
        push(&mut out, &md_inline(&xml_escape(raw)));
    }
    if in_fence {
        out.push_str(&format!("<tt>{}</tt>\n", xml_escape(code.trim_end_matches('\n'))));
    }
    out.trim_end_matches('\n').to_string()
}

/// Format a single note as plain text for .txt export: title, an underline, a
/// blank line, then the body.
fn note_to_txt(title: &str, content: &str) -> String {
    let t = if title.trim().is_empty() { "Untitled" } else { title };
    let underline = "=".repeat(t.chars().count().clamp(3, 60));
    format!("{}\n{}\n\n{}\n", t, underline, content)
}

/// Turn a note title into a safe single-segment .txt filename (no path
/// separators or control characters), capped in length. Falls back to "Untitled".
fn sanitize_filename(title: &str) -> String {
    let cleaned: String = title
        .chars()
        .map(|c| if c.is_control() || "/\\:*?\"<>|".contains(c) { '_' } else { c })
        .take(80)
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').trim();
    if trimmed.is_empty() {
        "Untitled".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Build the right-click context menu for a sidebar note row. Each item
/// dispatches through the shared `action_holder` (Copy/Pin/Rename/Delete by id).
/// The caller parents the popover; it unparents itself when closed.
fn build_row_menu(
    action_holder: &Rc<RefCell<Option<Rc<dyn Fn(&str, u64)>>>>,
    id: u64,
    pinned: bool,
    include_find: bool,
) -> gtk::Popover {
    let popover = gtk::Popover::new();
    popover.set_has_arrow(false);

    let menu = gtk::Box::new(gtk::Orientation::Vertical, 0);
    menu.add_css_class("context-menu");

    let make = |label: &str, action: &'static str, danger: bool| -> gtk::Button {
        let btn = gtk::Button::with_label(label);
        btn.add_css_class("flat");
        btn.add_css_class("menu-item");
        if danger {
            btn.add_css_class("menu-item-danger");
        }
        if let Some(child) = btn.child() {
            child.set_halign(gtk::Align::Start);
        }
        let holder = action_holder.clone();
        let pop = popover.clone();
        btn.connect_clicked(move |_| {
            pop.popdown();
            if let Some(a) = holder.borrow().as_ref() {
                a(action, id);
            }
        });
        btn
    };

    // Find & replace acts on the open note, so it's only offered from the top-bar
    // ⋮ (which always targets the open note), not per-row sidebar menus.
    if include_find {
        menu.append(&make("Find & replace", "find", false));
    }
    menu.append(&make("Copy", "copy", false));
    menu.append(&make(if pinned { "Unpin" } else { "Pin" }, "pin", false));
    menu.append(&make("Rename", "rename", false));
    menu.append(&make("Export as .txt", "export", false));
    menu.append(&make("Delete", "delete", true));

    popover.set_child(Some(&menu));
    popover
}

/// The editor's right-click context menu, built as plain buttons that invoke the
/// `notectx` actions DIRECTLY via `activate_action` on the group we hold — so it
/// never depends on GtkPopoverMenu's widget-hierarchy action resolution, which
/// silently left every item dead when the popover was attached to the TextView.
/// Submenus (Insert / Generate / Transform) are nested popovers. This mirrors the
/// proven `build_row_menu` pattern. A fresh menu is built per right-click; the
/// `connect_closed` handler unparents it (and its submenus) so nothing leaks.
fn build_editor_context_menu(group: &gtk::gio::SimpleActionGroup) -> gtk::Popover {
    use gtk::gio::prelude::*;

    let root = gtk::Popover::new();
    root.set_has_arrow(false);
    let root_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    root_box.add_css_class("context-menu");

    // Submenu popovers, tracked so we can pop them down + unparent on close.
    let children: Rc<RefCell<Vec<gtk::Popover>>> = Rc::new(RefCell::new(Vec::new()));

    let close_all: Rc<dyn Fn()> = {
        let root = root.clone();
        let children = children.clone();
        Rc::new(move || {
            for c in children.borrow().iter() {
                c.popdown();
            }
            root.popdown();
        })
    };

    let add_leaf = |container: &gtk::Box, label: &str, action: &str| {
        let btn = gtk::Button::with_label(label);
        btn.add_css_class("flat");
        btn.add_css_class("menu-item");
        if let Some(c) = btn.child() {
            c.set_halign(gtk::Align::Start);
        }
        let g = group.clone();
        let close = close_all.clone();
        let action = action.to_owned();
        btn.connect_clicked(move |_| {
            close();
            g.activate_action(&action, None);
        });
        container.append(&btn);
    };

    let sep = || {
        let s = gtk::Separator::new(gtk::Orientation::Horizontal);
        s.add_css_class("menu-separator");
        s
    };

    // Standard editing
    add_leaf(&root_box, "Cut", "cut");
    add_leaf(&root_box, "Copy", "copy");
    add_leaf(&root_box, "Paste", "paste");
    add_leaf(&root_box, "Delete", "delete");
    add_leaf(&root_box, "Select All", "selectall");
    root_box.append(&sep());
    add_leaf(&root_box, "Undo", "undo");
    add_leaf(&root_box, "Redo", "redo");
    root_box.append(&sep());
    add_leaf(&root_box, "Find & replace", "find");
    add_leaf(&root_box, "Markdown preview", "preview");
    root_box.append(&sep());

    // Submenus (nested popovers opening to the right)
    let submenus: [(&str, &[(&str, &str)]); 6] = [
        ("Insert", &[
            ("Date", "insert_date"),
            ("Date & time", "insert_datetime"),
            ("Checklist item", "checklist"),
            ("Toggle checkbox (this line)", "togglecheck"),
            ("Separator line", "separator"),
        ]),
        ("Generate", &[
            ("Password…", "generate"),
            ("Passphrase", "passphrase"),
            ("PIN", "pin"),
            ("UUID", "uuid"),
            ("Hex token", "hex"),
        ]),
        ("Transform selection", &[
            ("UPPERCASE", "upper"),
            ("lowercase", "lower"),
            ("Title Case", "title"),
            ("Sort lines", "sort"),
            ("Remove duplicate lines", "dedupe"),
            ("Lines to checklist", "tochecklist"),
            ("Trim trailing spaces", "trim"),
        ]),
        // toolkit.py operations on the selection
        ("Encode", &[
            ("Base64", "enc_base64"),
            ("Base32", "enc_base32"),
            ("Hex", "enc_hex"),
            ("Binary", "enc_binary"),
            ("Morse", "enc_morse"),
            ("ROT13", "rot13"),
            ("Encrypt (passphrase)…", "encrypt"),
        ]),
        ("Decode", &[
            ("Base64", "dec_base64"),
            ("Base32", "dec_base32"),
            ("Hex", "dec_hex"),
            ("Binary", "dec_binary"),
            ("Morse", "dec_morse"),
            ("ROT13", "rot13"),
            ("Decrypt (passphrase)…", "decrypt"),
        ]),
        ("Hash", &[
            ("MD5", "hash_md5"),
            ("SHA-1", "hash_sha1"),
            ("SHA-256", "hash_sha256"),
            ("CRC32", "crc32"),
            ("Adler-32", "adler32"),
        ]),
    ];
    for (label, items) in submenus {
        let btn = gtk::Button::with_label(&format!("{}   \u{203a}", label));
        btn.add_css_class("flat");
        btn.add_css_class("menu-item");
        if let Some(c) = btn.child() {
            c.set_halign(gtk::Align::Start);
        }
        let child = gtk::Popover::new();
        child.set_has_arrow(false);
        child.set_position(gtk::PositionType::Right);
        let cbox = gtk::Box::new(gtk::Orientation::Vertical, 0);
        cbox.add_css_class("context-menu");
        for &(l, a) in items.iter() {
            add_leaf(&cbox, l, a);
        }
        child.set_child(Some(&cbox));
        child.set_parent(&btn);
        children.borrow_mut().push(child.clone());
        let children_for_btn = children.clone();
        btn.connect_clicked(move |_| {
            for c in children_for_btn.borrow().iter() {
                c.popdown();
            }
            child.popup();
        });
        root_box.append(&btn);
    }

    root.set_child(Some(&root_box));
    let children_for_close = children.clone();
    root.connect_closed(move |r| {
        for c in children_for_close.borrow().iter() {
            c.popdown();
            c.unparent();
        }
        children_for_close.borrow_mut().clear();
        r.unparent();
    });
    root
}

/// A popover listing every available theme; clicking one applies it live and
/// persists it. This is the top-bar 🎨 button's menu — the full app theme picker,
/// not just a light/dark toggle.
fn build_theme_picker(manager_rc: Arc<Mutex<CoreManager>>) -> gtk::Popover {
    let popover = gtk::Popover::new();
    popover.set_has_arrow(false);

    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .max_content_height(360)
        .propagate_natural_height(true)
        .build();

    let menu = gtk::Box::new(gtk::Orientation::Vertical, 0);
    menu.add_css_class("context-menu");

    let current = CURRENT_THEME.with(|t| t.borrow().clone());
    for (name, theme) in theme_choices() {
        // Mark the active theme with a dot.
        let label = if theme == current { format!("● {name}") } else { format!("    {name}") };
        let btn = gtk::Button::with_label(&label);
        btn.add_css_class("flat");
        btn.add_css_class("menu-item");
        if let Some(child) = btn.child() {
            child.set_halign(gtk::Align::Start);
        }
        let manager_rc = manager_rc.clone();
        let pop = popover.clone();
        btn.connect_clicked(move |_| {
            pop.popdown();
            switch_theme(&theme);
            if let Ok(mut mgr) = manager_rc.lock() {
                let mut s = mgr.get_settings().clone();
                if s.theme != theme {
                    s.theme = theme.clone();
                    let _ = mgr.update_settings(s);
                }
            }
        });
        menu.append(&btn);
    }

    scroller.set_child(Some(&menu));
    popover.set_child(Some(&scroller));
    popover
}

// ── Password tools: strength meter + generator ───────────────────────────────

/// Rough password strength as (fraction 0..1, short label). Heuristic entropy =
/// length × log2(character-pool size). No dictionary, no network.
fn password_strength(pw: &str) -> (f64, &'static str) {
    if pw.is_empty() {
        return (0.0, "");
    }
    let mut pool = 0u32;
    if pw.chars().any(|c| c.is_ascii_lowercase()) { pool += 26; }
    if pw.chars().any(|c| c.is_ascii_uppercase()) { pool += 26; }
    if pw.chars().any(|c| c.is_ascii_digit()) { pool += 10; }
    if pw.chars().any(|c| !c.is_ascii_alphanumeric()) { pool += 33; }
    let bits = pw.chars().count() as f64 * (pool.max(1) as f64).log2();
    let label = if bits < 40.0 { "Weak" }
        else if bits < 60.0 { "Fair" }
        else if bits < 80.0 { "Strong" }
        else { "Very strong" };
    ((bits / 100.0).min(1.0), label)
}

fn strength_color(frac: f64) -> &'static str {
    if frac < 0.4 { "#e06060" } else if frac < 0.6 { "#e0b060" }
    else if frac < 0.8 { "#80b060" } else { "#60c080" }
}

/// A small strength indicator (thin bar + coloured word) wired to live-update as
/// the given entry's text changes. Hidden while the field is empty.
fn make_strength_meter<E: IsA<gtk::Editable>>(entry: &E) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Vertical, 2);
    row.set_margin_top(6);
    let bar = gtk::ProgressBar::new();
    bar.add_css_class("strength-bar");
    let label = Label::new(None);
    label.set_halign(gtk::Align::Start);
    label.add_css_class("strength-label");
    row.append(&bar);
    row.append(&label);
    row.set_visible(false);

    let bar_c = bar.clone();
    let label_c = label.clone();
    let row_c = row.clone();
    entry.connect_changed(move |e| {
        let text = e.text().to_string();
        if text.is_empty() {
            row_c.set_visible(false);
            return;
        }
        row_c.set_visible(true);
        let (frac, word) = password_strength(&text);
        bar_c.set_fraction(frac);
        label_c.set_markup(&format!("<span foreground='{}'>Strength: {}</span>", strength_color(frac), word));
    });
    row
}

/// Generate a cryptographically-strong random password from the chosen classes,
/// rejection-sampling OS-RNG bytes to avoid modulo bias.
fn generate_password(len: usize, lower: bool, upper: bool, digits: bool, symbols: bool) -> String {
    use aes_gcm::aead::{rand_core::RngCore, OsRng};
    let mut pool: Vec<u8> = Vec::new();
    if lower { pool.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz"); }
    if upper { pool.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if digits { pool.extend_from_slice(b"0123456789"); }
    if symbols { pool.extend_from_slice(b"!@#$%^&*()-_=+[]{};:,.<>/?"); }
    if pool.is_empty() {
        pool.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    }
    let n = pool.len();
    let limit = 256usize - (256usize % n); // reject bytes >= limit to kill bias
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 1];
    while out.len() < len {
        OsRng.fill_bytes(&mut buf);
        let b = buf[0] as usize;
        if b < limit {
            out.push(pool[b % n] as char);
        }
    }
    out
}

/// A movable, centered modal window that generates strong passwords (length
/// slider + class toggles). "Insert" hands the current password to `apply` (e.g.
/// to drop it into the open note); "Copy" puts it on the clipboard.
fn show_password_generator<F: Fn(&str) + 'static>(parent: Option<gtk::Window>, apply: F) {
    let dialog = gtk::Window::builder()
        .title("Generate password")
        .modal(true)
        .resizable(false)
        .default_width(340)
        .build();
    if let Some(ref p) = parent {
        dialog.set_transient_for(Some(p));
    }

    // Custom header (hidden title buttons + traffic close), matching the app.
    let header = gtk::HeaderBar::new();
    header.set_show_title_buttons(false);
    header.add_css_class("custom-headerbar");
    let dialog_for_close = dialog.clone();
    let close_btn = gtk::Button::new();
    close_btn.add_css_class("traffic-btn");
    close_btn.add_css_class("traffic-close");
    shape_traffic_button(&close_btn);
    close_btn.connect_clicked(move |_| dialog_for_close.close());
    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 2);
    btn_box.set_margin_start(4);
    btn_box.append(&close_btn);
    header.pack_start(&btn_box);
    let header_title = Label::new(Some("Generate password"));
    header_title.add_css_class("headerbar-title");
    header.set_title_widget(Some(&header_title));
    dialog.set_titlebar(Some(&header));

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 10);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);

    let len_label = Label::new(Some("Length: 24"));
    len_label.set_halign(gtk::Align::Start);
    let scale = gtk::Scale::with_range(gtk::Orientation::Horizontal, 12.0, 64.0, 1.0);
    scale.set_value(24.0);
    scale.set_hexpand(true);
    scale.set_draw_value(false);
    {
        let len_label = len_label.clone();
        scale.connect_value_changed(move |s| {
            len_label.set_text(&format!("Length: {}", s.value() as usize));
        });
    }

    let classes = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let lower = gtk::CheckButton::with_label("a-z");
    let upper = gtk::CheckButton::with_label("A-Z");
    let digits = gtk::CheckButton::with_label("0-9");
    let symbols = gtk::CheckButton::with_label("!@#");
    lower.set_active(true);
    upper.set_active(true);
    digits.set_active(true);
    symbols.set_active(true);
    classes.append(&lower);
    classes.append(&upper);
    classes.append(&digits);
    classes.append(&symbols);

    // Live strength readout computed from the chosen length × class pool, so you
    // can see exactly how strong (in bits) a generated password will be.
    let strength_bar = gtk::ProgressBar::new();
    strength_bar.add_css_class("strength-bar");
    let strength_label = Label::new(None);
    strength_label.set_halign(gtk::Align::Start);
    strength_label.add_css_class("strength-label");
    let update_strength = {
        let scale = scale.clone();
        let lower = lower.clone();
        let upper = upper.clone();
        let digits = digits.clone();
        let symbols = symbols.clone();
        let bar = strength_bar.clone();
        let label = strength_label.clone();
        move || {
            let mut pool = 0u32;
            if lower.is_active() { pool += 26; }
            if upper.is_active() { pool += 26; }
            if digits.is_active() { pool += 10; }
            if symbols.is_active() { pool += 33; }
            let bits = scale.value() * (pool.max(1) as f64).log2();
            let frac = (bits / 128.0).min(1.0);
            let word = if bits < 50.0 { "Weak" } else if bits < 70.0 { "Fair" }
                else if bits < 100.0 { "Strong" } else { "Very strong" };
            bar.set_fraction(frac);
            label.set_markup(&format!(
                "<span foreground='{}'>Strength: {} (~{} bits)</span>",
                strength_color(frac), word, bits as u32,
            ));
        }
    };
    update_strength();
    {
        let u = update_strength.clone();
        scale.connect_value_changed(move |_| u());
    }
    for cb in [&lower, &upper, &digits, &symbols] {
        let u = update_strength.clone();
        cb.connect_toggled(move |_| u());
    }

    let preview = Label::new(None);
    preview.set_selectable(true);
    preview.set_wrap(true);
    preview.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    preview.set_halign(gtk::Align::Start);
    preview.add_css_class("gen-preview");

    let gen_btn = gtk::Button::with_label("Generate");
    gen_btn.add_css_class("action-button");
    let insert_btn = gtk::Button::with_label("Insert at cursor");
    insert_btn.add_css_class("secondary-button");
    let copy_btn = gtk::Button::with_label("Copy");
    copy_btn.add_css_class("secondary-button");

    {
        let scale = scale.clone();
        let lower = lower.clone();
        let upper = upper.clone();
        let digits = digits.clone();
        let symbols = symbols.clone();
        let preview = preview.clone();
        gen_btn.connect_clicked(move |_| {
            let pw = generate_password(
                scale.value() as usize,
                lower.is_active(),
                upper.is_active(),
                digits.is_active(),
                symbols.is_active(),
            );
            preview.set_text(&pw);
        });
    }
    {
        let preview = preview.clone();
        insert_btn.connect_clicked(move |_| {
            let pw = preview.text().to_string();
            if !pw.is_empty() {
                apply(&pw);
            }
        });
    }
    {
        let preview = preview.clone();
        copy_btn.connect_clicked(move |_| {
            let pw = preview.text().to_string();
            if !pw.is_empty() {
                if let Some(d) = gtk::gdk::Display::default() {
                    d.clipboard().set_text(&pw);
                }
            }
        });
    }

    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    actions.set_halign(gtk::Align::End);
    actions.append(&copy_btn);
    actions.append(&insert_btn);

    vbox.append(&len_label);
    vbox.append(&scale);
    vbox.append(&classes);
    vbox.append(&strength_bar);
    vbox.append(&strength_label);
    vbox.append(&gen_btn);
    vbox.append(&preview);
    vbox.append(&actions);
    dialog.set_child(Some(&vbox));
    dialog.present();
}

/// Compact word list for memorable passphrases (~128 words → 7 bits each).
const PASSPHRASE_WORDS: &[&str] = &[
    "amber","anchor","apple","arrow","aspen","autumn","basil","beacon","birch","bison",
    "bloom","branch","breeze","bridge","bronze","brook","candle","canyon","cedar","cherry",
    "cinder","clover","cobalt","comet","copper","coral","cosmos","cotton","crimson","crystal",
    "cypress","daisy","dawn","delta","ember","falcon","feather","fern","flint","forest",
    "garnet","ginger","glacier","granite","gravel","harbor","hazel","heron","hickory","honey",
    "indigo","iris","ivory","jasmine","juniper","kestrel","lagoon","lantern","laurel","lemon",
    "lilac","linen","lotus","lunar","maple","marble","meadow","mint","mirror","nectar",
    "nimbus","ocean","olive","onyx","opal","orchid","otter","pebble","pepper","pine",
    "poppy","quartz","quill","quince","raven","ridge","ripple","river","robin","rowan",
    "ruby","saffron","sage","sapphire","scarlet","sequoia","shadow","silver","slate","sparrow",
    "spruce","storm","summit","sunset","thicket","thistle","thorn","timber","topaz","tulip",
    "tundra","umber","valley","velvet","violet","walnut","willow","winter","zephyr","cascade",
    "cliff","drift","grove","harvest","island","lake","moss",
];

/// Generate a Title-Case hyphenated passphrase of `n` words (OS-random, rejection-sampled).
fn gen_passphrase(n: usize) -> String {
    use aes_gcm::aead::{rand_core::RngCore, OsRng};
    let words = PASSPHRASE_WORDS;
    let len = words.len();
    let limit = 256usize - (256usize % len);
    let mut chosen: Vec<String> = Vec::with_capacity(n);
    let mut buf = [0u8; 1];
    while chosen.len() < n {
        OsRng.fill_bytes(&mut buf);
        let b = buf[0] as usize;
        if b < limit {
            let w = words[b % len];
            let mut c = w.chars();
            let titled = c.next().map(|f| f.to_uppercase().collect::<String>()).unwrap_or_default()
                + c.as_str();
            chosen.push(titled);
        }
    }
    chosen.join("-")
}

/// A numeric PIN of `len` digits (OS-random, unbiased).
fn gen_pin(len: usize) -> String {
    use aes_gcm::aead::{rand_core::RngCore, OsRng};
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 1];
    while out.len() < len {
        OsRng.fill_bytes(&mut buf);
        if buf[0] < 250 {
            out.push((b'0' + (buf[0] % 10)) as char);
        }
    }
    out
}

/// A random v4 UUID.
fn gen_uuid_v4() -> String {
    use aes_gcm::aead::{rand_core::RngCore, OsRng};
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

/// A random lowercase-hex token of `nbytes` bytes (so 2×nbytes hex chars).
fn gen_hex_token(nbytes: usize) -> String {
    use aes_gcm::aead::{rand_core::RngCore, OsRng};
    let mut v = vec![0u8; nbytes];
    OsRng.fill_bytes(&mut v);
    v.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Title-case a string (capitalise the first letter of each whitespace-separated run).
fn title_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut cap = true;
    for ch in s.chars() {
        if ch.is_whitespace() {
            cap = true;
            out.push(ch);
        } else if cap {
            out.extend(ch.to_uppercase());
            cap = false;
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}

/// The region the context-menu actions operate on: the live selection if there
/// is one, else the `snapshot` taken on right-click (char offsets, before the
/// editor could clear the selection when the menu opened), else the whole buffer.
fn region_iters(
    buffer: &gtk::TextBuffer,
    snapshot: Option<(i32, i32)>,
) -> (gtk::TextIter, gtk::TextIter) {
    if let Some(sel) = buffer.selection_bounds() {
        return sel;
    }
    if let Some((a, b)) = snapshot {
        // Guard against a stale snapshot from a different/previous note.
        let n = buffer.char_count();
        if a != b && a >= 0 && b <= n {
            return (buffer.iter_at_offset(a), buffer.iter_at_offset(b));
        }
    }
    (buffer.start_iter(), buffer.end_iter())
}

/// Apply `f` to the selected text (or `snapshot`, or the whole buffer), replacing
/// it as one undoable action.
fn transform_region<F: Fn(&str) -> String>(
    buffer: &gtk::TextBuffer,
    snapshot: Option<(i32, i32)>,
    f: F,
) {
    let (mut s, mut e) = region_iters(buffer, snapshot);
    let text = buffer.text(&s, &e, false).to_string();
    let new = f(&text);
    if new != text {
        buffer.begin_user_action();
        buffer.delete(&mut s, &mut e);
        buffer.insert(&mut s, &new);
        buffer.end_user_action();
    }
}

/// Like `transform_region` but `f` may fail: on `Ok` the region is replaced (one
/// undoable action); on `Err` the message is shown in the status bar and the text
/// is left untouched. Used by the toolkit Encode/Decode/Hash actions, where a
/// decode can legitimately fail on malformed input.
fn transform_region_fallible<F: Fn(&str) -> Result<String, String>>(
    buffer: &gtk::TextBuffer,
    snapshot: Option<(i32, i32)>,
    status: &Label,
    f: F,
) {
    let (mut s, mut e) = region_iters(buffer, snapshot);
    let text = buffer.text(&s, &e, false).to_string();
    if text.is_empty() {
        status.set_text("Select some text first");
        return;
    }
    match f(&text) {
        Ok(new) => {
            if new != text {
                buffer.begin_user_action();
                buffer.delete(&mut s, &mut e);
                buffer.insert(&mut s, &new);
                buffer.end_user_action();
            }
        }
        Err(msg) => status.set_text(&msg),
    }
}

/// Encrypt (or decrypt) the selected text with a passphrase. Captures the region
/// offsets up front (the modal dialog blocks edits, so they stay valid), prompts
/// for the passphrase, then replaces the region with the result as one undoable
/// action. A wrong passphrase / malformed block shows in the status bar.
fn run_passphrase_op(
    view: &gtk::TextView,
    buffer: &Arc<gtk::TextBuffer>,
    last_selection: &Rc<Cell<Option<(i32, i32)>>>,
    status: &Arc<Label>,
    encrypt: bool,
) {
    let (s, e) = region_iters(buffer, last_selection.get());
    let (start_off, end_off) = (s.offset(), e.offset());
    let text = buffer.text(&s, &e, false).to_string();
    if text.trim().is_empty() {
        status.set_text("Select some text first");
        return;
    }
    let parent = view.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    let buffer = buffer.clone();
    let status = status.clone();
    show_passphrase_dialog(parent, encrypt, move |pass| {
        let result = if encrypt {
            toolkit::encrypt_text(&text, &pass)
        } else {
            toolkit::decrypt_text(&text, &pass)
        };
        match result {
            Ok(new) => {
                let n = buffer.char_count();
                let (a, b) = (start_off.min(n), end_off.min(n));
                let mut si = buffer.iter_at_offset(a);
                let mut ei = buffer.iter_at_offset(b);
                buffer.begin_user_action();
                buffer.delete(&mut si, &mut ei);
                let mut ins = buffer.iter_at_offset(a);
                buffer.insert(&mut ins, &new);
                buffer.end_user_action();
                status.set_text(if encrypt { "Encrypted" } else { "Decrypted" });
            }
            Err(msg) => status.set_text(&msg),
        }
    });
}

/// Modal passphrase prompt. For encrypt it asks for a confirmation too (a typo
/// would otherwise make the text unrecoverable). `on_ok` is called with the
/// passphrase only after validation passes. The passphrase is never stored.
fn show_passphrase_dialog(
    parent: Option<gtk::Window>,
    encrypt: bool,
    on_ok: impl Fn(String) + 'static,
) {
    let win = gtk::Window::new();
    win.set_modal(true);
    if let Some(p) = &parent {
        win.set_transient_for(Some(p));
    }
    win.set_title(Some(if encrypt { "Encrypt selection" } else { "Decrypt selection" }));
    win.set_default_width(380);
    win.set_resizable(false);

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 10);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);

    let pass = gtk::PasswordEntry::new();
    pass.set_show_peek_icon(true);
    vbox.append(&pass);

    let confirm = gtk::PasswordEntry::new();
    confirm.set_show_peek_icon(true);
    if encrypt {
        let lbl = Label::new(Some("Confirm passphrase"));
        lbl.set_xalign(0.0);
        lbl.add_css_class("dim-label");
        vbox.append(&lbl);
        vbox.append(&confirm);
    }

    let err = Label::new(None);
    err.set_xalign(0.0);
    err.add_css_class("error");
    err.set_visible(false);
    vbox.append(&err);

    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    buttons.set_halign(gtk::Align::End);
    buttons.set_margin_top(4);
    let cancel = gtk::Button::with_label("Cancel");
    let ok = gtk::Button::with_label(if encrypt { "Encrypt" } else { "Decrypt" });
    ok.add_css_class("suggested-action");
    buttons.append(&cancel);
    buttons.append(&ok);
    vbox.append(&buttons);

    win.set_child(Some(&vbox));

    {
        let win = win.clone();
        cancel.connect_clicked(move |_| win.close());
    }

    let do_ok: Rc<dyn Fn()> = {
        let win = win.clone();
        let pass = pass.clone();
        let confirm = confirm.clone();
        let err = err.clone();
        let on_ok = Rc::new(on_ok);
        Rc::new(move || {
            let p = pass.text().to_string();
            if p.is_empty() {
                err.set_text("Passphrase cannot be empty");
                err.set_visible(true);
                return;
            }
            if encrypt && p != confirm.text().as_str() {
                err.set_text("Passphrases do not match");
                err.set_visible(true);
                return;
            }
            win.close();
            on_ok(p);
        })
    };
    {
        let do_ok = do_ok.clone();
        ok.connect_clicked(move |_| do_ok());
    }
    {
        let do_ok = do_ok.clone();
        // Enter in the (last) field submits.
        let target = if encrypt { &confirm } else { &pass };
        target.connect_activate(move |_| do_ok());
    }

    win.present();
    pass.grab_focus();
}

/// Add Notas' extra items to the note editor's right-click menu (Find & replace,
/// Insert…, Generate…, Transform selection…, Copy auto-clear, word count).
fn attach_note_context_menu(
    view: &gtk::TextView,
    buffer: &Arc<gtk::TextBuffer>,
    find_bar: &gtk::Box,
    find_entry: &gtk::SearchEntry,
    status_label: &Arc<Label>,
    last_selection: &Rc<Cell<Option<(i32, i32)>>>,
    toggle_preview: Rc<dyn Fn()>,
) {
    use gtk::gio;
    use gtk::gio::prelude::*;

    let group = gio::SimpleActionGroup::new();
    let add = |name: &str, cb: Box<dyn Fn() + 'static>| {
        let a = gio::SimpleAction::new(name, None);
        a.connect_activate(move |_, _| cb());
        group.add_action(&a);
    };

    // Find & replace
    {
        let find_bar = find_bar.clone();
        let find_entry = find_entry.clone();
        add("find", Box::new(move || {
            find_bar.set_visible(true);
            find_entry.grab_focus();
        }));
    }

    // Markdown preview toggle (also on Ctrl+P)
    {
        let tp = toggle_preview.clone();
        add("preview", Box::new(move || tp()));
    }

    // ── Standard editing actions ──
    // Our custom right-click popover does NOT inherit GtkTextView's built-in
    // clipboard/undo actions (a `set_parent`'d PopoverMenu doesn't resolve them),
    // so we provide our own here, all inside the `notectx` group that gets
    // inserted directly on the popover. Without this, every menu item is dead.
    {
        let b = buffer.clone();
        add("undo", Box::new(move || b.undo()));
    }
    {
        let b = buffer.clone();
        add("redo", Box::new(move || b.redo()));
    }
    {
        let b = buffer.clone();
        let v = view.clone();
        add("cut", Box::new(move || {
            if let Some((mut s, mut e)) = b.selection_bounds() {
                v.clipboard().set_text(b.text(&s, &e, false).as_str());
                b.delete(&mut s, &mut e);
            }
        }));
    }
    {
        let b = buffer.clone();
        let v = view.clone();
        add("copy", Box::new(move || {
            if let Some((s, e)) = b.selection_bounds() {
                v.clipboard().set_text(b.text(&s, &e, false).as_str());
            }
        }));
    }
    {
        let b = buffer.clone();
        let v = view.clone();
        add("paste", Box::new(move || {
            // Replace any selection, then insert the clipboard text at the cursor.
            if let Some((mut s, mut e)) = b.selection_bounds() {
                b.delete(&mut s, &mut e);
            }
            let b2 = b.clone();
            v.clipboard().read_text_async(gtk::gio::Cancellable::NONE, move |res| {
                if let Ok(Some(text)) = res {
                    b2.insert_at_cursor(text.as_str());
                }
            });
        }));
    }
    {
        let b = buffer.clone();
        add("delete", Box::new(move || {
            if let Some((mut s, mut e)) = b.selection_bounds() {
                b.delete(&mut s, &mut e);
            }
        }));
    }
    {
        let b = buffer.clone();
        add("selectall", Box::new(move || {
            b.select_range(&b.start_iter(), &b.end_iter());
        }));
    }

    // ── Insert ──
    {
        let b = buffer.clone();
        add("insert_date", Box::new(move || {
            b.insert_at_cursor(&chrono::Local::now().format("%Y-%m-%d").to_string());
        }));
    }
    {
        let b = buffer.clone();
        add("insert_datetime", Box::new(move || {
            b.insert_at_cursor(&chrono::Local::now().format("%Y-%m-%d %H:%M").to_string());
        }));
    }
    {
        let b = buffer.clone();
        add("checklist", Box::new(move || {
            let cur = b.iter_at_offset(b.cursor_position());
            b.insert_at_cursor(if cur.starts_line() { "- [ ] " } else { "\n- [ ] " });
        }));
    }
    // Toggle the checkbox on the cursor's line (precise, no click-gesture).
    {
        let b = buffer.clone();
        add("togglecheck", Box::new(move || {
            let line = b.iter_at_offset(b.cursor_position()).line();
            let Some(ls) = b.iter_at_line(line) else { return };
            let mut le = ls.clone();
            if !le.ends_line() {
                le.forward_to_line_end();
            }
            let text = b.text(&ls, &le, false).to_string();
            let Some(inner) = checkbox_inner_index(&text) else { return };
            let chars: Vec<char> = text.chars().collect();
            let new_char = if chars[inner] == ' ' { "x" } else { " " };
            let (Some(mut a), Some(mut b2)) = (
                b.iter_at_line_offset(line, inner as i32),
                b.iter_at_line_offset(line, inner as i32 + 1),
            ) else {
                return;
            };
            b.begin_user_action();
            b.delete(&mut a, &mut b2);
            if let Some(mut a2) = b.iter_at_line_offset(line, inner as i32) {
                b.insert(&mut a2, new_char);
            }
            b.end_user_action();
        }));
    }
    {
        let b = buffer.clone();
        add("separator", Box::new(move || {
            let cur = b.iter_at_offset(b.cursor_position());
            b.insert_at_cursor(if cur.starts_line() { "---\n" } else { "\n---\n" });
        }));
    }

    // ── Generate → insert ──
    {
        let view = view.clone();
        let b = buffer.clone();
        add("generate", Box::new(move || {
            let b = b.clone();
            let parent = view.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_password_generator(parent, move |pw| b.insert_at_cursor(pw));
        }));
    }
    {
        let b = buffer.clone();
        add("passphrase", Box::new(move || b.insert_at_cursor(&gen_passphrase(8))));
    }
    {
        let b = buffer.clone();
        add("pin", Box::new(move || b.insert_at_cursor(&gen_pin(6))));
    }
    {
        let b = buffer.clone();
        add("uuid", Box::new(move || b.insert_at_cursor(&gen_uuid_v4())));
    }
    {
        let b = buffer.clone();
        add("hex", Box::new(move || b.insert_at_cursor(&gen_hex_token(16))));
    }

    // ── Transform the selection snapshot (or whole note if nothing selected) ──
    {
        let b = buffer.clone();
        let ls = last_selection.clone();
        add("upper", Box::new(move || transform_region(&b, ls.get(), |t| t.to_uppercase())));
    }
    {
        let b = buffer.clone();
        let ls = last_selection.clone();
        add("lower", Box::new(move || transform_region(&b, ls.get(), |t| t.to_lowercase())));
    }
    {
        let b = buffer.clone();
        let ls = last_selection.clone();
        add("title", Box::new(move || transform_region(&b, ls.get(), |t| title_case(t))));
    }
    {
        let b = buffer.clone();
        let ls = last_selection.clone();
        add("sort", Box::new(move || transform_region(&b, ls.get(), |t| {
            let mut v: Vec<&str> = t.lines().collect();
            v.sort_unstable();
            v.join("\n")
        })));
    }
    {
        let b = buffer.clone();
        let ls = last_selection.clone();
        add("dedupe", Box::new(move || transform_region(&b, ls.get(), |t| {
            let mut seen = std::collections::HashSet::new();
            t.lines().filter(|l| seen.insert(l.to_string())).collect::<Vec<_>>().join("\n")
        })));
    }
    {
        let b = buffer.clone();
        let ls = last_selection.clone();
        add("tochecklist", Box::new(move || transform_region(&b, ls.get(), |t| {
            t.lines().map(|l| format!("- [ ] {}", l)).collect::<Vec<_>>().join("\n")
        })));
    }
    {
        let b = buffer.clone();
        let ls = last_selection.clone();
        add("trim", Box::new(move || transform_region(&b, ls.get(), |t| {
            t.lines().map(|l| l.trim_end()).collect::<Vec<_>>().join("\n")
        })));
    }

    // ── Clipboard / info ──
    {
        let b = buffer.clone();
        let status = status_label.clone();
        let ls = last_selection.clone();
        add("copyclear", Box::new(move || {
            let (s, e) = region_iters(&b, ls.get());
            let text = b.text(&s, &e, false).to_string();
            if text.is_empty() {
                return;
            }
            let Some(d) = gtk::gdk::Display::default() else { return };
            d.clipboard().set_text(&text);
            status.set_text("Copied");
            let timeout = CORE_MANAGER
                .get()
                .map(|m| m.lock().unwrap().get_settings().clipboard_timeout)
                .unwrap_or(0);
            if timeout > 0 {
                CLIPBOARD_TIMER.with(|c| {
                    if let Some(o) = c.borrow_mut().take() {
                        o.remove();
                    }
                });
                let status2 = status.clone();
                let tid = glib::timeout_add_seconds_local(timeout as u32, move || {
                    if let Some(d) = gtk::gdk::Display::default() {
                        d.clipboard().set_text("");
                    }
                    status2.set_text("Clipboard cleared");
                    CLIPBOARD_TIMER.with(|c| *c.borrow_mut() = None);
                    glib::ControlFlow::Break
                });
                CLIPBOARD_TIMER.with(|c| *c.borrow_mut() = Some(tid));
            }
        }));
    }
    {
        let b = buffer.clone();
        let status = status_label.clone();
        let ls = last_selection.clone();
        add("wordcount", Box::new(move || {
            let (s, e) = region_iters(&b, ls.get());
            let text = b.text(&s, &e, false).to_string();
            status.set_text(&format!(
                "Selection: {} words · {} chars",
                text.split_whitespace().count(),
                text.chars().count(),
            ));
        }));
    }

    // ── toolkit.py operations (Encode / Decode / Hash) on the selection ──
    // Native re-implementations (see src/toolkit.rs). Each acts on the selection
    // snapshot like the Transform actions; decode failures show in the status bar.
    {
        let tools: &[(&str, fn(&str) -> Result<String, String>)] = &[
            ("enc_base64", |t| Ok(toolkit::base64_encode(t))),
            ("dec_base64", toolkit::base64_decode),
            ("enc_base32", |t| Ok(toolkit::base32_encode(t))),
            ("dec_base32", toolkit::base32_decode),
            ("enc_hex", |t| Ok(toolkit::hex_encode(t))),
            ("dec_hex", toolkit::hex_decode),
            ("enc_binary", |t| Ok(toolkit::binary_encode(t))),
            ("dec_binary", toolkit::binary_decode),
            ("enc_morse", |t| Ok(toolkit::morse_encode(t))),
            ("dec_morse", toolkit::morse_decode),
            ("rot13", |t| Ok(toolkit::rot13(t))),
            ("hash_md5", |t| Ok(toolkit::md5(t))),
            ("hash_sha1", |t| Ok(toolkit::sha1(t))),
            ("hash_sha256", |t| Ok(toolkit::sha256(t))),
            ("crc32", |t| Ok(toolkit::crc32(t))),
            ("adler32", |t| Ok(toolkit::adler32(t))),
        ];
        for &(name, f) in tools {
            let b = buffer.clone();
            let ls = last_selection.clone();
            let st = status_label.clone();
            add(name, Box::new(move || transform_region_fallible(&b, ls.get(), &st, f)));
        }
    }

    // Passphrase encrypt/decrypt of the selection (prompts for a passphrase).
    {
        let v = view.clone();
        let b = buffer.clone();
        let ls = last_selection.clone();
        let st = status_label.clone();
        add("encrypt", Box::new(move || run_passphrase_op(&v, &b, &ls, &st, true)));
    }
    {
        let v = view.clone();
        let b = buffer.clone();
        let ls = last_selection.clone();
        let st = status_label.clone();
        add("decrypt", Box::new(move || run_passphrase_op(&v, &b, &ls, &st, false)));
    }

    view.insert_action_group("notectx", Some(&group));

    // Build the menu with submenus so it stays tidy.
    let menu = gio::Menu::new();
    menu.append(Some("Find & replace"), Some("notectx.find"));
    menu.append(Some("Markdown preview"), Some("notectx.preview"));

    let insert = gio::Menu::new();
    insert.append(Some("Date"), Some("notectx.insert_date"));
    insert.append(Some("Date & time"), Some("notectx.insert_datetime"));
    insert.append(Some("Checklist item"), Some("notectx.checklist"));
    insert.append(Some("Toggle checkbox (this line)"), Some("notectx.togglecheck"));
    insert.append(Some("Separator line"), Some("notectx.separator"));
    menu.append_submenu(Some("Insert"), &insert);

    let generate = gio::Menu::new();
    generate.append(Some("Password…"), Some("notectx.generate"));
    generate.append(Some("Passphrase"), Some("notectx.passphrase"));
    generate.append(Some("PIN"), Some("notectx.pin"));
    generate.append(Some("UUID"), Some("notectx.uuid"));
    generate.append(Some("Hex token"), Some("notectx.hex"));
    menu.append_submenu(Some("Generate"), &generate);

    let transform = gio::Menu::new();
    transform.append(Some("UPPERCASE"), Some("notectx.upper"));
    transform.append(Some("lowercase"), Some("notectx.lower"));
    transform.append(Some("Title Case"), Some("notectx.title"));
    transform.append(Some("Sort lines"), Some("notectx.sort"));
    transform.append(Some("Remove duplicate lines"), Some("notectx.dedupe"));
    transform.append(Some("Lines to checklist"), Some("notectx.tochecklist"));
    transform.append(Some("Trim trailing spaces"), Some("notectx.trim"));
    menu.append_submenu(Some("Transform selection"), &transform);

    let encode = gio::Menu::new();
    encode.append(Some("Base64"), Some("notectx.enc_base64"));
    encode.append(Some("Base32"), Some("notectx.enc_base32"));
    encode.append(Some("Hex"), Some("notectx.enc_hex"));
    encode.append(Some("Binary"), Some("notectx.enc_binary"));
    encode.append(Some("Morse"), Some("notectx.enc_morse"));
    encode.append(Some("ROT13"), Some("notectx.rot13"));
    encode.append(Some("Encrypt (passphrase)…"), Some("notectx.encrypt"));
    menu.append_submenu(Some("Encode"), &encode);

    let decode = gio::Menu::new();
    decode.append(Some("Base64"), Some("notectx.dec_base64"));
    decode.append(Some("Base32"), Some("notectx.dec_base32"));
    decode.append(Some("Hex"), Some("notectx.dec_hex"));
    decode.append(Some("Binary"), Some("notectx.dec_binary"));
    decode.append(Some("Morse"), Some("notectx.dec_morse"));
    decode.append(Some("ROT13"), Some("notectx.rot13"));
    decode.append(Some("Decrypt (passphrase)…"), Some("notectx.decrypt"));
    menu.append_submenu(Some("Decode"), &decode);

    let hash = gio::Menu::new();
    hash.append(Some("MD5"), Some("notectx.hash_md5"));
    hash.append(Some("SHA-1"), Some("notectx.hash_sha1"));
    hash.append(Some("SHA-256"), Some("notectx.hash_sha256"));
    hash.append(Some("CRC32"), Some("notectx.crc32"));
    hash.append(Some("Adler-32"), Some("notectx.adler32"));
    menu.append_submenu(Some("Hash"), &hash);

    menu.append(Some("Copy (auto-clear)"), Some("notectx.copyclear"));
    menu.append(Some("Selection word count"), Some("notectx.wordcount"));

    // Keep the model on the native menu too, so the keyboard context-menu key
    // (Menu / Shift+F10) still offers our items (the native path adds the
    // standard Cut/Copy/Paste itself and doesn't have the mouse glitch below).
    view.set_extra_menu(Some(&menu));

    // ── The right-click "cut" fix ──────────────────────────────────────────────
    // GtkTextView's NATIVE context menu opens on button *press*. In this setup a
    // quick right-click's *release* then lands on whatever item sits under the
    // pointer (the first one is "Cut") and fires it — so a normal right-click
    // instantly cuts the selection, and only press-and-HOLD (so the release comes
    // later, elsewhere) let you reach an item on purpose. That's the whole bug.
    //
    // Fix: take over the secondary (right) button ourselves and pop up the menu on
    // RELEASE, not press. When the menu appears the button is already up, so there
    // is no release left to auto-activate an item. We claim the press in the
    // CAPTURE phase so the native press-menu never opens (no double menu). This is
    // button-3 only — primary-button selection / drag-and-drop is left alone.
    //
    // We build the popover from plain buttons (see build_editor_context_menu),
    // which invoke the `notectx` actions DIRECTLY via activate_action — so it does
    // NOT depend on GtkPopoverMenu's hierarchy action resolution, which silently
    // left every item dead when the popover was attached to the TextView.
    {
        let view_for_menu = view.clone();
        let group_for_menu = group.clone();
        let press_xy: Rc<Cell<(f64, f64)>> = Rc::new(Cell::new((0.0, 0.0)));
        let gesture = gtk::GestureClick::new();
        gesture.set_button(gtk::gdk::BUTTON_SECONDARY);
        gesture.set_propagation_phase(gtk::PropagationPhase::Capture);
        {
            let press_xy = press_xy.clone();
            gesture.connect_pressed(move |g, _, x, y| {
                // Claim the press so the native press-triggered menu never opens.
                g.set_state(gtk::EventSequenceState::Claimed);
                press_xy.set((x, y));
            });
        }
        gesture.connect_released(move |_, _, _, _| {
            // Pop up on release (button already up → nothing auto-activates),
            // pointing at where the press landed.
            let (x, y) = press_xy.get();
            let popover = build_editor_context_menu(&group_for_menu);
            popover.set_parent(&view_for_menu);
            popover.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            popover.popup();
        });
        view.add_controller(gesture);
    }
}

/// Quick-rename a note's title without opening it; the body is left untouched.
fn show_rename_dialog<F: Fn() + 'static>(
    parent: &ApplicationWindow,
    manager_rc: Arc<Mutex<CoreManager>>,
    id: u64,
    active_note_id: Arc<Mutex<Option<u64>>>,
    title_entry: Arc<gtk::Entry>,
    refresh: F,
) {
    let note = manager_rc
        .lock()
        .unwrap()
        .get_notes()
        .into_iter()
        .find(|n| n.id == id);
    let Some(note) = note else { return };
    let content = note.content.clone();

    let dialog = adw::MessageDialog::new(Some(parent), Some("Rename note"), None);
    let entry = gtk::Entry::new();
    entry.set_text(&note.title);
    entry.set_hexpand(true);
    entry.set_activates_default(true);
    dialog.set_extra_child(Some(&entry));
    dialog.add_responses(&[("cancel", "Cancel"), ("save", "Rename")]);
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("save"));
    dialog.set_close_response("cancel");

    dialog.connect_response(None, move |_, resp| {
        if resp != "save" {
            return;
        }
        let new_title = entry.text().to_string();
        let _ = manager_rc
            .lock()
            .unwrap()
            .update_note(id, new_title.clone(), content.clone(), None);
        if *active_note_id.lock().unwrap() == Some(id) {
            title_entry.set_text(&new_title);
        }
        refresh();
    });
    dialog.present();
}

fn show_password_screen(app: &Application) {
    // Kill any auto-lock timer left over from the main window we're locking out of.
    // Reached on every lock (manual, Ctrl+L/Escape, or auto) and at startup, so a
    // single cancel here guarantees at most one auto-lock timer is ever alive.
    cancel_auto_lock_timer();

    let window = ApplicationWindow::builder()
        .application(app)
        .title("Notas")
        .default_width(420)
        .default_height(380)
        .build();
    
    // Create custom header bar
    let header = gtk::HeaderBar::new();
    header.set_show_title_buttons(false);
    header.add_css_class("custom-headerbar");
    
    // Window controls on the right.
    let traffic_buttons = create_traffic_light_buttons(&window);
    header.pack_end(&traffic_buttons);

    // Title
    let header_title = Label::new(None);
    header_title.add_css_class("headerbar-title");
    header.set_title_widget(Some(&header_title));
    
    window.set_titlebar(Some(&header));
    window.add_css_class("lock-screen");

    let main_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    main_box.set_valign(gtk::Align::Center);
    main_box.set_halign(gtk::Align::Center);
    main_box.set_margin_top(20);
    main_box.set_margin_bottom(40);
    main_box.set_margin_start(40);
    main_box.set_margin_end(40);

    let title = Label::new(Some("Notas"));
    title.add_css_class("lock-title");

    let password_entry = gtk::PasswordEntry::new();
    password_entry.add_css_class("password-entry");
    password_entry.set_show_peek_icon(true);

    // First-time setup (no vault file yet) vs unlocking an existing vault. The
    // strength meter + generator only make sense when CREATING the password, so
    // they appear only on first setup — never when entering an existing one.
    let first_setup = CORE_MANAGER
        .get()
        .map(|m| !m.lock().unwrap().get_data_path().exists())
        .unwrap_or(false);

    let strength_meter: Option<gtk::Box> = if first_setup {
        password_entry.set_placeholder_text(Some("Create a password"));
        Some(make_strength_meter(&password_entry))
    } else {
        password_entry.set_placeholder_text(Some("Password"));
        None
    };

    let status_label = Arc::new(Label::new(None));
    status_label.set_margin_top(12);

    let unlock_button = gtk::Button::with_label(if first_setup { "Create vault" } else { "Unlock" });
    unlock_button.add_css_class("unlock-button");

    let window_clone = window.clone();
    let app_clone = app.clone();
    let status_label_clone = status_label.clone();
    let password_entry_clone = password_entry.clone();

    let do_unlock = move || {
        let password = password_entry_clone.text().to_string();
        if password.is_empty() {
            status_label_clone.set_markup("<span foreground='#a06060'>Password cannot be empty</span>");
            return;
        }

        let manager_rc = CORE_MANAGER.get().unwrap().clone();
        let master_password = core::data::MasterPassword::from(password.as_str());

        let result = manager_rc.lock().unwrap().unlock(master_password);
        match result {
            Ok(_) => {
                window_clone.close();
                show_main_window(&app_clone);
            },
            Err(e) => {
                status_label_clone.set_markup(&format!("<span foreground='#a06060'>{}</span>", e));
            }
        };
    };

    let do_unlock_clone = do_unlock.clone();
    unlock_button.connect_clicked(move |_| {
        do_unlock_clone();
    });

    password_entry.connect_activate(move |_| {
        do_unlock();
    });

    main_box.append(&title);
    main_box.append(&password_entry);
    if let Some(ref meter) = strength_meter {
        main_box.append(meter);
    }
    main_box.append(status_label.as_ref());
    main_box.append(&unlock_button);

    window.set_child(Some(&main_box));
    window.present();
    password_entry.grab_focus();
}

fn show_main_window(app: &Application) {
    let manager_rc = CORE_MANAGER.get().unwrap().clone();

    let window = ApplicationWindow::builder()
        .application(app)
        .title("Notas")
        .default_width(1000)
        .default_height(700)
        .build();
    
    // Create custom header bar
    let header = gtk::HeaderBar::new();
    header.set_show_title_buttons(false);
    header.add_css_class("custom-headerbar");
    
    // Window controls on the right.
    let traffic_buttons = create_traffic_light_buttons(&window);
    header.pack_end(&traffic_buttons);

    // Title in center
    let header_title = Label::new(None);
    header_title.add_css_class("headerbar-title");
    header.set_title_widget(Some(&header_title));
    
    window.set_titlebar(Some(&header));
    
    let motion_controller = gtk::EventControllerMotion::new();
    motion_controller.connect_motion(|_, _, _| {
        reset_activity_timer();
    });
    window.add_controller(motion_controller);

    let paned = gtk::Paned::new(gtk::Orientation::Horizontal);
    paned.set_position(220);
    paned.set_wide_handle(false);

    // Compact sidebar
    let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 0);
    sidebar.set_size_request(140, -1);
    sidebar.add_css_class("sidebar");

    let sidebar_header = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    sidebar_header.add_css_class("sidebar-header");
    
    let app_title = Label::new(Some("Notas"));
    app_title.add_css_class("app-title");
    app_title.set_hexpand(true);
    app_title.set_halign(gtk::Align::Start);
    app_title.set_visible(manager_rc.lock().unwrap().get_settings().show_app_logo);
    
    let header_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 1);
    
    let theme_button = gtk::Button::with_label("◑");
    theme_button.add_css_class("icon-button");
    theme_button.add_css_class("hbtn");
    theme_button.set_tooltip_text(Some("Theme"));

    let settings_button = gtk::Button::with_label("⚙");
    settings_button.add_css_class("icon-button");
    settings_button.add_css_class("hbtn");
    settings_button.set_tooltip_text(Some("Preferences"));

    let lock_button = gtk::Button::with_label("⏻");
    lock_button.add_css_class("icon-button");
    lock_button.add_css_class("hbtn");
    lock_button.add_css_class("glyph-nudge-down");
    lock_button.set_tooltip_text(Some("Lock"));

    header_buttons.append(&theme_button);
    header_buttons.append(&settings_button);
    header_buttons.append(&lock_button);

    // The 3 action buttons now live in the main top bar (to the left of the
    // window controls); the sidebar header keeps only the optional wordmark.
    sidebar_header.append(&app_title);
    header.pack_end(&header_buttons);

    // Top-bar left cluster: ☰ collapse toggle, ▾ note-switcher dropdown, compact +.
    let collapse_button = gtk::Button::with_label("<");
    collapse_button.add_css_class("icon-button");
    collapse_button.add_css_class("hbtn");
    collapse_button.set_tooltip_text(Some("Show / hide the note list"));

    let note_switcher = gtk::DropDown::from_strings(&[]);
    note_switcher.add_css_class("note-switcher");
    note_switcher.set_tooltip_text(Some("Switch note"));
    let switcher_model = note_switcher
        .model()
        .expect("DropDown has a model")
        .downcast::<gtk::StringList>()
        .expect("DropDown::from_strings model is a StringList");
    // note ids in dropdown order, and a guard so programmatic selection changes
    // don't re-trigger a note load.
    let switcher_ids: Rc<RefCell<Vec<u64>>> = Rc::new(RefCell::new(Vec::new()));
    let suppress_switcher: Rc<Cell<bool>> = Rc::new(Cell::new(false));

    let search_entry = gtk::SearchEntry::new();
    search_entry.set_placeholder_text(Some("Search..."));
    search_entry.add_css_class("search-entry");

    // Compact new-note button, now in the top bar rather than a big sidebar bar.
    let new_note_button = gtk::Button::with_label("+");
    new_note_button.add_css_class("icon-button");
    new_note_button.add_css_class("hbtn");
    new_note_button.set_tooltip_text(Some("New note (Ctrl+N)"));

    // ⋮ opens the current note's actions (Copy / Pin / Rename / Export / Delete)
    // — the same menu as right-clicking a row, so the actions are reachable even
    // when the note list is collapsed.
    let more_button = gtk::Button::with_label("⋮");
    more_button.add_css_class("icon-button");
    more_button.add_css_class("hbtn");
    more_button.set_tooltip_text(Some("Note actions"));
    // Greyed out until a note is actually open (a blank editor isn't a saved note
    // yet), so it's clear there's nothing to act on rather than silently no-op'ing.
    more_button.set_sensitive(false);

    // Three buttons grouped, then the note picker (with a small gap before it).
    note_switcher.set_margin_start(6);
    let top_left = gtk::Box::new(gtk::Orientation::Horizontal, 1);
    top_left.append(&collapse_button);
    top_left.append(&more_button);
    top_left.append(&new_note_button);
    top_left.append(&note_switcher);
    header.pack_start(&top_left);

    let note_list_box = Arc::new(gtk::ListBox::new());
    note_list_box.set_selection_mode(gtk::SelectionMode::Single);
    note_list_box.add_css_class("note-list");

    let scrolled_window = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(note_list_box.as_ref())
        .vexpand(true)
        .build();

    sidebar.append(&sidebar_header);
    sidebar.append(&search_entry);
    sidebar.append(&scrolled_window);

    // ☰ collapses / shows the sidebar note list. In minimal mode it starts hidden
    // (the dropdown + compact + in the top bar still let you switch/create notes).
    {
        let sidebar = sidebar.clone();
        let paned = paned.clone();
        collapse_button.connect_clicked(move |btn| {
            let show = !sidebar.get_visible();
            sidebar.set_visible(show);
            // If the divider had been dragged narrow, restore a sane width so the
            // list actually reappears with room to read it.
            if show && paned.position() < 120 {
                paned.set_position(220);
            }
            // Chevron points the way the list will move on the next click.
            btn.set_label(if show { "<" } else { ">" });
        });
    }
    let minimal = manager_rc.lock().unwrap().get_settings().minimal_mode;
    sidebar.set_visible(!minimal);
    collapse_button.set_label(if minimal { ">" } else { "<" });

    let editor_area = gtk::Box::new(gtk::Orientation::Vertical, 0);
    editor_area.add_css_class("editor-area");
    editor_area.set_hexpand(true);
    editor_area.set_size_request(300, -1);

    // The note title is now the first line of the body ("first line = title"), so
    // there is no separate title field in the editor. We keep a hidden, unparented
    // `title_entry` only so the existing references (save flush, focus checks)
    // still compile; it is never shown or edited.
    let title_entry = Arc::new(gtk::Entry::new());
    title_entry.set_visible(false);

    let content_buffer = Arc::new(gtk::TextBuffer::new(None));
    content_buffer.set_enable_undo(true); // Ctrl+Z / Ctrl+Shift+Z in the editor
    let content_view = gtk::TextView::builder()
        .buffer(content_buffer.as_ref())
        .vexpand(true)
        .editable(true)
        .wrap_mode(gtk::WrapMode::Word)
        .left_margin(10)
        .right_margin(10)
        .top_margin(10)
        .bottom_margin(10)
        .build();
    content_view.add_css_class("content-view");
    // (The editor's right-click menu — Find & replace / checklist / password
    // generator — is wired up below, once the find bar exists.)

    // Click a "[ ]" / "[x]" to toggle it. Uses the BUBBLE phase + `released` and
    // never claims the event, so it runs AFTER the editor's own selection / right-
    // click handling and can't disrupt it (the capture-phase version did, causing
    // the cut). Skips entirely when the click produced a selection (a drag), so it
    // can't fire while you're selecting text.
    {
        let view = content_view.clone();
        let buffer = content_buffer.clone();
        let gesture = gtk::GestureClick::new();
        gesture.set_button(gtk::gdk::BUTTON_PRIMARY);
        gesture.connect_released(move |_, n_press, x, y| {
            if n_press != 1 || buffer.has_selection() {
                return;
            }
            let (bx, by) =
                view.window_to_buffer_coords(gtk::TextWindowType::Widget, x as i32, y as i32);
            let Some(iter) = view.iter_at_location(bx, by) else { return };
            let line = iter.line();
            let Some(ls) = buffer.iter_at_line(line) else { return };
            let mut le = ls.clone();
            if !le.ends_line() {
                le.forward_to_line_end();
            }
            let text = buffer.text(&ls, &le, false).to_string();
            let Some(inner) = checkbox_inner_index(&text) else { return };
            let click_off = iter.line_offset() as usize;
            // Only when the click lands on the "[x]" box itself.
            if click_off + 1 < inner || click_off > inner + 1 {
                return;
            }
            let chars: Vec<char> = text.chars().collect();
            let new_char = if chars[inner] == ' ' { "x" } else { " " };
            let (Some(mut a), Some(mut b)) = (
                buffer.iter_at_line_offset(line, inner as i32),
                buffer.iter_at_line_offset(line, inner as i32 + 1),
            ) else {
                return;
            };
            buffer.begin_user_action();
            buffer.delete(&mut a, &mut b);
            if let Some(mut a2) = buffer.iter_at_line_offset(line, inner as i32) {
                buffer.insert(&mut a2, new_char);
            }
            buffer.end_user_action();
        });
        content_view.add_controller(gesture);
    }

    // Remember the most recent non-empty selection via a passive buffer signal
    // (NOT an input gesture — a capture-phase right-click gesture interfered with
    // the editor's selection/DnD and could cut the text). The context-menu
    // transform / copy / count actions use this so they still act on what was
    // selected even after the editor drops the highlight when the menu opens.
    let last_selection: Rc<Cell<Option<(i32, i32)>>> = Rc::new(Cell::new(None));
    {
        let last_sel = last_selection.clone();
        content_buffer.connect_mark_set(move |buf, _iter, _mark| {
            if let Some((s, e)) = buf.selection_bounds() {
                last_sel.set(Some((s.offset(), e.offset())));
            }
        });
    }

    let editor_scrolled_window = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&content_view)
        .vexpand(true)
        .build();

    // ── Markdown live preview (toggle) ──────────────────────────────────────────
    // A read-only rendered view that swaps in over the editor via a Stack. Toggle
    // it from the editor right-click menu ("Markdown preview") or Ctrl+P. Rendering
    // is in-process (markdown_to_pango → Pango markup on a selectable Label); no
    // external renderer dependency. The preview re-renders whenever it's shown and
    // whenever the buffer changes while visible (so a note-switch refreshes it).
    let preview_label = Label::new(None);
    preview_label.set_wrap(true);
    preview_label.set_xalign(0.0);
    preview_label.set_yalign(0.0);
    preview_label.set_selectable(true);
    preview_label.set_margin_top(12);
    preview_label.set_margin_bottom(12);
    preview_label.set_margin_start(14);
    preview_label.set_margin_end(14);
    preview_label.add_css_class("content-view");
    let preview_scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&preview_label)
        .vexpand(true)
        .build();

    let editor_stack = gtk::Stack::new();
    editor_stack.set_vexpand(true);
    editor_stack.add_named(&editor_scrolled_window, Some("edit"));
    editor_stack.add_named(&preview_scrolled, Some("preview"));
    editor_stack.set_visible_child_name("edit");

    // Flip between the editor and the rendered preview.
    let toggle_preview: Rc<dyn Fn()> = {
        let stack = editor_stack.clone();
        let buffer = content_buffer.clone();
        let label = preview_label.clone();
        Rc::new(move || {
            if stack.visible_child_name().as_deref() == Some("preview") {
                stack.set_visible_child_name("edit");
            } else {
                let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
                label.set_markup(&markdown_to_pango(text.as_str()));
                stack.set_visible_child_name("preview");
            }
        })
    };
    // Keep the preview fresh when the buffer changes while it's showing (covers
    // note switches, which replace the buffer text). No-op while editing.
    {
        let stack = editor_stack.clone();
        let label = preview_label.clone();
        content_buffer.connect_changed(move |buf| {
            if stack.visible_child_name().as_deref() == Some("preview") {
                let text = buf.text(&buf.start_iter(), &buf.end_iter(), false);
                label.set_markup(&markdown_to_pango(text.as_str()));
            }
        });
    }

    // In preview mode the editor TextView is hidden, so its right-click menu (the
    // way back to editing) is unreachable and the read-only Label's own "Select
    // All" menu shows instead — trapping the user. Give the preview area its own
    // right-click menu with an "Exit preview" item. Capture-phase + claim so the
    // Label's native menu never shows. (Ctrl+P also still toggles back.)
    {
        let toggle = toggle_preview.clone();
        let area = preview_scrolled.clone();
        let press_xy: Rc<Cell<(f64, f64)>> = Rc::new(Cell::new((0.0, 0.0)));
        let gesture = gtk::GestureClick::new();
        gesture.set_button(gtk::gdk::BUTTON_SECONDARY);
        gesture.set_propagation_phase(gtk::PropagationPhase::Capture);
        {
            let press_xy = press_xy.clone();
            gesture.connect_pressed(move |g, _, x, y| {
                g.set_state(gtk::EventSequenceState::Claimed);
                press_xy.set((x, y));
            });
        }
        gesture.connect_released(move |_, _, _, _| {
            let (x, y) = press_xy.get();
            let pop = gtk::Popover::new();
            pop.set_has_arrow(false);
            let vbox = gtk::Box::new(gtk::Orientation::Vertical, 0);
            vbox.add_css_class("context-menu");
            let btn = gtk::Button::with_label("Exit preview");
            btn.add_css_class("flat");
            btn.add_css_class("menu-item");
            if let Some(c) = btn.child() {
                c.set_halign(gtk::Align::Start);
            }
            let toggle2 = toggle.clone();
            let pop2 = pop.clone();
            btn.connect_clicked(move |_| {
                pop2.popdown();
                toggle2();
            });
            vbox.append(&btn);
            pop.set_child(Some(&vbox));
            pop.set_parent(&area);
            pop.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            pop.connect_closed(|p| p.unparent());
            pop.popup();
        });
        preview_scrolled.add_controller(gesture);
    }

    // Slim status bar: just an auto-fading status line ("Saved ✓", "Copied",
    // "Deleted", …) that's empty most of the time. Saving is automatic and the
    // per-note actions (copy/pin/rename/delete) live in the sidebar right-click
    // menu, so there are no buttons here.
    let status_bar = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    status_bar.add_css_class("status-bar");

    let status_label = Arc::new(Label::new(Some("")));
    status_label.add_css_class("status-text");
    status_label.set_hexpand(true);
    status_label.set_halign(gtk::Align::Start);

    // Right-aligned live word & character count for the open note's body.
    let word_count_label = Arc::new(Label::new(Some("")));
    word_count_label.add_css_class("status-text");
    word_count_label.add_css_class("word-count");
    word_count_label.set_halign(gtk::Align::End);
    word_count_label.set_visible(SHOW_WORD_COUNT.with(|s| *s.borrow()));

    status_bar.append(status_label.as_ref());
    status_bar.append(word_count_label.as_ref());

    editor_area.append(&editor_stack);
    editor_area.append(&status_bar);

    // ── Find & replace bar (toggled with Ctrl+H), prepended above the editor ──
    let find_bar = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    find_bar.add_css_class("find-bar");
    find_bar.set_visible(false);
    let find_entry = gtk::SearchEntry::new();
    find_entry.set_placeholder_text(Some("Find"));
    find_entry.set_hexpand(true);
    let prev_btn = gtk::Button::with_label("‹");
    prev_btn.set_tooltip_text(Some("Previous match (Shift+Ctrl+G)"));
    let next_btn = gtk::Button::with_label("›");
    next_btn.set_tooltip_text(Some("Next match (Enter)"));
    let replace_entry = gtk::Entry::new();
    replace_entry.set_placeholder_text(Some("Replace with"));
    replace_entry.set_hexpand(true);
    let replace_btn = gtk::Button::with_label("Replace");
    let replace_all_btn = gtk::Button::with_label("All");
    let find_close_btn = gtk::Button::with_label("×");
    find_close_btn.set_tooltip_text(Some("Close (Esc)"));
    find_bar.append(&find_entry);
    find_bar.append(&prev_btn);
    find_bar.append(&next_btn);
    find_bar.append(&replace_entry);
    find_bar.append(&replace_btn);
    find_bar.append(&replace_all_btn);
    find_bar.append(&find_close_btn);
    editor_area.prepend(&find_bar);

    // Select the next/previous match (case-insensitive, wrapping).
    let do_find: Rc<dyn Fn(bool)> = {
        let buffer = content_buffer.clone();
        let view = content_view.clone();
        let find_entry = find_entry.clone();
        Rc::new(move |forward: bool| {
            let query = find_entry.text().to_string();
            if query.is_empty() {
                return;
            }
            let flags = gtk::TextSearchFlags::CASE_INSENSITIVE | gtk::TextSearchFlags::TEXT_ONLY;
            let cursor = buffer.iter_at_offset(buffer.cursor_position());
            let (from_fwd, from_bwd) = match buffer.selection_bounds() {
                Some((s, e)) => (e, s),
                None => (cursor.clone(), cursor),
            };
            let found = if forward {
                from_fwd
                    .forward_search(&query, flags, None)
                    .or_else(|| buffer.start_iter().forward_search(&query, flags, None))
            } else {
                from_bwd
                    .backward_search(&query, flags, None)
                    .or_else(|| buffer.end_iter().backward_search(&query, flags, None))
            };
            if let Some((mstart, mend)) = found {
                buffer.select_range(&mstart, &mend);
                view.scroll_to_iter(&mut mstart.clone(), 0.1, false, 0.0, 0.0);
            }
        })
    };
    {
        let f = do_find.clone();
        next_btn.connect_clicked(move |_| f(true));
    }
    {
        let f = do_find.clone();
        prev_btn.connect_clicked(move |_| f(false));
    }
    {
        let f = do_find.clone();
        find_entry.connect_search_changed(move |_| f(true));
    }
    {
        let f = do_find.clone();
        find_entry.connect_next_match(move |_| f(true));
    }
    {
        let f = do_find.clone();
        find_entry.connect_previous_match(move |_| f(false));
    }
    // Replace the current match (if the selection equals the query), then advance.
    {
        let buffer = content_buffer.clone();
        let find_entry = find_entry.clone();
        let replace_entry = replace_entry.clone();
        let f = do_find.clone();
        replace_btn.connect_clicked(move |_| {
            let query = find_entry.text().to_string();
            if query.is_empty() {
                return;
            }
            if let Some((mut s, mut e)) = buffer.selection_bounds() {
                let sel = buffer.text(&s, &e, false).to_string();
                if sel.eq_ignore_ascii_case(&query) {
                    let repl = replace_entry.text().to_string();
                    buffer.begin_user_action();
                    buffer.delete(&mut s, &mut e);
                    buffer.insert(&mut s, &repl);
                    buffer.end_user_action();
                }
            }
            f(true);
        });
    }
    // Replace every match.
    {
        let buffer = content_buffer.clone();
        let find_entry = find_entry.clone();
        let replace_entry = replace_entry.clone();
        replace_all_btn.connect_clicked(move |_| {
            let query = find_entry.text().to_string();
            if query.is_empty() {
                return;
            }
            let repl = replace_entry.text().to_string();
            let flags = gtk::TextSearchFlags::CASE_INSENSITIVE | gtk::TextSearchFlags::TEXT_ONLY;
            buffer.begin_user_action();
            let mut search_from = buffer.start_iter();
            let mut guard = 0;
            while let Some((s, e)) = search_from.forward_search(&query, flags, None) {
                let mut a = s;
                let mut b = e;
                buffer.delete(&mut a, &mut b);
                buffer.insert(&mut a, &repl);
                search_from = a; // continue past the replacement (avoids re-matching)
                guard += 1;
                if guard > 100_000 {
                    break;
                }
            }
            buffer.end_user_action();
        });
    }
    {
        let find_bar = find_bar.clone();
        let view = content_view.clone();
        find_close_btn.connect_clicked(move |_| {
            find_bar.set_visible(false);
            view.grab_focus();
        });
    }

    // Editor right-click menu: Find & replace, Insert…, Generate…, Transform…, etc.
    attach_note_context_menu(&content_view, &content_buffer, &find_bar, &find_entry, &status_label, &last_selection, toggle_preview.clone());

    // Apply any saved custom editor text colour (display-wide CSS override).
    apply_editor_text_color(
        manager_rc.lock().unwrap().get_settings().editor_text_color.as_deref(),
    );

    paned.set_start_child(Some(&sidebar));
    paned.set_end_child(Some(&editor_area));
    paned.set_resize_start_child(true);
    // Do NOT allow the sidebar to shrink below its min width by dragging — that
    // let the user drag it to nothing and lose it with no way back. Hiding is now
    // done explicitly with the ☰ button / Minimal mode.
    paned.set_shrink_start_child(false);
    paned.set_resize_end_child(true);
    paned.set_shrink_end_child(false);

    window.set_child(Some(&paned));

    let active_note_id = Arc::new(Mutex::new(None::<u64>));
    let row_ids: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    // note id -> its sidebar title Label, so we can update a note's displayed
    // title in place as the user types (first line = title) without rebuilding
    // the list (a rebuild + reselect would reset the editor cursor).
    let row_title_labels: Rc<RefCell<HashMap<u64, gtk::Label>>> = Rc::new(RefCell::new(HashMap::new()));
    let search_text: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    // Set to true just before select_row on a newly created note so the
    // row_selected handler doesn't overwrite the blank title entry with "Untitled".
    let skip_next_load: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    // Set to true whenever we programmatically clear the editor (new note, delete,
    // row selection) so connect_changed doesn't mistake it for the user typing and
    // spawn a phantom "Untitled" note.
    let suppress_auto_create: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    // True when the editor has unsaved edits. Each save re-encrypts the WHOLE
    // vault (Argon2 + 3-layer cascade), so we only do it when something actually
    // changed — otherwise every note-switch would pay that cost for nothing,
    // which is what made switching feel slow.
    let dirty: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    // Persist the currently-active note's editor contents synchronously, without
    // refreshing the sidebar list (so it never flickers / loses selection while
    // typing). Returns Ok(true) only when it actually wrote. No-ops instantly
    // when nothing's dirty. This is the single save path: the debounce timer
    // calls it after typing pauses, and note-switch / new-note / lock flush it.
    let save_active = {
        let manager_rc = manager_rc.clone();
        let active_note_id = active_note_id.clone();
        let content_buffer = content_buffer.clone();
        let dirty = dirty.clone();
        move || -> Result<bool, String> {
            if !*dirty.lock().unwrap() {
                return Ok(false);
            }
            let id_opt = *active_note_id.lock().unwrap();
            let Some(id) = id_opt else {
                *dirty.lock().unwrap() = false;
                return Ok(false);
            };
            let content = content_buffer
                .text(&content_buffer.start_iter(), &content_buffer.end_iter(), false)
                .to_string();
            // First line of the body is the title.
            let title = derive_title(&content);
            let result = manager_rc
                .lock()
                .unwrap()
                .update_note(id, title, content, None)
                .map(|_| true)
                .map_err(|e| e.to_string());
            if result.is_ok() {
                *dirty.lock().unwrap() = false;
            }
            result
        }
    };

    // Dispatcher for the sidebar right-click actions (copy/pin/rename/delete),
    // populated once it and refresh_note_list both exist. Rows reference it
    // through this shared cell, so it's fine that it's empty at first render —
    // the menu is only consulted on click, long after it's filled in.
    let action_holder: Rc<RefCell<Option<Rc<dyn Fn(&str, u64)>>>> = Rc::new(RefCell::new(None));

    let refresh_note_list = {
        let note_list_box = note_list_box.clone();
        let manager_rc = manager_rc.clone();
        let row_ids = row_ids.clone();
        let row_title_labels = row_title_labels.clone();
        let search_text = search_text.clone();
        let action_holder = action_holder.clone();
        let switcher_model = switcher_model.clone();
        let switcher_ids = switcher_ids.clone();
        let suppress_switcher = suppress_switcher.clone();
        let note_switcher = note_switcher.clone();
        let active_note_id = active_note_id.clone();

        move || {
            while let Some(child) = note_list_box.first_child() {
                note_list_box.remove(&child);
            }
            row_ids.lock().unwrap().clear();
            row_title_labels.borrow_mut().clear();
            // Titles for the top-bar dropdown, collected in the same (filtered)
            // order as the list rows so the two stay index-aligned.
            let mut switcher_titles: Vec<String> = Vec::new();

            let notes = manager_rc.lock().unwrap().get_notes();
            let search = search_text.lock().unwrap().to_lowercase();

            for note in notes {
                if !search.is_empty() {
                    let title_lower = note.title.to_lowercase();
                    let content_lower = note.content.to_lowercase();
                    if !title_lower.contains(&search) && !content_lower.contains(&search) {
                        continue;
                    }
                }
                
                let row = ListBoxRow::new();
                let row_box = gtk::Box::new(gtk::Orientation::Vertical, 1);
                row_box.set_margin_top(2);
                row_box.set_margin_bottom(2);

                let title_box = gtk::Box::new(gtk::Orientation::Horizontal, 4);
                
                if note.pinned {
                    let pin_icon = Label::new(Some("●"));
                    pin_icon.add_css_class("note-pinned");
                    title_box.append(&pin_icon);
                }
                
                // Title = first line of the body. Show "Untitled" for an as-yet
                // empty note so the row isn't blank.
                let display_title = if note.title.trim().is_empty() {
                    "Untitled".to_string()
                } else {
                    note.title.clone()
                };
                let title_label = Label::new(Some(&display_title));
                title_label.set_halign(gtk::Align::Start);
                title_label.add_css_class("note-title");
                title_label.set_ellipsize(gtk::pango::EllipsizeMode::End);
                title_label.set_hexpand(true);
                title_box.append(&title_label);
                // Remember this label so typing can update the title live.
                row_title_labels.borrow_mut().insert(note.id, title_label.clone());
                switcher_titles.push(display_title.clone());

                let date_label = Label::new(Some(&note.updated_at.format("%b %d, %Y").to_string()));
                date_label.set_halign(gtk::Align::Start);
                date_label.add_css_class("note-date");

                row_box.append(&title_box);
                // Privacy: the preview is omitted entirely when the "Show note
                // previews" setting is off (the row never builds it). It shows the
                // line after the title so it doesn't just repeat the title.
                if SHOW_NOTE_PREVIEWS.with(|s| *s.borrow()) {
                    let preview = derive_preview(&note.content);
                    let preview_label = Label::new(Some(&preview));
                    preview_label.set_halign(gtk::Align::Start);
                    preview_label.add_css_class("note-preview");
                    preview_label.set_ellipsize(gtk::pango::EllipsizeMode::End);
                    row_box.append(&preview_label);
                }
                row_box.append(&date_label);

                row.set_child(Some(&row_box));

                // Right-click → context menu (Copy / Pin / Rename / Delete).
                let note_id = note.id;
                let note_pinned = note.pinned;
                let menu_gesture = gtk::GestureClick::new();
                menu_gesture.set_button(gtk::gdk::BUTTON_SECONDARY);
                let action_holder_for_row = action_holder.clone();
                let row_for_menu = row.clone();
                menu_gesture.connect_pressed(move |g, _, x, y| {
                    g.set_state(gtk::EventSequenceState::Claimed);
                    let popover = build_row_menu(&action_holder_for_row, note_id, note_pinned, false);
                    popover.set_parent(&row_for_menu);
                    popover.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
                    popover.connect_closed(|p| p.unparent());
                    popover.popup();
                });
                row.add_controller(menu_gesture);

                note_list_box.append(&row);
                row_ids.lock().unwrap().push(note.id);
            }
            note_list_box.show();

            // Rebuild the top-bar note-switcher to match the (filtered) list, then
            // point it at the active note. Guarded so the selection change here
            // doesn't trigger a note load.
            suppress_switcher.set(true);
            let strs: Vec<&str> = switcher_titles.iter().map(|s| s.as_str()).collect();
            switcher_model.splice(0, switcher_model.n_items(), &strs);
            *switcher_ids.borrow_mut() = row_ids.lock().unwrap().clone();
            // Point the dropdown at the active note, or deselect (u32::MAX =
            // GTK_INVALID_LIST_POSITION) when nothing is open, so it doesn't
            // misleadingly show note #0.
            let active_pos = active_note_id
                .lock()
                .unwrap()
                .and_then(|active| switcher_ids.borrow().iter().position(|&x| x == active));
            note_switcher.set_selected(active_pos.map(|p| p as u32).unwrap_or(u32::MAX));
            suppress_switcher.set(false);
        }
    };

    refresh_note_list();

    let refresh_clone = refresh_note_list.clone();
    let search_text_clone = search_text.clone();
    search_entry.connect_search_changed(move |entry| {
        *search_text_clone.lock().unwrap() = entry.text().to_string();
        refresh_clone();
    });

    let manager_clone = manager_rc.clone();
    theme_button.connect_clicked(move |btn| {
        // Open the full theme picker (all built-in themes + palettes).
        let popover = build_theme_picker(manager_clone.clone());
        popover.set_parent(btn);
        popover.connect_closed(|p| p.unparent());
        popover.popup();
    });

    let window_clone = window.clone();
    let app_clone = app.clone();
    let save_on_lock = save_active.clone();
    lock_button.connect_clicked(move |_| {
        // Flush the active note before locking (synchronous, so it completes
        // before the vault is sealed and the window closes).
        let _ = save_on_lock();
        let manager_rc = CORE_MANAGER.get().unwrap().clone();
        manager_rc.lock().unwrap().lock();
        window_clone.close();
        show_password_screen(&app_clone);
    });

    let window_clone = window.clone();
    let manager_clone = manager_rc.clone();
    let status_clone = status_label.clone();
    let app_title_for_prefs = app_title.clone();
    let refresh_for_prefs = refresh_note_list.clone();
    let word_count_for_prefs = word_count_label.clone();
    let content_buffer_for_prefs = content_buffer.clone();
    let sidebar_for_prefs = sidebar.clone();
    settings_button.connect_clicked(move |_| {
        show_preferences_dialog(&window_clone, manager_clone.clone(), status_clone.clone(), app_title_for_prefs.clone(), word_count_for_prefs.clone(), content_buffer_for_prefs.clone(), sidebar_for_prefs.clone(), refresh_for_prefs.clone());
    });

    // Auto-create a note if the user starts typing directly into the editor
    // without clicking "+ New Note" first. Without this, the save button stays
    // greyed out and the user's text has nowhere to go.
    let auto_create = {
        let manager_rc = manager_rc.clone();
        let active_note_id = active_note_id.clone();
        let status_label = status_label.clone();
        let note_list_box = note_list_box.clone();
        let skip_next_load = skip_next_load.clone();
        let suppress_auto_create = suppress_auto_create.clone();
        let refresh = refresh_note_list.clone();
        let content_buffer = content_buffer.clone();
        move || {
            // Don't fire if we're programmatically clearing the editor
            if *suppress_auto_create.lock().unwrap() {
                return;
            }
            // Only fire if there is no active note.
            if active_note_id.lock().unwrap().is_some() {
                return;
            }
            // Only create once the editor genuinely has something in it. A
            // spurious empty `changed` — focus/IME, or the buffer being cleared
            // when the window tears down on close — must NOT spawn a blank
            // "Untitled" note (that was the phantom-notes bug).
            if content_buffer.char_count() == 0 {
                return;
            }
            // Create the note SYNCHRONOUSLY and set active_note_id before this
            // call returns. Doing it async let rapid keystrokes race — each
            // keystroke saw active_note_id == None (the previous create hadn't
            // landed yet) and spawned another "Untitled" note.
            let new_id = match manager_rc
                .lock()
                .unwrap()
                .create_note("Untitled".to_string(), String::new())
            {
                Ok(id) => id,
                Err(e) => {
                    status_label.set_text(&format!("Error: {}", e));
                    return;
                }
            };
            *active_note_id.lock().unwrap() = Some(new_id);
            status_label.set_text("");
            refresh();
            // Tell row_selected not to overwrite the editor with the blank note.
            *skip_next_load.lock().unwrap() = true;
            if let Some(row) = note_list_box.row_at_index(0) {
                note_list_box.select_row(Some(&row));
            }
        }
    };

    // Debounced autosave: each edit (re)arms a 700ms timer; when typing pauses it
    // saves the active note and flashes "Saved ✓". Skipped while we're
    // programmatically rewriting the editor (load/clear), same as auto_create.
    // Asynchronous active-note save, used by the debounce timer only. The cascade
    // re-runs Argon2 on every save (fresh salt); at the default Paranoid strength
    // that's ~1.3s, so a synchronous save would freeze the UI each time typing
    // pauses. Instead we snapshot the editor on the main thread (gtk types are
    // !Send), clear `dirty` optimistically, and re-encrypt on a blocking thread.
    // If the user keeps typing during the save, the new edits re-set `dirty` and
    // the next debounce captures them; on error we restore `dirty` to retry.
    let save_active_async = {
        let manager_rc = manager_rc.clone();
        let active_note_id = active_note_id.clone();
        let content_buffer = content_buffer.clone();
        let dirty = dirty.clone();
        let status_label = status_label.clone();
        move || {
            if !*dirty.lock().unwrap() {
                return;
            }
            let id = match *active_note_id.lock().unwrap() {
                Some(id) => id,
                None => {
                    *dirty.lock().unwrap() = false;
                    return;
                }
            };
            let content = content_buffer
                .text(&content_buffer.start_iter(), &content_buffer.end_iter(), false)
                .to_string();
            // First line of the body is the title.
            let title = derive_title(&content);
            // Optimistically mark clean; a concurrent edit re-dirties it, and a
            // failed save below restores it.
            *dirty.lock().unwrap() = false;

            let manager_for_task = manager_rc.clone();
            let dirty_for_result = dirty.clone();
            let status_for_result = status_label.clone();
            let (sender, receiver) = async_channel::unbounded();
            let runtime = TOKIO_RUNTIME.get().unwrap();
            glib::spawn_future_local(async move {
                let _guard = runtime.enter();
                let result = tokio::task::spawn_blocking(move || {
                    manager_for_task.lock().unwrap().update_note(id, title, content, None)
                }).await;
                let _ = sender.send(result).await;
            });
            glib::spawn_future_local(async move {
                if let Ok(result) = receiver.recv().await {
                    match result {
                        Ok(Ok(())) => flash_saved(&status_for_result),
                        Ok(Err(e)) => {
                            *dirty_for_result.lock().unwrap() = true;
                            status_for_result.set_text(&format!("Error: {}", e));
                        }
                        Err(e) => {
                            *dirty_for_result.lock().unwrap() = true;
                            status_for_result.set_text(&format!("Error: {}", e));
                        }
                    }
                }
            });
        }
    };

    let schedule_autosave = {
        let save_active_async = save_active_async.clone();
        let suppress = suppress_auto_create.clone();
        let dirty = dirty.clone();
        move || {
            if *suppress.lock().unwrap() {
                return;
            }
            // A genuine user edit — mark unsaved so the next save actually writes.
            *dirty.lock().unwrap() = true;
            let save_active_async = save_active_async.clone();
            AUTOSAVE_TIMER.with(|cell| {
                if let Some(old) = cell.borrow_mut().take() {
                    old.remove();
                }
                let id = glib::timeout_add_local_once(Duration::from_millis(700), move || {
                    AUTOSAVE_TIMER.with(|c| *c.borrow_mut() = None);
                    save_active_async();
                });
                *cell.borrow_mut() = Some(id);
            });
        }
    };

    // (The old separate title field is gone — title = first line of the body —
    // so there is no title `connect_changed` hook anymore.)

    // Update the active note's sidebar title label in place as the user types.
    // This is the live-title fix: previously the row title only refreshed on a
    // full rebuild (note switch / lock+reopen), so a freshly typed title looked
    // stale. We touch only the one Label (no list rebuild → no cursor reset).
    let update_active_title = {
        let row_title_labels = row_title_labels.clone();
        let active_note_id = active_note_id.clone();
        let content_buffer = content_buffer.clone();
        let suppress_auto_create = suppress_auto_create.clone();
        let switcher_model = switcher_model.clone();
        let switcher_ids = switcher_ids.clone();
        let suppress_switcher = suppress_switcher.clone();
        let note_switcher = note_switcher.clone();
        move || {
            // Skip programmatic edits (note load/clear): `active_note_id` may not
            // be updated yet, so we could clobber the wrong note's label. The row
            // is already correct from the refresh in those cases.
            if *suppress_auto_create.lock().unwrap() {
                return;
            }
            let Some(id) = *active_note_id.lock().unwrap() else { return };
            let content = content_buffer
                .text(&content_buffer.start_iter(), &content_buffer.end_iter(), false);
            let title = derive_title(&content);
            if let Some(label) = row_title_labels.borrow().get(&id) {
                label.set_text(&title);
            }
            // Keep the dropdown's label for this note in sync as we type.
            let pos = switcher_ids.borrow().iter().position(|&x| x == id);
            if let Some(pos) = pos {
                suppress_switcher.set(true);
                switcher_model.splice(pos as u32, 1, &[title.as_str()]);
                note_switcher.set_selected(pos as u32);
                suppress_switcher.set(false);
            }
        }
    };

    // Recompute the editor body's word & character count. Cheap, so it runs on
    // every content change — both user edits and programmatic note loads/clears,
    // since `set_text` also fires `connect_changed`. That single hook covers
    // load / switch / new / delete without separate wiring.
    let update_word_count = {
        let word_count_label = word_count_label.clone();
        let content_buffer = content_buffer.clone();
        move || {
            let text = content_buffer
                .text(&content_buffer.start_iter(), &content_buffer.end_iter(), false);
            let words = text.split_whitespace().count();
            let chars = text.chars().count();
            word_count_label.set_text(&format!("{} words · {} chars", words, chars));
        }
    };
    update_word_count(); // initialise for the (empty) editor at startup

    let auto_create_for_content = auto_create.clone();
    let schedule_autosave_content = schedule_autosave.clone();
    let update_word_count_for_content = update_word_count.clone();
    let update_active_title_for_content = update_active_title.clone();
    content_buffer.connect_changed(move |buf| {
        auto_create_for_content();
        schedule_autosave_content();
        update_word_count_for_content();
        // Live-update the sidebar title (first line = title). Runs after
        // auto_create so a just-created note's row already exists in the map.
        update_active_title_for_content();
        // Re-paint rainbow colours when enabled (covers typing and note loads,
        // since set_text also fires `changed`). Skipped entirely when off so we
        // don't scan tags on every keystroke; disabling clears them once in prefs.
        if RAINBOW_TEXT.with(|r| *r.borrow()) {
            apply_rainbow(buf, true);
        }
    });

    let save_active_for_row = save_active.clone();
    note_list_box.connect_row_selected(glib::clone!(@strong manager_rc, @strong title_entry,
        @strong content_buffer,
        @strong active_note_id, @strong status_label, @strong row_ids, @strong skip_next_load,
        @strong suppress_auto_create, @strong note_switcher, @strong switcher_ids,
        @strong suppress_switcher, @strong more_button => move |_, row_opt| {
        if let Some(row) = row_opt {
            let idx = row.index();
            if idx >= 0 {
                let id_opt = row_ids.lock().unwrap().get(idx as usize).copied();
                if let Some(id) = id_opt {
                    let skip = {
                        let mut guard = skip_next_load.lock().unwrap();
                        let val = *guard;
                        *guard = false;
                        val
                    };
                    if skip {
                        *active_note_id.lock().unwrap() = Some(id);
                        status_label.set_text("");
                    } else {
                        // Flush the outgoing note before loading the selected one
                        // (covers edits made in the last <700ms before switching),
                        // and drop any pending debounce so it can't re-fire after.
                        let prev = *active_note_id.lock().unwrap();
                        if prev.map_or(false, |p| p != id) {
                            let _ = save_active_for_row();
                        }
                        AUTOSAVE_TIMER.with(|c| {
                            if let Some(t) = c.borrow_mut().take() { t.remove(); }
                        });
                        let note_opt = manager_rc.lock().unwrap().get_notes().into_iter().find(|n| n.id == id);
                        if let Some(note) = note_opt {
                            *suppress_auto_create.lock().unwrap() = true;
                            title_entry.set_text(&note.title);
                            // Irreversible so Ctrl+Z can't undo across a note load.
                            content_buffer.begin_irreversible_action();
                            content_buffer.set_text(&note.content);
                            content_buffer.end_irreversible_action();
                            *suppress_auto_create.lock().unwrap() = false;
                            *active_note_id.lock().unwrap() = Some(id);
                            status_label.set_text("");
                        }
                    }
                    // Keep the top-bar note-switcher dropdown pointing at the
                    // active note (guarded so it doesn't re-trigger this handler).
                    suppress_switcher.set(true);
                    let pos = switcher_ids.borrow().iter().position(|&x| x == id);
                    if let Some(pos) = pos {
                        note_switcher.set_selected(pos as u32);
                    }
                    suppress_switcher.set(false);
                    // A note is open → the actions (⋮) button is usable.
                    more_button.set_sensitive(true);
                }
            }
        }
        // NOTE: We intentionally do NOT clear active_note_id when row_opt is None,
        // because this can happen when focus moves to the paned resize handle or
        // other widgets. The active note should persist until explicitly changed
        // (new note, delete, or selecting another note).
    }));

    // Top-bar dropdown → switch note. It drives the list selection (which runs
    // the load logic above), so there's a single source of truth. Guarded so our
    // own programmatic selection changes (refresh / row-select sync) don't loop.
    {
        let switcher_ids = switcher_ids.clone();
        let suppress_switcher = suppress_switcher.clone();
        let note_list_box = note_list_box.clone();
        let row_ids = row_ids.clone();
        note_switcher.connect_selected_notify(move |dd| {
            if suppress_switcher.get() {
                return;
            }
            let idx = dd.selected() as usize;
            let id = switcher_ids.borrow().get(idx).copied();
            if let Some(id) = id {
                let pos = row_ids.lock().unwrap().iter().position(|&x| x == id);
                if let Some(pos) = pos {
                    if let Some(row) = note_list_box.row_at_index(pos as i32) {
                        note_list_box.select_row(Some(&row));
                    }
                }
            }
        });
    }

    let refresh_clone = refresh_note_list.clone();
    let save_active_for_new = save_active.clone();
    new_note_button.connect_clicked(glib::clone!(@strong manager_rc, @strong title_entry,
        @strong content_buffer, @strong active_note_id, @strong note_list_box,
        @strong status_label, @strong skip_next_load, @strong more_button,
        @strong suppress_auto_create => move |_| {

        // Persist the current note before starting a new one.
        let _ = save_active_for_new();

        // Suppress connect_changed during programmatic clear so no phantom note is created
        *suppress_auto_create.lock().unwrap() = true;
        title_entry.set_text("");
        content_buffer.begin_irreversible_action();
        content_buffer.set_text("");
        content_buffer.end_irreversible_action();
        *suppress_auto_create.lock().unwrap() = false;

        *active_note_id.lock().unwrap() = None;
        // No active note during the brief async-create window; re-enabled by
        // row_selected once the new note loads.
        more_button.set_sensitive(false);

        let manager_clone = manager_rc.clone();
        let status_clone = status_label.clone();
        let refresh = refresh_clone.clone();
        let list_box = note_list_box.clone();
        let skip_flag = skip_next_load.clone();

        status_label.set_text("Creating...");

        let (sender, receiver) = async_channel::unbounded();
        let runtime = TOKIO_RUNTIME.get().unwrap();
        
        let manager_for_task = manager_clone.clone();
        glib::spawn_future_local(async move {
            let _guard = runtime.enter();
            let result = tokio::task::spawn_blocking(move || {
                manager_for_task.lock().unwrap().create_note("Untitled".to_string(), String::new())
            }).await;
            let _ = sender.send(result).await;
        });

        glib::spawn_future_local(async move {
            if let Ok(result) = receiver.recv().await {
                match result {
                    Ok(Ok(new_id)) => {
                        status_clone.set_text("New note");
                        refresh();
                        // Set the flag BEFORE select_row so row_selected knows
                        // not to overwrite the blank title entry with "Untitled".
                        *skip_flag.lock().unwrap() = true;
                        if let Some(row) = list_box.row_at_index(0) {
                            list_box.select_row(Some(&row));
                        }
                        // active_note_id is set inside row_selected when skip is true,
                        // but set it here too as a safety net in case select_row
                        // doesn't fire (e.g. row was already selected).
                        // The row_selected handler will overwrite this with the same value.
                        let _ = new_id; // used via skip path in row_selected
                    },
                    Ok(Err(e)) => status_clone.set_text(&format!("Error: {}", e)),
                    Err(e) => status_clone.set_text(&format!("Error: {}", e)),
                }
            }
        });
    }));

    // Per-note action dispatcher used by the sidebar right-click menu and the
    // keyboard Delete shortcut. Handles Copy / Pin / Rename / Delete by note id.
    let note_action: Rc<dyn Fn(&str, u64)> = {
        let manager_rc = manager_rc.clone();
        let active_note_id = active_note_id.clone();
        let title_entry = title_entry.clone();
        let content_buffer = content_buffer.clone();
        let status_label = status_label.clone();
        let suppress_auto_create = suppress_auto_create.clone();
        let refresh = refresh_note_list.clone();
        let window = window.clone();
        let more_button = more_button.clone();
        let find_bar = find_bar.clone();
        let find_entry = find_entry.clone();
        Rc::new(move |action: &str, id: u64| {
            match action {
                "find" => {
                    find_bar.set_visible(true);
                    find_entry.grab_focus();
                }
                "copy" => {
                    let content = manager_rc
                        .lock()
                        .unwrap()
                        .get_notes()
                        .into_iter()
                        .find(|n| n.id == id)
                        .map(|n| n.content);
                    if let (Some(content), Some(display)) =
                        (content, gtk::gdk::Display::default())
                    {
                        display.clipboard().set_text(&content);
                        status_label.set_text("Copied");
                        // Re-arm the clipboard auto-clear (the security feature the
                        // old Copy button provided).
                        let timeout = manager_rc.lock().unwrap().get_settings().clipboard_timeout;
                        if timeout > 0 {
                            CLIPBOARD_TIMER.with(|c| {
                                if let Some(o) = c.borrow_mut().take() { o.remove(); }
                            });
                            let status_for_timer = status_label.clone();
                            let tid = glib::timeout_add_seconds_local(timeout as u32, move || {
                                if let Some(d) = gtk::gdk::Display::default() {
                                    d.clipboard().set_text("");
                                }
                                status_for_timer.set_text("Clipboard cleared");
                                CLIPBOARD_TIMER.with(|c| *c.borrow_mut() = None);
                                glib::ControlFlow::Break
                            });
                            CLIPBOARD_TIMER.with(|c| *c.borrow_mut() = Some(tid));
                        }
                    }
                }
                "pin" => {
                    let _ = manager_rc.lock().unwrap().toggle_pin(id);
                    refresh();
                }
                "rename" => {
                    show_rename_dialog(
                        &window,
                        manager_rc.clone(),
                        id,
                        active_note_id.clone(),
                        title_entry.clone(),
                        refresh.clone(),
                    );
                }
                "export" => {
                    let note = manager_rc
                        .lock()
                        .unwrap()
                        .get_notes()
                        .into_iter()
                        .find(|n| n.id == id);
                    if let Some(note) = note {
                        let chooser = gtk::FileChooserDialog::new(
                            Some("Export note as .txt"),
                            Some(&window),
                            gtk::FileChooserAction::Save,
                            &[
                                ("Cancel", gtk::ResponseType::Cancel),
                                ("Export", gtk::ResponseType::Accept),
                            ],
                        );
                        chooser.set_current_name(&format!("{}.txt", sanitize_filename(&note.title)));
                        let status_label = status_label.clone();
                        chooser.connect_response(move |chooser, response| {
                            if response == gtk::ResponseType::Accept {
                                if let Some(path) = chooser.file().and_then(|f| f.path()) {
                                    match std::fs::write(
                                        &path,
                                        note_to_txt(&note.title, &note.content),
                                    ) {
                                        Ok(_) => status_label
                                            .set_text(&format!("Exported: {}", path.display())),
                                        Err(e) => status_label
                                            .set_text(&format!("Error: {}", e)),
                                    }
                                }
                            }
                            chooser.close();
                        });
                        chooser.show();
                    }
                }
                "delete" => {
                    let dialog = adw::MessageDialog::new(
                        Some(&window),
                        Some("Delete note?"),
                        Some("This permanently deletes the note. This can't be undone."),
                    );
                    dialog.add_responses(&[("cancel", "Cancel"), ("delete", "Delete")]);
                    dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
                    dialog.set_default_response(Some("cancel"));
                    dialog.set_close_response("cancel");
                    let manager_rc = manager_rc.clone();
                    let active_note_id = active_note_id.clone();
                    let title_entry = title_entry.clone();
                    let content_buffer = content_buffer.clone();
                    let status_label = status_label.clone();
                    let suppress = suppress_auto_create.clone();
                    let refresh = refresh.clone();
                    let more_button = more_button.clone();
                    dialog.connect_response(None, move |_, resp| {
                        if resp != "delete" {
                            return;
                        }
                        let _ = manager_rc.lock().unwrap().delete_note(id);
                        // If the deleted note was open in the editor, clear it.
                        if *active_note_id.lock().unwrap() == Some(id) {
                            *suppress.lock().unwrap() = true;
                            title_entry.set_text("");
                            content_buffer.begin_irreversible_action();
                            content_buffer.set_text("");
                            content_buffer.end_irreversible_action();
                            *suppress.lock().unwrap() = false;
                            *active_note_id.lock().unwrap() = None;
                            // No note open now → grey out the actions button.
                            more_button.set_sensitive(false);
                        }
                        status_label.set_text("Deleted");
                        refresh();
                    });
                    dialog.present();
                }
                _ => {}
            }
        })
    };
    *action_holder.borrow_mut() = Some(note_action.clone());

    // Top-bar ⋮ → the active note's action menu (works when the list is hidden).
    {
        let active_note_id = active_note_id.clone();
        let action_holder = action_holder.clone();
        let manager_rc = manager_rc.clone();
        more_button.connect_clicked(move |btn| {
            let Some(id) = *active_note_id.lock().unwrap() else {
                return;
            };
            let pinned = manager_rc
                .lock()
                .unwrap()
                .get_notes()
                .iter()
                .find(|n| n.id == id)
                .map(|n| n.pinned)
                .unwrap_or(false);
            let popover = build_row_menu(&action_holder, id, pinned, true);
            popover.set_parent(btn);
            popover.connect_closed(|p| p.unparent());
            popover.popup();
        });
    }

    // Window-level keyboard shortcuts:
    //   Ctrl+N  new note        Ctrl+F  focus search
    //   Ctrl+L / Esc  lock      Delete  delete active note (when editor unfocused)
    // The lock/new shortcuts route through the existing buttons via emit_clicked,
    // so they reuse the exact save-flush + lock / create paths.
    let key_controller = gtk::EventControllerKey::new();
    let note_action_key = note_action.clone();
    let active_note_id_for_key = active_note_id.clone();
    let title_entry_for_key = title_entry.clone();
    let content_view_clone = content_view.clone();
    let new_note_button_for_key = new_note_button.clone();
    let search_entry_for_key = search_entry.clone();
    let lock_button_for_key = lock_button.clone();
    let window_for_key = window.clone();
    let sidebar_for_key = sidebar.clone();
    let find_bar_for_key = find_bar.clone();
    let find_entry_for_key = find_entry.clone();
    let toggle_preview_for_key = toggle_preview.clone();
    // Sidebar visibility to restore when leaving distraction-free mode.
    let df_prev_sidebar: Rc<Cell<bool>> = Rc::new(Cell::new(true));

    key_controller.connect_key_pressed(move |_, keyval, _, mods| {
        reset_activity_timer();
        use gtk::gdk::Key;
        let ctrl = mods.contains(gtk::gdk::ModifierType::CONTROL_MASK);

        // F11: distraction-free — fullscreen + hide the note list (restored on exit).
        if keyval == Key::F11 {
            if window_for_key.is_fullscreen() {
                window_for_key.unfullscreen();
                sidebar_for_key.set_visible(df_prev_sidebar.get());
            } else {
                df_prev_sidebar.set(sidebar_for_key.get_visible());
                sidebar_for_key.set_visible(false);
                window_for_key.fullscreen();
            }
            return glib::Propagation::Stop;
        }
        // Esc leaves fullscreen first (before falling through to lock).
        if keyval == Key::Escape && window_for_key.is_fullscreen() {
            window_for_key.unfullscreen();
            sidebar_for_key.set_visible(df_prev_sidebar.get());
            return glib::Propagation::Stop;
        }

        // Ctrl+H toggles the find & replace bar.
        if ctrl && (keyval == Key::h || keyval == Key::H) {
            let show = !find_bar_for_key.get_visible();
            find_bar_for_key.set_visible(show);
            if show {
                find_entry_for_key.grab_focus();
            }
            return glib::Propagation::Stop;
        }
        // Esc closes the find bar (before falling through to lock).
        if keyval == Key::Escape && find_bar_for_key.get_visible() {
            find_bar_for_key.set_visible(false);
            return glib::Propagation::Stop;
        }

        if ctrl && (keyval == Key::n || keyval == Key::N) {
            new_note_button_for_key.emit_clicked();
            return glib::Propagation::Stop;
        }
        // Ctrl+P toggles the Markdown preview.
        if ctrl && (keyval == Key::p || keyval == Key::P) {
            toggle_preview_for_key();
            return glib::Propagation::Stop;
        }
        if ctrl && (keyval == Key::f || keyval == Key::F) {
            search_entry_for_key.grab_focus();
            return glib::Propagation::Stop;
        }
        if (ctrl && (keyval == Key::l || keyval == Key::L)) || keyval == Key::Escape {
            lock_button_for_key.emit_clicked();
            return glib::Propagation::Stop;
        }
        if keyval == Key::Delete {
            let id_opt = *active_note_id_for_key.lock().unwrap();
            if let Some(id) = id_opt {
                if !title_entry_for_key.has_focus() && !content_view_clone.has_focus() {
                    note_action_key("delete", id);
                    return glib::Propagation::Stop;
                }
            }
        }
        glib::Propagation::Proceed
    });
    window.add_controller(key_controller);

    let window_weak = window.downgrade();
    let app_weak = app.downgrade();
    let manager_for_timer = manager_rc.clone();
    let save_on_autolock = save_active.clone();

    // Replace any prior auto-lock timer before installing this window's, and track
    // its SourceId so the next lock can cancel it (see cancel_auto_lock_timer).
    cancel_auto_lock_timer();
    let auto_lock_source = glib::timeout_add_seconds_local(30, move || {
        let timeout = manager_for_timer.lock()
            .map(|m| m.get_settings().auto_lock_timeout)
            .unwrap_or(0);

        if timeout == 0 {
            return glib::ControlFlow::Continue;
        }

        let elapsed = LAST_ACTIVITY.with(|l| l.borrow().elapsed());

        if elapsed >= Duration::from_secs(timeout) {
            if let (Some(w), Some(a)) = (window_weak.upgrade(), app_weak.upgrade()) {
                // Flush the active note before auto-locking.
                let _ = save_on_autolock();
                if let Some(mgr) = CORE_MANAGER.get() {
                    mgr.clone().lock().unwrap().lock();
                }
                // Drop our handle WITHOUT remove() — returning Break removes the
                // source itself, and show_password_screen would otherwise try to
                // remove it a second time (GLib "source not found" warning).
                AUTO_LOCK_TIMER.with(|c| { c.borrow_mut().take(); });
                w.close();
                show_password_screen(&a);
                return glib::ControlFlow::Break;
            }
        }
        glib::ControlFlow::Continue
    });
    AUTO_LOCK_TIMER.with(|c| *c.borrow_mut() = Some(auto_lock_source));

    // On open, actually LOAD the most-recent note (row 0) so the editor shows it
    // instead of being blank. Previously nothing was selected at startup, so the
    // dropdown showed a note the editor had never loaded — you had to switch away
    // and back to see it. No-op (empty editor) when there are no notes yet.
    if let Some(row) = note_list_box.row_at_index(0) {
        note_list_box.select_row(Some(&row));
    }

    window.present();
}

fn show_preferences_dialog<F: Fn() + Clone + 'static>(
    parent: &ApplicationWindow,
    manager_rc: Arc<Mutex<CoreManager>>,
    status_label: Arc<Label>,
    app_title_widget: Label,
    word_count_widget: Arc<Label>,
    content_buffer: Arc<gtk::TextBuffer>,
    sidebar_widget: gtk::Box,
    refresh: F,
) {
    let settings = manager_rc.lock().unwrap().get_settings().clone();
    let db_path = manager_rc.lock().unwrap().get_data_path().display().to_string();
    
    let dialog = gtk::Window::builder()
        .title("Preferences")
        .modal(true)
        .transient_for(parent)
        .default_width(420)
        .default_height(560)
        .build();
    
    // Custom header for dialog too
    let header = gtk::HeaderBar::new();
    header.set_show_title_buttons(false);
    header.add_css_class("custom-headerbar");
    
    let dialog_for_header = dialog.clone();
    let close_btn = gtk::Button::new();
    close_btn.add_css_class("traffic-btn");
    close_btn.add_css_class("traffic-close");
    shape_traffic_button(&close_btn);
    close_btn.connect_clicked(move |_| dialog_for_header.close());
    
    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 2);
    btn_box.set_margin_start(4);
    btn_box.append(&close_btn);
    header.pack_start(&btn_box);
    
    let header_title = Label::new(Some("Preferences"));
    header_title.add_css_class("headerbar-title");
    header.set_title_widget(Some(&header_title));
    
    dialog.set_titlebar(Some(&header));

    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();

    let main_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
    main_box.set_margin_top(18);
    main_box.set_margin_bottom(18);
    main_box.set_margin_start(18);
    main_box.set_margin_end(18);

    // Editor group
    let editor_group = gtk::Box::new(gtk::Orientation::Vertical, 8);
    editor_group.add_css_class("preferences-group");
    
    let editor_title = Label::new(Some("EDITOR"));
    editor_title.add_css_class("preferences-title");
    editor_title.set_halign(gtk::Align::Start);
    
    // Font family dropdown
    let font_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let font_label = Label::new(Some("Font"));
    font_label.set_hexpand(true);
    font_label.set_halign(gtk::Align::Start);
    
    let font_dropdown = gtk::DropDown::from_strings(
        &EditorFont::all_fonts().iter().map(|f| f.display_name()).collect::<Vec<_>>()
    );
    font_dropdown.set_selected(settings.editor_font.to_index());
    
    font_row.append(&font_label);
    font_row.append(&font_dropdown);
    
    // Font size
    let size_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let size_label = Label::new(Some("Font size"));
    size_label.set_hexpand(true);
    size_label.set_halign(gtk::Align::Start);
    let size_spin = gtk::SpinButton::with_range(6.0, 24.0, 1.0);
    size_spin.set_value(settings.editor_font_size as f64);
    size_row.append(&size_label);
    size_row.append(&size_spin);
    
    // (The old "Show note title" toggle is gone: with first-line = title there is
    // no separate title field to show or hide.)

    editor_group.append(&editor_title);
    editor_group.append(&font_row);
    editor_group.append(&size_row);

    // Appearance group (theme selection: built-in Notas themes + tesseract palettes)
    let appearance_group = gtk::Box::new(gtk::Orientation::Vertical, 8);
    appearance_group.add_css_class("preferences-group");
    let appearance_title = Label::new(Some("APPEARANCE"));
    appearance_title.add_css_class("preferences-title");
    appearance_title.set_halign(gtk::Align::Start);

    let theme_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let theme_label = Label::new(Some("Theme"));
    theme_label.set_hexpand(true);
    theme_label.set_halign(gtk::Align::Start);
    let theme_list = theme_choices();
    let theme_dropdown = gtk::DropDown::from_strings(
        &theme_list.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
    );
    let current_theme_idx = theme_list
        .iter()
        .position(|(_, t)| *t == settings.theme)
        .unwrap_or(0) as u32;
    theme_dropdown.set_selected(current_theme_idx);
    // Apply the picked theme instantly AND persist it. The CSS provider is
    // display-wide so the palette keeps rendering across lock/unlock, but if we
    // only render and don't save, `settings.theme` stays on its old value — so
    // reopening Preferences (whose dropdown initialises from `settings.theme`)
    // would wrongly show "Notas Dark" while a custom palette is on screen.
    let manager_for_theme = manager_rc.clone();
    theme_dropdown.connect_selected_notify(move |dd| {
        if let Some((_, t)) = theme_choices().get(dd.selected() as usize) {
            switch_theme(t);
            if let Ok(mut mgr) = manager_for_theme.lock() {
                let mut updated = mgr.get_settings().clone();
                if updated.theme != *t {
                    updated.theme = t.clone();
                    let _ = mgr.update_settings(updated);
                }
            }
        }
    });
    theme_row.append(&theme_label);
    theme_row.append(&theme_dropdown);

    // Show / hide the "Notas" wordmark in the sidebar header.
    let logo_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let logo_label = Label::new(Some("Show Notas logo"));
    logo_label.set_hexpand(true);
    logo_label.set_halign(gtk::Align::Start);
    let logo_switch = gtk::Switch::new();
    logo_switch.set_active(settings.show_app_logo);
    logo_row.append(&logo_label);
    logo_row.append(&logo_switch);

    // Show / hide the first-line preview under each note in the sidebar (privacy).
    let previews_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let previews_label = Label::new(Some("Show note previews"));
    previews_label.set_hexpand(true);
    previews_label.set_halign(gtk::Align::Start);
    let previews_switch = gtk::Switch::new();
    previews_switch.set_active(settings.show_note_previews);
    previews_row.append(&previews_label);
    previews_row.append(&previews_switch);

    // Show / hide the word & character count in the editor status bar.
    let wordcount_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let wordcount_label = Label::new(Some("Show word count"));
    wordcount_label.set_hexpand(true);
    wordcount_label.set_halign(gtk::Align::Start);
    let wordcount_switch = gtk::Switch::new();
    wordcount_switch.set_active(settings.show_word_count);
    wordcount_row.append(&wordcount_label);
    wordcount_row.append(&wordcount_switch);

    // Rainbow ("lolcat") editor text.
    let rainbow_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let rainbow_label = Label::new(Some("Rainbow text (lolcat)"));
    rainbow_label.set_hexpand(true);
    rainbow_label.set_halign(gtk::Align::Start);
    let rainbow_switch = gtk::Switch::new();
    rainbow_switch.set_active(settings.rainbow_text);
    rainbow_switch.set_tooltip_text(Some("Colour each character in Catppuccin pastels. Overrides the custom text colour."));
    rainbow_row.append(&rainbow_label);
    rainbow_row.append(&rainbow_switch);

    // Custom editor text colour: an enable switch + a colour picker. When the
    // switch is off the editor follows the theme colour.
    let textcolor_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let textcolor_label = Label::new(Some("Custom text colour"));
    textcolor_label.set_hexpand(true);
    textcolor_label.set_halign(gtk::Align::Start);
    let textcolor_switch = gtk::Switch::new();
    textcolor_switch.set_active(settings.editor_text_color.is_some());
    let textcolor_button = gtk::ColorButton::new();
    // Seed the picker from the saved colour, falling back to white.
    let seed = settings
        .editor_text_color
        .as_deref()
        .and_then(|h| gtk::gdk::RGBA::parse(h).ok())
        .unwrap_or_else(|| gtk::gdk::RGBA::new(1.0, 1.0, 1.0, 1.0));
    textcolor_button.set_rgba(&seed);
    textcolor_row.append(&textcolor_label);
    textcolor_row.append(&textcolor_switch);
    textcolor_row.append(&textcolor_button);

    // Minimal mode: start with the note list collapsed (toggle it back with ☰).
    let minimal_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let minimal_label = Label::new(Some("Minimal mode (hide note list)"));
    minimal_label.set_hexpand(true);
    minimal_label.set_halign(gtk::Align::Start);
    let minimal_switch = gtk::Switch::new();
    minimal_switch.set_active(settings.minimal_mode);
    minimal_switch.set_tooltip_text(Some("Start with the sidebar collapsed; switch notes from the top-bar dropdown. Toggle the list anytime with ☰."));
    minimal_row.append(&minimal_label);
    minimal_row.append(&minimal_switch);

    appearance_group.append(&appearance_title);
    appearance_group.append(&theme_row);
    appearance_group.append(&logo_row);
    appearance_group.append(&previews_row);
    appearance_group.append(&wordcount_row);
    appearance_group.append(&rainbow_row);
    appearance_group.append(&textcolor_row);
    appearance_group.append(&minimal_row);

    // Security group
    let security_group = gtk::Box::new(gtk::Orientation::Vertical, 8);
    security_group.add_css_class("preferences-group");
    
    let security_title = Label::new(Some("SECURITY"));
    security_title.add_css_class("preferences-title");
    security_title.set_halign(gtk::Align::Start);
    
    let auto_lock_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let auto_lock_label = Label::new(Some("Auto-lock (sec, 0=off)"));
    auto_lock_label.set_hexpand(true);
    auto_lock_label.set_halign(gtk::Align::Start);
    let auto_lock_spin = gtk::SpinButton::with_range(0.0, 3600.0, 30.0);
    auto_lock_spin.set_value(settings.auto_lock_timeout as f64);
    auto_lock_row.append(&auto_lock_label);
    auto_lock_row.append(&auto_lock_spin);
    
    let clipboard_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let clipboard_label = Label::new(Some("Clipboard clear (sec, 0=off)"));
    clipboard_label.set_hexpand(true);
    clipboard_label.set_halign(gtk::Align::Start);
    let clipboard_spin = gtk::SpinButton::with_range(0.0, 300.0, 5.0);
    clipboard_spin.set_value(settings.clipboard_timeout as f64);
    clipboard_row.append(&clipboard_label);
    clipboard_row.append(&clipboard_spin);

    // Key-derivation strength. Strong (64 MiB) is the default; "Extra strong" is
    // Paranoid (256 MiB) — much harder to brute-force but ~1.4s per unlock/save.
    // The dropdown initialises from the vault's actual params. Changing it
    // re-encrypts the vault (done off the UI thread so it can't freeze).
    let kdf_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let kdf_label = Label::new(Some("Key derivation"));
    kdf_label.set_hexpand(true);
    kdf_label.set_halign(gtk::Align::Start);
    let kdf_labels: Vec<&str> = vec!["Strong (recommended)", "Extra strong"];
    let kdf_dropdown = gtk::DropDown::from_strings(&kdf_labels);
    let cur_is_paranoid =
        settings.argon2_params.memory_cost >= core::data::KdfStrength::Paranoid.params().memory_cost;
    kdf_dropdown.set_selected(if cur_is_paranoid { 1 } else { 0 });
    kdf_dropdown.set_tooltip_text(Some(
        "Extra strong = 256 MiB Argon2 (~1.4s per unlock and save). \
         Changing this re-encrypts your vault.",
    ));
    kdf_row.append(&kdf_label);
    kdf_row.append(&kdf_dropdown);

    security_group.append(&security_title);
    security_group.append(&auto_lock_row);
    security_group.append(&clipboard_row);
    security_group.append(&kdf_row);

    // Storage group
    let storage_group = gtk::Box::new(gtk::Orientation::Vertical, 8);
    storage_group.add_css_class("preferences-group");
    
    let storage_title = Label::new(Some("STORAGE"));
    storage_title.add_css_class("preferences-title");
    storage_title.set_halign(gtk::Align::Start);
    
    let path_label = Label::new(Some("Database location:"));
    path_label.set_halign(gtk::Align::Start);
    
    let path_entry = gtk::Entry::new();
    path_entry.set_text(&db_path);
    path_entry.set_hexpand(true);
    
    storage_group.append(&storage_title);
    storage_group.append(&path_label);
    storage_group.append(&path_entry);

    // Password group
    let password_group = gtk::Box::new(gtk::Orientation::Vertical, 8);
    password_group.add_css_class("preferences-group");
    
    let password_title = Label::new(Some("CHANGE PASSWORD"));
    password_title.add_css_class("preferences-title");
    password_title.set_halign(gtk::Align::Start);
    
    let current_password_entry = gtk::PasswordEntry::new();
    current_password_entry.set_placeholder_text(Some("Current Password"));
    current_password_entry.set_show_peek_icon(true);
    
    let new_password_entry = gtk::PasswordEntry::new();
    new_password_entry.set_placeholder_text(Some("New Password"));
    new_password_entry.set_show_peek_icon(true);
    // Live strength meter on the new-password field (no generator — the master
    // password isn't something you randomly generate per the user's request).
    let new_password_strength = make_strength_meter(&new_password_entry);

    let confirm_password_entry = gtk::PasswordEntry::new();
    confirm_password_entry.set_placeholder_text(Some("Confirm New Password"));
    confirm_password_entry.set_show_peek_icon(true);

    let change_password_button = gtk::Button::with_label("Change Password");
    change_password_button.add_css_class("secondary-button");

    let password_status = Rc::new(Label::new(None));
    password_status.set_halign(gtk::Align::Start);

    password_group.append(&password_title);
    password_group.append(&current_password_entry);
    password_group.append(&new_password_entry);
    password_group.append(&new_password_strength);
    password_group.append(&confirm_password_entry);
    password_group.append(&change_password_button);
    password_group.append(password_status.as_ref());

    let manager_clone = manager_rc.clone();
    let current_clone = current_password_entry.clone();
    let new_clone = new_password_entry.clone();
    let confirm_clone = confirm_password_entry.clone();
    let password_status_clone = password_status.clone();
    
    change_password_button.connect_clicked(move |btn| {
        let current = current_clone.text().to_string();
        let new_pass = new_clone.text().to_string();
        let confirm = confirm_clone.text().to_string();
        
        if current.is_empty() || new_pass.is_empty() || confirm.is_empty() {
            password_status_clone.set_markup("<span foreground='#a06060'>All fields required</span>");
            return;
        }
        if new_pass != confirm {
            password_status_clone.set_markup("<span foreground='#a06060'>Passwords don't match</span>");
            return;
        }
        if new_pass.len() < 8 {
            password_status_clone.set_markup("<span foreground='#a06060'>Min 8 characters</span>");
            return;
        }
        
        btn.set_sensitive(false);
        password_status_clone.set_text("Changing...");
        
        let manager_for_task = manager_clone.clone();
        let password_status_for_ui = password_status_clone.clone();
        let current_entry = current_clone.clone();
        let new_entry = new_clone.clone();
        let confirm_entry = confirm_clone.clone();
        let btn_ui = btn.clone();
        
        let (sender, receiver) = async_channel::unbounded();
        let runtime = TOKIO_RUNTIME.get().unwrap();
        
        glib::spawn_future_local(async move {
            let _guard = runtime.enter();
            let result = tokio::task::spawn_blocking(move || {
                let old = core::data::MasterPassword::from(current.as_str());
                let new = core::data::MasterPassword::from(new_pass.as_str());
                manager_for_task.lock().unwrap().change_password(old, new)
            }).await;
            let _ = sender.send(result).await;
        });
        
        glib::spawn_future_local(async move {
            if let Ok(result) = receiver.recv().await {
                match result {
                    Ok(Ok(_)) => {
                        password_status_for_ui.set_markup("<span foreground='#60a060'>Password changed</span>");
                        current_entry.set_text("");
                        new_entry.set_text("");
                        confirm_entry.set_text("");
                    },
                    Ok(Err(e)) => password_status_for_ui.set_markup(&format!("<span foreground='#a06060'>{}</span>", e)),
                    Err(e) => password_status_for_ui.set_markup(&format!("<span foreground='#a06060'>{}</span>", e)),
                }
                btn_ui.set_sensitive(true);
            }
        });
    });

    let button_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    button_box.set_halign(gtk::Align::End);
    button_box.set_margin_top(8);
    
    let cancel_button = gtk::Button::with_label("Cancel");
    cancel_button.add_css_class("secondary-button");
    
    let save_button = gtk::Button::with_label("Save");
    save_button.add_css_class("action-button");
    
    button_box.append(&cancel_button);
    button_box.append(&save_button);

    // Backup group: Export / Import (moved here from the sidebar to reduce clutter)
    let data_group = gtk::Box::new(gtk::Orientation::Vertical, 8);
    data_group.add_css_class("preferences-group");
    let data_title = Label::new(Some("BACKUP"));
    data_title.add_css_class("preferences-title");
    data_title.set_halign(gtk::Align::Start);

    let data_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let export_button = gtk::Button::with_label("Export vault");
    export_button.add_css_class("secondary-button");
    export_button.set_hexpand(true);
    let import_button = gtk::Button::with_label("Import vault");
    import_button.add_css_class("secondary-button");
    import_button.set_hexpand(true);
    data_row.append(&export_button);
    data_row.append(&import_button);

    // Plain-text export (unencrypted, for reading outside the app).
    let txt_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let export_txt_button = gtk::Button::with_label("Export all (.txt)");
    export_txt_button.add_css_class("secondary-button");
    export_txt_button.set_hexpand(true);
    export_txt_button.set_tooltip_text(Some("All notes in one plain-text file (unencrypted)"));
    let export_txt_folder_button = gtk::Button::with_label("Export each (.txt)");
    export_txt_folder_button.add_css_class("secondary-button");
    export_txt_folder_button.set_hexpand(true);
    export_txt_folder_button.set_tooltip_text(Some("One .txt file per note into a folder (unencrypted)"));
    txt_row.append(&export_txt_button);
    txt_row.append(&export_txt_folder_button);

    data_group.append(&data_title);
    data_group.append(&data_row);
    data_group.append(&txt_row);

    // Export all notes into a single plain-text file.
    {
        let manager_rc = manager_rc.clone();
        let status_label = status_label.clone();
        let dialog_for_chooser = dialog.clone();
        export_txt_button.connect_clicked(move |_| {
            let chooser = gtk::FileChooserDialog::new(
                Some("Export all notes as .txt"),
                Some(&dialog_for_chooser),
                gtk::FileChooserAction::Save,
                &[
                    ("Cancel", gtk::ResponseType::Cancel),
                    ("Export", gtk::ResponseType::Accept),
                ],
            );
            chooser.set_current_name("notes_export.txt");
            let manager_clone = manager_rc.clone();
            let status_clone = status_label.clone();
            chooser.connect_response(move |chooser, response| {
                if response == gtk::ResponseType::Accept {
                    if let Some(path) = chooser.file().and_then(|f| f.path()) {
                        let notes = manager_clone.lock().unwrap().get_notes();
                        let body = notes
                            .iter()
                            .map(|n| note_to_txt(&n.title, &n.content))
                            .collect::<Vec<_>>()
                            .join("\n\n----------------------------------------\n\n");
                        match std::fs::write(&path, body) {
                            Ok(_) => status_clone.set_text(&format!(
                                "Exported {} notes: {}",
                                notes.len(),
                                path.display()
                            )),
                            Err(e) => status_clone.set_text(&format!("Error: {}", e)),
                        }
                    }
                }
                chooser.close();
            });
            chooser.show();
        });
    }

    // Export each note as its own .txt file into a chosen folder.
    {
        let manager_rc = manager_rc.clone();
        let status_label = status_label.clone();
        let dialog_for_chooser = dialog.clone();
        export_txt_folder_button.connect_clicked(move |_| {
            let chooser = gtk::FileChooserDialog::new(
                Some("Choose a folder for .txt exports"),
                Some(&dialog_for_chooser),
                gtk::FileChooserAction::SelectFolder,
                &[
                    ("Cancel", gtk::ResponseType::Cancel),
                    ("Export", gtk::ResponseType::Accept),
                ],
            );
            let manager_clone = manager_rc.clone();
            let status_clone = status_label.clone();
            chooser.connect_response(move |chooser, response| {
                if response == gtk::ResponseType::Accept {
                    if let Some(dir) = chooser.file().and_then(|f| f.path()) {
                        let notes = manager_clone.lock().unwrap().get_notes();
                        let mut used: std::collections::HashSet<String> =
                            std::collections::HashSet::new();
                        let mut count = 0;
                        let mut err = None;
                        for n in &notes {
                            let base = sanitize_filename(&n.title);
                            let mut fname = format!("{}.txt", base);
                            let mut i = 2;
                            while used.contains(&fname) {
                                fname = format!("{} ({}).txt", base, i);
                                i += 1;
                            }
                            used.insert(fname.clone());
                            if let Err(e) =
                                std::fs::write(dir.join(&fname), note_to_txt(&n.title, &n.content))
                            {
                                err = Some(e.to_string());
                                break;
                            }
                            count += 1;
                        }
                        match err {
                            None => status_clone.set_text(&format!(
                                "Exported {} notes to {}",
                                count,
                                dir.display()
                            )),
                            Some(e) => status_clone
                                .set_text(&format!("Error after {} notes: {}", count, e)),
                        }
                    }
                }
                chooser.close();
            });
            chooser.show();
        });
    }

    {
        let manager_rc = manager_rc.clone();
        let status_label = status_label.clone();
        let dialog_for_chooser = dialog.clone();
        export_button.connect_clicked(move |_| {
            let file_chooser = gtk::FileChooserDialog::new(
                Some("Export Notes"),
                Some(&dialog_for_chooser),
                gtk::FileChooserAction::Save,
                &[("Cancel", gtk::ResponseType::Cancel), ("Export", gtk::ResponseType::Accept)],
            );
            file_chooser.set_current_name("notes_export.dat");
            let manager_clone = manager_rc.clone();
            let status_clone = status_label.clone();
            file_chooser.connect_response(move |chooser, response| {
                if response == gtk::ResponseType::Accept {
                    if let Some(path) = chooser.file().and_then(|f| f.path()) {
                        let manager_for_task = manager_clone.clone();
                        let status_for_ui = status_clone.clone();
                        let path_clone = path.clone();
                        status_clone.set_text("Exporting...");
                        let (sender, receiver) = async_channel::unbounded();
                        let runtime = TOKIO_RUNTIME.get().unwrap();
                        glib::spawn_future_local(async move {
                            let _guard = runtime.enter();
                            let result = tokio::task::spawn_blocking(move || {
                                manager_for_task.lock().unwrap().export_all_encrypted(&path_clone)
                            }).await;
                            let _ = sender.send((result, path)).await;
                        });
                        glib::spawn_future_local(async move {
                            if let Ok((result, path)) = receiver.recv().await {
                                match result {
                                    Ok(Ok(_)) => status_for_ui.set_text(&format!("Exported: {}", path.display())),
                                    Ok(Err(e)) => status_for_ui.set_text(&format!("Error: {}", e)),
                                    Err(e) => status_for_ui.set_text(&format!("Error: {}", e)),
                                }
                            }
                        });
                    }
                }
                chooser.close();
            });
            file_chooser.show();
        });
    }

    {
        let manager_rc = manager_rc.clone();
        let status_label = status_label.clone();
        let dialog_for_chooser = dialog.clone();
        let parent_window = parent.clone();
        let refresh = refresh.clone();
        import_button.connect_clicked(move |_| {
            let file_chooser = gtk::FileChooserDialog::new(
                Some("Import Notes"),
                Some(&dialog_for_chooser),
                gtk::FileChooserAction::Open,
                &[("Cancel", gtk::ResponseType::Cancel), ("Import", gtk::ResponseType::Accept)],
            );
            let manager_clone = manager_rc.clone();
            let status_clone = status_label.clone();
            let parent_clone = parent_window.clone();
            let refresh = refresh.clone();
            file_chooser.connect_response(move |chooser, response| {
                if response == gtk::ResponseType::Accept {
                    if let Some(path) = chooser.file().and_then(|f| f.path()) {
                        show_import_password_dialog(
                            &parent_clone,
                            manager_clone.clone(),
                            status_clone.clone(),
                            refresh.clone(),
                            path,
                        );
                    }
                }
                chooser.close();
            });
            file_chooser.show();
        });
    }

    main_box.append(&editor_group);
    main_box.append(&appearance_group);
    main_box.append(&security_group);
    main_box.append(&storage_group);
    main_box.append(&password_group);
    main_box.append(&data_group);
    main_box.append(&button_box);

    scrolled.set_child(Some(&main_box));
    dialog.set_child(Some(&scrolled));

    let dialog_clone = dialog.clone();
    cancel_button.connect_clicked(move |_| { dialog_clone.close(); });

    let dialog_clone = dialog.clone();
    let manager_clone = manager_rc.clone();
    let path_entry_clone = path_entry.clone();
    let font_dropdown_clone = font_dropdown.clone();
    let size_spin_clone = size_spin.clone();
    let theme_dropdown_clone = theme_dropdown.clone();
    let logo_switch_clone = logo_switch.clone();
    let app_title_clone = app_title_widget.clone();
    let previews_switch_clone = previews_switch.clone();
    let wordcount_switch_clone = wordcount_switch.clone();
    let word_count_widget_clone = word_count_widget.clone();
    let rainbow_switch_clone = rainbow_switch.clone();
    let textcolor_switch_clone = textcolor_switch.clone();
    let textcolor_button_clone = textcolor_button.clone();
    let content_buffer_clone = content_buffer.clone();
    let kdf_dropdown_clone = kdf_dropdown.clone();
    let minimal_switch_clone = minimal_switch.clone();
    let sidebar_widget_clone = sidebar_widget.clone();
    let refresh_for_save = refresh.clone();

    save_button.connect_clicked(move |btn| {
        let current = manager_clone.lock().unwrap().get_settings().clone();
        let default_path = manager_clone.lock().unwrap().get_data_path().display().to_string();
        let path_str = path_entry_clone.text().to_string();
        
        let selected_font = EditorFont::from_index(font_dropdown_clone.selected());
        let font_size = size_spin_clone.value() as u32;
        let show_logo = logo_switch_clone.is_active();
        let show_previews = previews_switch_clone.is_active();
        let show_wordcount = wordcount_switch_clone.is_active();
        let rainbow_on = rainbow_switch_clone.is_active();
        let minimal_on = minimal_switch_clone.is_active();
        // KDF: index 1 = Extra strong (Paranoid), else Strong.
        let selected_kdf = if kdf_dropdown_clone.selected() == 1 {
            core::data::KdfStrength::Paranoid
        } else {
            core::data::KdfStrength::Strong
        };
        // Custom text colour: Some(hex) only when the enable switch is on.
        let text_color: Option<String> = if textcolor_switch_clone.is_active() {
            Some(rgba_to_hex(&textcolor_button_clone.rgba()))
        } else {
            None
        };
        let selected_theme = theme_choices()
            .get(theme_dropdown_clone.selected() as usize)
            .map(|(_, t)| t.clone())
            .unwrap_or(AppTheme::Dark);
        CURRENT_THEME.with(|t| *t.borrow_mut() = selected_theme.clone());

        // Update thread-local settings
        EDITOR_FONT.with(|f| *f.borrow_mut() = selected_font.clone());
        EDITOR_FONT_SIZE.with(|s| *s.borrow_mut() = font_size);
        SHOW_NOTE_PREVIEWS.with(|s| *s.borrow_mut() = show_previews);
        SHOW_WORD_COUNT.with(|s| *s.borrow_mut() = show_wordcount);
        RAINBOW_TEXT.with(|s| *s.borrow_mut() = rainbow_on);

        // Whether the sidebar preview setting changed — only then do we rebuild
        // the list (a rebuild resets the selection highlight, so avoid it
        // otherwise).
        let previews_changed = current.show_note_previews != show_previews;

        // Update logo + word-count visibility immediately, and apply minimal mode
        // live (collapse/expand the sidebar to match the toggle).
        app_title_clone.set_visible(show_logo);
        word_count_widget_clone.set_visible(show_wordcount);
        sidebar_widget_clone.set_visible(!minimal_on);

        // Did the KDF strength change? If so the save re-encrypts the whole vault
        // (Strong ~0.25s, Extra strong ~1.4s), which we run off the UI thread.
        let kdf_changed = current.argon2_params.memory_cost != selected_kdf.params().memory_cost
            || current.argon2_params.time_cost != selected_kdf.params().time_cost;

        let new_settings = AppSettings {
            auto_lock_timeout: auto_lock_spin.value() as u64,
            clipboard_timeout: clipboard_spin.value() as u64,
            custom_db_path: if path_str != default_path {
                Some(std::path::PathBuf::from(path_str))
            } else {
                None
            },
            // Strong by default; Extra strong (Paranoid) is the user's opt-in.
            argon2_params: selected_kdf.params(),
            // Cascade encryption is always on; there is no opt-out.
            encryption_mode: core::data::EncryptionMode::Cascade,
            theme: selected_theme,
            editor_font: selected_font,
            editor_font_size: font_size,
            show_note_title: false, // no separate title field (first line = title)
            show_app_logo: show_logo,
            show_note_previews: show_previews,
            show_word_count: show_wordcount,
            editor_text_color: text_color.clone(),
            rainbow_text: rainbow_on,
            minimal_mode: minimal_on,
        };

        // Apply the live, persistence-independent UI immediately (so it feels
        // instant even if the re-encrypt below runs asynchronously).
        reload_css();
        apply_editor_text_color(text_color.as_deref());
        apply_rainbow(&content_buffer_clone, rainbow_on);
        if previews_changed {
            refresh_for_save();
        }

        if kdf_changed {
            // Heavy re-encrypt → off the UI thread so the app never freezes (this
            // is exactly the path that hung at Paranoid). Dialog stays open with
            // a status until it finishes, then closes.
            status_label.set_text("Re-encrypting vault…");
            btn.set_sensitive(false);
            let manager_for_task = manager_clone.clone();
            let status_done = status_label.clone();
            let dialog_done = dialog_clone.clone();
            let btn_done = btn.clone();
            let (sender, receiver) = async_channel::unbounded();
            let runtime = TOKIO_RUNTIME.get().unwrap();
            glib::spawn_future_local(async move {
                let _guard = runtime.enter();
                let result = tokio::task::spawn_blocking(move || {
                    manager_for_task.lock().unwrap().update_settings(new_settings)
                })
                .await;
                let _ = sender.send(result).await;
            });
            glib::spawn_future_local(async move {
                if let Ok(result) = receiver.recv().await {
                    match result {
                        Ok(Ok(())) => {
                            status_done.set_text("Settings saved");
                            dialog_done.close();
                        }
                        Ok(Err(e)) => {
                            status_done.set_text(&format!("Error: {}", e));
                            btn_done.set_sensitive(true);
                        }
                        Err(e) => {
                            status_done.set_text(&format!("Error: {}", e));
                            btn_done.set_sensitive(true);
                        }
                    }
                }
            });
        } else {
            // No re-encrypt: settings.json write is trivial, do it synchronously.
            match manager_clone.lock().unwrap().update_settings(new_settings) {
                Ok(_) => {
                    status_label.set_text("Settings saved");
                    dialog_clone.close();
                }
                Err(e) => status_label.set_text(&format!("Error: {}", e)),
            }
        }
    });

    dialog.present();
}

fn show_import_password_dialog<F>(
    parent: &ApplicationWindow,
    manager_rc: Arc<Mutex<CoreManager>>,
    status_label: Arc<Label>,
    refresh_list: F,
    import_path: std::path::PathBuf,
) where F: Fn() + 'static + Clone {
    let dialog = gtk::Window::builder()
        .title("Import")
        .modal(true)
        .transient_for(parent)
        .default_width(320)
        .default_height(200)
        .build();
    
    // Custom header
    let header = gtk::HeaderBar::new();
    header.set_show_title_buttons(false);
    header.add_css_class("custom-headerbar");
    
    let dialog_for_header = dialog.clone();
    let close_btn = gtk::Button::new();
    close_btn.add_css_class("traffic-btn");
    close_btn.add_css_class("traffic-close");
    shape_traffic_button(&close_btn);
    close_btn.connect_clicked(move |_| dialog_for_header.close());
    
    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 2);
    btn_box.set_margin_start(4);
    btn_box.append(&close_btn);
    header.pack_start(&btn_box);
    
    let header_title = Label::new(Some("Import"));
    header_title.add_css_class("headerbar-title");
    header.set_title_widget(Some(&header_title));
    
    dialog.set_titlebar(Some(&header));

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 12);
    vbox.set_margin_top(18);
    vbox.set_margin_bottom(18);
    vbox.set_margin_start(18);
    vbox.set_margin_end(18);

    let label = Label::new(Some("Enter password for import file:"));
    label.set_halign(gtk::Align::Start);

    let password_entry = gtk::PasswordEntry::new();
    password_entry.set_placeholder_text(Some("Password"));
    password_entry.set_show_peek_icon(true);

    let import_status = Rc::new(Label::new(None));
    import_status.set_halign(gtk::Align::Start);

    let button_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    button_box.set_halign(gtk::Align::End);

    let cancel_button = gtk::Button::with_label("Cancel");
    cancel_button.add_css_class("secondary-button");
    
    let import_button = gtk::Button::with_label("Import");
    import_button.add_css_class("action-button");

    button_box.append(&cancel_button);
    button_box.append(&import_button);

    vbox.append(&label);
    vbox.append(&password_entry);
    vbox.append(import_status.as_ref());
    vbox.append(&button_box);

    dialog.set_child(Some(&vbox));

    let dialog_clone = dialog.clone();
    cancel_button.connect_clicked(move |_| { dialog_clone.close(); });

    let dialog_clone = dialog.clone();
    let import_status_clone = import_status.clone();
    let password_entry_clone = password_entry.clone();
    
    import_button.connect_clicked(move |_| {
        let password = password_entry_clone.text().to_string();
        if password.is_empty() {
            import_status_clone.set_markup("<span foreground='#a06060'>Password required</span>");
            return;
        }

        let manager_clone = manager_rc.clone();
        let status_clone = status_label.clone();
        let path_clone = import_path.clone();
        let dialog_close = dialog_clone.clone();
        let import_status2 = import_status_clone.clone();
        let refresh = refresh_list.clone();
        
        import_status_clone.set_text("Importing...");
        
        let (sender, receiver) = async_channel::unbounded();
        let runtime = TOKIO_RUNTIME.get().unwrap();
        
        glib::spawn_future_local(async move {
            let _guard = runtime.enter();
            let result = tokio::task::spawn_blocking(move || {
                let pw = core::data::MasterPassword::from(password.as_str());
                manager_clone.lock().unwrap().import_encrypted(&path_clone, pw)
            }).await;
            let _ = sender.send(result).await;
        });
        
        glib::spawn_future_local(async move {
            if let Ok(result) = receiver.recv().await {
                match result {
                    Ok(Ok(_)) => { 
                        status_clone.set_text("Imported"); 
                        refresh(); 
                        dialog_close.close(); 
                    },
                    Ok(Err(e)) => import_status2.set_markup(&format!("<span foreground='#a06060'>{}</span>", e)),
                    Err(e) => import_status2.set_markup(&format!("<span foreground='#a06060'>{}</span>", e)),
                }
            }
        });
    });

    dialog.present();
    password_entry.grab_focus();
}
