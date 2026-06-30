//! Theme palettes ported from the tesseract UI.
//!
//! Each [`Palette`] is a colour manifest; [`compile_css`] maps it onto Notas'
//! existing `@define-color` token scheme (so all the hand-written widget rules
//! keep working) and emits a complete stylesheet. The original Notas Dark/Light
//! themes are left untouched in `main.rs`; these are additional options exposed
//! as `AppTheme::Palette(id)`.

#![allow(dead_code)] // some palette fields are carried verbatim but unused here

/// A colour manifest. Field set mirrors tesseract's so the catalog ports as-is;
/// `compile_css` only consumes the subset that maps onto Notas tokens.
#[derive(Debug, Clone)]
pub struct Palette {
    pub id: String,
    pub name: String,
    pub dark: bool,
    pub follow_system: bool,
    pub window_bg: String,
    pub view_bg: String,
    pub surface: String,
    pub surface_alt: String,
    pub headerbar: String,
    pub sidebar: String,
    pub card: String,
    pub popover: String,
    pub text: String,
    pub text_dim: String,
    pub accent: String,
    pub accent_fg: String,
    pub accent2: String,
    pub success: String,
    pub warning: String,
    pub error: String,
    pub border: String,
    pub radius: u32,
    pub glow: bool,
    pub serif: bool,
}

macro_rules! palette {
    ($id:expr, $name:expr, dark=$dark:expr, win=$win:expr, view=$view:expr,
     surface=$surface:expr, alt=$alt:expr, header=$header:expr, side=$side:expr,
     card=$card:expr, pop=$pop:expr, text=$text:expr, dim=$dim:expr,
     accent=$accent:expr, accent_fg=$afg:expr, accent2=$a2:expr,
     ok=$ok:expr, warn=$warn:expr, err=$err:expr, border=$border:expr,
     radius=$radius:expr, glow=$glow:expr, serif=$serif:expr) => {
        Palette {
            id: $id.into(),
            name: $name.into(),
            dark: $dark,
            follow_system: false,
            window_bg: $win.into(),
            view_bg: $view.into(),
            surface: $surface.into(),
            surface_alt: $alt.into(),
            headerbar: $header.into(),
            sidebar: $side.into(),
            card: $card.into(),
            popover: $pop.into(),
            text: $text.into(),
            text_dim: $dim.into(),
            accent: $accent.into(),
            accent_fg: $afg.into(),
            accent2: $a2.into(),
            success: $ok.into(),
            warning: $warn.into(),
            error: $err.into(),
            border: $border.into(),
            radius: $radius,
            glow: $glow,
            serif: $serif,
        }
    };
}

/// All palettes ported from the tesseract UI.
pub fn builtin_themes() -> Vec<Palette> {
    vec![
        palette!("dracula", "Dracula", dark = true,
            win = "#282a36", view = "#21222c", surface = "#343746", alt = "#3c3f51",
            header = "#21222c", side = "#262833", card = "#313342", pop = "#343746",
            text = "#f8f8f2", dim = "#9ea8c7",
            accent = "#bd93f9", accent_fg = "#1c1d26", accent2 = "#ff79c6",
            ok = "#50fa7b", warn = "#f1fa8c", err = "#ff5555", border = "#44475a",
            radius = 12, glow = false, serif = false),
        palette!("catppuccin-latte", "Catppuccin Latte", dark = false,
            win = "#eff1f5", view = "#ffffff", surface = "#e6e9ef", alt = "#dce0e8",
            header = "#e6e9ef", side = "#e9ecf2", card = "#ffffff", pop = "#eff1f5",
            text = "#4c4f69", dim = "#6c6f85",
            accent = "#8839ef", accent_fg = "#ffffff", accent2 = "#ea76cb",
            ok = "#40a02b", warn = "#df8e1d", err = "#d20f39", border = "#ccd0da",
            radius = 12, glow = false, serif = false),
        palette!("catppuccin-frappe", "Catppuccin Frappé", dark = true,
            win = "#303446", view = "#292c3c", surface = "#414559", alt = "#51576d",
            header = "#292c3c", side = "#2e3244", card = "#3b3f54", pop = "#414559",
            text = "#c6d0f5", dim = "#a5adce",
            accent = "#ca9ee6", accent_fg = "#232634", accent2 = "#f4b8e4",
            ok = "#a6d189", warn = "#e5c890", err = "#e78284", border = "#51576d",
            radius = 12, glow = false, serif = false),
        palette!("catppuccin-macchiato", "Catppuccin Macchiato", dark = true,
            win = "#24273a", view = "#1e2030", surface = "#363a4f", alt = "#494d64",
            header = "#1e2030", side = "#222539", card = "#2f3247", pop = "#363a4f",
            text = "#cad3f5", dim = "#a5adcb",
            accent = "#c6a0f6", accent_fg = "#181926", accent2 = "#f5bde6",
            ok = "#a6da95", warn = "#eed49f", err = "#ed8796", border = "#494d64",
            radius = 12, glow = false, serif = false),
        palette!("catppuccin-mocha", "Catppuccin Mocha", dark = true,
            win = "#1e1e2e", view = "#181825", surface = "#313244", alt = "#45475a",
            header = "#181825", side = "#1c1c2c", card = "#2a2a3c", pop = "#313244",
            text = "#cdd6f4", dim = "#a6adc8",
            accent = "#cba6f7", accent_fg = "#11111b", accent2 = "#f5c2e7",
            ok = "#a6e3a1", warn = "#f9e2af", err = "#f38ba8", border = "#45475a",
            radius = 12, glow = false, serif = false),
        palette!("vintage-light", "Vintage Light", dark = false,
            win = "#f6efe1", view = "#fbf6ea", surface = "#efe5d0", alt = "#e7dabf",
            header = "#efe5d0", side = "#f1e9d7", card = "#fbf6ea", pop = "#f3ecdc",
            text = "#46392b", dim = "#7a6a55",
            accent = "#b07d3a", accent_fg = "#fff8ec", accent2 = "#4f7c74",
            ok = "#5f7d4f", warn = "#b07d3a", err = "#a14d3a", border = "#d8c8a8",
            radius = 14, glow = false, serif = true),
        palette!("neon-tessera", "Neon Tessera", dark = true,
            win = "#0a0e14", view = "#070a10", surface = "#11161f", alt = "#161d29",
            header = "#0a0e14", side = "#0d1118", card = "#10151e", pop = "#131923",
            text = "#d8e6f2", dim = "#7e93a8",
            accent = "#00e5ff", accent_fg = "#03131a", accent2 = "#ff2ec4",
            ok = "#00ff9c", warn = "#ffc400", err = "#ff3860", border = "#1d2735",
            radius = 10, glow = true, serif = false),
        // --- terminal / editor schemes (Gogh-derived palettes) ---
        palette!("adventure-time", "Adventure Time", dark = true,
            win = "#1f1d45", view = "#17152f", surface = "#2a2755", alt = "#34306a",
            header = "#17152f", side = "#1b1940", card = "#252253", pop = "#2a2755",
            text = "#f8dcc0", dim = "#a39ac4",
            accent = "#e7741e", accent_fg = "#1f1d45", accent2 = "#5cf9ff",
            ok = "#4ab118", warn = "#e7b000", err = "#bd0013", border = "#3a356f",
            radius = 12, glow = false, serif = false),
        palette!("borland", "Borland", dark = true,
            win = "#0000a4", view = "#000084", surface = "#0a1ab0", alt = "#1730c0",
            header = "#000084", side = "#00118f", card = "#0817ac", pop = "#0a1ab0",
            text = "#ffff80", dim = "#b6b6e6",
            accent = "#ffff4e", accent_fg = "#0000a4", accent2 = "#4fe9fc",
            ok = "#4efa78", warn = "#ffff4e", err = "#ff5959", border = "#2a40c4",
            radius = 8, glow = false, serif = false),
        palette!("c64", "Commodore 64", dark = true,
            win = "#40318d", view = "#352978", surface = "#4d3ea0", alt = "#5a4bb0",
            header = "#352978", side = "#3a2e85", card = "#473a98", pop = "#4d3ea0",
            text = "#cabdf2", dim = "#9385c9",
            accent = "#bfce72", accent_fg = "#40318d", accent2 = "#67b6bd",
            ok = "#55a049", warn = "#bfce72", err = "#883932", border = "#5648a8",
            radius = 8, glow = false, serif = false),
        palette!("fairy-floss-dark", "Fairy Floss Dark", dark = true,
            win = "#3b364c", view = "#332f42", surface = "#4a4564", alt = "#56506f",
            header = "#332f42", side = "#3d3850", card = "#453f5c", pop = "#4a4564",
            text = "#f8f8f2", dim = "#c5bdda",
            accent = "#ffb8d1", accent_fg = "#3b364c", accent2 = "#c5a3ff",
            ok = "#c2ffdf", warn = "#ffea00", err = "#ff857f", border = "#564f6f",
            radius = 14, glow = false, serif = false),
        palette!("flat", "Flat", dark = true,
            win = "#2c3e50", view = "#243342", surface = "#34495e", alt = "#3e5870",
            header = "#243342", side = "#2a3a4a", card = "#324356", pop = "#34495e",
            text = "#ecf0f1", dim = "#a4b5c4",
            accent = "#3498db", accent_fg = "#ffffff", accent2 = "#9b59b6",
            ok = "#2ecc71", warn = "#f1c40f", err = "#e74c3c", border = "#3e5066",
            radius = 12, glow = false, serif = false),
        palette!("gogh", "Gogh — Starry Night", dark = true,
            win = "#0d1b34", view = "#0a1628", surface = "#14264a", alt = "#1b3260",
            header = "#0a1628", side = "#0f1d38", card = "#122243", pop = "#14264a",
            text = "#e8eeff", dim = "#94a8cc",
            accent = "#f4cd3a", accent_fg = "#0d1b34", accent2 = "#5b8dd9",
            ok = "#6bbf59", warn = "#f4cd3a", err = "#d9603b", border = "#21345f",
            radius = 12, glow = false, serif = false),
        palette!("grass", "Grass", dark = true,
            win = "#13773d", view = "#0f6234", surface = "#1c8a4a", alt = "#239a55",
            header = "#0f6234", side = "#126b38", card = "#188044", pop = "#1c8a4a",
            text = "#fff0a5", dim = "#bcd6a0",
            accent = "#e7b000", accent_fg = "#13773d", accent2 = "#7fd9b0",
            ok = "#9bea6a", warn = "#e7b000", err = "#cf3a2a", border = "#2a9a5e",
            radius = 12, glow = false, serif = false),
        palette!("gruvbox-material", "Gruvbox Material", dark = true,
            win = "#282828", view = "#1f1f1f", surface = "#32302f", alt = "#3c3836",
            header = "#1f1f1f", side = "#252423", card = "#2f2d2c", pop = "#32302f",
            text = "#d4be98", dim = "#a89984",
            accent = "#d8a657", accent_fg = "#282828", accent2 = "#7daea3",
            ok = "#a9b665", warn = "#d8a657", err = "#ea6962", border = "#45403d",
            radius = 12, glow = false, serif = false),
        palette!("homebrew", "Homebrew", dark = true,
            win = "#000000", view = "#050505", surface = "#0c140c", alt = "#122012",
            header = "#000000", side = "#040804", card = "#0a120a", pop = "#0c140c",
            text = "#00d000", dim = "#1f8a1f",
            accent = "#00ff00", accent_fg = "#001500", accent2 = "#00d8b2",
            ok = "#00c800", warn = "#9a9a00", err = "#c80000", border = "#103810",
            radius = 8, glow = true, serif = false),
        palette!("ocean", "Ocean", dark = true,
            win = "#2b303b", view = "#232831", surface = "#343d46", alt = "#3e4855",
            header = "#232831", side = "#2a2f39", card = "#313844", pop = "#343d46",
            text = "#c0c5ce", dim = "#8b95a4",
            accent = "#8fa1b3", accent_fg = "#1b2027", accent2 = "#b48ead",
            ok = "#a3be8c", warn = "#ebcb8b", err = "#bf616a", border = "#3e4855",
            radius = 12, glow = false, serif = false),
        palette!("kokuban", "Kokuban", dark = true,
            win = "#1f3526", view = "#192c1f", surface = "#274030", alt = "#2f4c39",
            header = "#192c1f", side = "#1d3123", card = "#243c2d", pop = "#274030",
            text = "#f0f0e8", dim = "#a9c2af",
            accent = "#f2e9c8", accent_fg = "#1f3526", accent2 = "#f2b4b4",
            ok = "#a8d8a0", warn = "#f0e68c", err = "#f2a0a0", border = "#315040",
            radius = 12, glow = false, serif = false),
        palette!("mono-cyan", "Mono Cyan", dark = true,
            win = "#081414", view = "#040e0e", surface = "#0e1f1f", alt = "#143030",
            header = "#040e0e", side = "#0a1818", card = "#0c1c1c", pop = "#0e1f1f",
            text = "#c8f0f0", dim = "#5c9a9a",
            accent = "#00d0d0", accent_fg = "#021616", accent2 = "#5ce0e0",
            ok = "#00d0a0", warn = "#80e0e0", err = "#e08585", border = "#163838",
            radius = 10, glow = true, serif = false),
    ]
}

/// Look up a palette by id, falling back to the first (Dracula) if unknown.
pub fn find_theme(id: &str) -> Palette {
    let mut all = builtin_themes();
    if let Some(pos) = all.iter().position(|t| t.id == id) {
        all.swap_remove(pos)
    } else {
        all.remove(0)
    }
}

/// Compile a palette into a full Notas stylesheet by mapping it onto the
/// existing `@define-color` tokens, then emitting the (tokenized) widget rules.
/// `editor_css` is the font block injected at the same point as the built-in
/// themes do.
pub fn compile_css(p: &Palette, editor_css: &str) -> String {
    format!(
        r#"
        @define-color bg_color {bg};
        @define-color surface_color {surface};
        @define-color overlay_color {overlay};
        @define-color text_color {text};
        @define-color subtext_color {subtext};
        @define-color accent_gray {accent};
        @define-color accent_light {accent2};
        @define-color border_color {border};
        @define-color focus_color {accent};

        *, *:focus, *:focus-within, *:focus-visible {{
            outline: none; outline-width: 0; box-shadow: none;
        }}

        window, .background {{ background-color: @bg_color; color: @text_color; }}

        .custom-headerbar {{
            background-color: {headerbar};
            border-bottom: 1px solid @border_color;
            padding: 4px 8px; min-height: 32px;
        }}
        .headerbar-title {{ font-family: 'DotGothic16','Noto Sans',monospace; font-size: 0.95em; font-weight: 600; color: @text_color; }}

        .traffic-btn {{ min-width:13px; min-height:13px; padding:0; margin:0 4px; border-radius:999px; border:none; font-size:0; -gtk-icon-size:0; }}
        .traffic-btn:hover {{ opacity:0.8; }}
        .traffic-close {{ background-color:#ff5f57; background-image:none; }}
        .traffic-close:hover {{ background-color:#ff3b30; background-image:none; }}
        .traffic-minimize {{ background-color:#ffbd2e; background-image:none; }}
        .traffic-minimize:hover {{ background-color:#ff9500; background-image:none; }}
        .traffic-maximize {{ background-color:#28c840; background-image:none; }}
        .traffic-maximize:hover {{ background-color:#00b341; background-image:none; }}

        .title-toggle {{ min-width:36px; min-height:18px; border-radius:9px; background-color:@overlay_color; border:1px solid @border_color; }}
        .title-toggle:checked {{ background-color:@accent_gray; }}
        .title-toggle slider {{ min-width:14px; min-height:14px; border-radius:7px; background-color:@subtext_color; }}
        .title-toggle:checked slider {{ background-color:@surface_color; }}

        .sidebar {{ background-color:{sidebar}; border-right:1px solid @border_color; }}
        .sidebar-header {{ padding:10px 10px; border-bottom:1px solid @border_color; background:transparent; }}
        .app-title {{ font-family:'DotGothic16','Noto Sans',monospace; font-size:1.3em; font-weight:bold; color:@text_color; }}
        .lock-title {{ font-family:'DotGothic16','Noto Sans',monospace; font-size:3.2em; font-weight:bold; color:@text_color; margin-bottom:12px; }}
        .lock-screen {{ background-color:@bg_color; }}
        .lock-subtitle {{ color:@subtext_color; margin-bottom:22px; font-size:0.95em; }}

        .search-entry {{ background-color:@surface_color; border:1px solid @border_color; border-radius:5px; padding:6px 8px; margin:6px 8px; color:@text_color; outline:none; }}
        .search-entry:focus {{ border-color:@focus_color; }}

        .note-list {{ background-color:transparent; }}
        .note-list row {{ padding:8px 10px; margin:1px 4px; border-radius:5px; background-color:transparent; border:1px solid transparent; }}
        .note-list row:hover {{ background-color:alpha(@overlay_color,0.6); border-color:@border_color; }}
        .note-list row:selected {{ background-color:@overlay_color; border-color:@accent_gray; }}
        .note-title {{ font-weight:600; font-size:0.9em; color:@text_color; }}
        .note-preview {{ font-size:0.78em; color:@subtext_color; margin-top:2px; }}
        .note-date {{ font-size:0.7em; color:alpha(@subtext_color,0.7); margin-top:2px; }}
        .note-pinned {{ color:{accent2}; }}

        .editor-area {{ background-color:@bg_color; padding:16px; }}
        .title-entry {{ font-size:1.3em; font-weight:bold; background-color:transparent; border:none; border-bottom:1px solid @border_color; border-radius:0; padding:6px 4px; margin-bottom:12px; color:@text_color; outline:none; }}
        .title-entry:focus {{ border-bottom-color:@focus_color; }}

        .content-view {{ background-color:@surface_color; border-radius:6px; padding:12px; color:@text_color; border:1px solid @border_color; outline:none; }}
        .content-view text {{ background-color:transparent; color:@text_color; }}
        .content-view text selection {{ background-color:alpha(@accent_gray,0.4); color:@text_color; }}
        .content-view:focus {{ border-color:@focus_color; }}

        {editor}

        .status-bar {{ background-color:{headerbar}; padding:6px 10px; border-top:1px solid @border_color; }}
        .status-text {{ color:@subtext_color; font-size:0.8em; }}

        .action-button {{ background:@surface_color; color:@text_color; border:1px solid @accent_gray; border-radius:5px; padding:7px 14px; font-weight:600; font-size:0.9em; outline:none; }}
        .action-button:hover {{ background:@overlay_color; border-color:@accent_light; }}

        .secondary-button {{ background:@surface_color; color:@subtext_color; border:1px solid @border_color; border-radius:5px; padding:6px 10px; font-size:0.85em; outline:none; }}
        .secondary-button:hover {{ border-color:@accent_gray; color:@text_color; }}

        .status-button {{ background:@surface_color; color:@subtext_color; border:1px solid @border_color; border-radius:4px; padding:4px 10px; font-size:0.8em; min-height:0; min-width:0; outline:none; }}
        .status-button:hover {{ border-color:@accent_gray; color:@text_color; }}

        .icon-button {{ background-color:transparent; border:none; border-radius:5px; padding:6px; min-width:28px; min-height:28px; color:@subtext_color; font-size:0.95em; outline:none; }}
        .icon-button:hover {{ background-color:@overlay_color; color:@text_color; }}

        .password-entry {{ background-color:@surface_color; border:1px solid @border_color; border-radius:6px; padding:12px 16px; font-size:1.05em; min-width:280px; color:@text_color; outline:none; }}
        .password-entry:focus {{ border-color:@focus_color; }}

        .unlock-button {{ background:@surface_color; color:@text_color; border:1px solid @accent_gray; border-radius:6px; padding:12px 32px; font-size:1.05em; font-weight:600; margin-top:14px; outline:none; }}
        .unlock-button:hover {{ background:@overlay_color; border-color:@accent_light; }}

        .error-label {{ color:{error}; font-size:0.88em; }}
        .success-label {{ color:{success}; font-size:0.88em; }}

        .preferences-group {{ background:@surface_color; border-radius:6px; padding:12px; margin:6px 0; border:1px solid @border_color; }}
        .preferences-title {{ font-weight:600; font-size:0.7em; color:@subtext_color; margin-bottom:10px; text-transform:uppercase; letter-spacing:1px; }}

        spinbutton {{ background-color:@surface_color; border:1px solid @border_color; border-radius:4px; color:@text_color; outline:none; }}
        spinbutton:focus {{ border-color:@focus_color; }}
        entry {{ background-color:@surface_color; border:1px solid @border_color; border-radius:4px; padding:6px 8px; color:@text_color; outline:none; }}
        entry:focus {{ border-color:@focus_color; }}
        checkbutton {{ color:@text_color; }}
        checkbutton check {{ background-color:@surface_color; border:1px solid @border_color; border-radius:3px; }}
        checkbutton:checked check {{ background-color:@accent_gray; border-color:@accent_light; }}
        switch {{ background-color:@overlay_color; border:1px solid @border_color; }}
        switch:checked {{ background-color:@accent_gray; }}
        dropdown button {{ background-color:@surface_color; border:1px solid @border_color; color:@text_color; border-radius:4px; padding:4px 8px; outline:none; }}
        dropdown button:focus {{ border-color:@focus_color; }}
    "#,
        bg = p.window_bg,
        surface = p.card,
        overlay = p.surface_alt,
        text = p.text,
        subtext = p.text_dim,
        accent = p.accent,
        accent2 = if p.accent2.is_empty() { &p.accent } else { &p.accent2 },
        border = p.border,
        headerbar = p.headerbar,
        sidebar = p.sidebar,
        error = p.error,
        success = p.success,
        editor = editor_css,
    ) + crate::MENU_CSS
}
