//! Glass mode — translucent, luminous window surfaces.
//!
//! The whole trick is to repaint every large surface with an `rgba()` colour
//! whose alpha is < 1 so the compositor shows the desktop behind the window,
//! then put a 1px luminous hairline plus an inner top-glow on the "edge"
//! surfaces (headerbar / status bar) to sell the glass.
//!
//! Two things make this safe to bolt onto Notas' existing stylesheets:
//!
//! 1. **Every rule is scoped to `window.glassy`** — only the lock screen and the
//!    main window carry that class. Preferences, the password generator and the
//!    `adw::MessageDialog`s are separate toplevels without it, so they stay
//!    fully opaque and can never "ghost" the window underneath them.
//! 2. **Every rule sets `background-image: none`** — the built-in Notas Dark and
//!    Light themes paint their body, sidebar, editor area and status bar with
//!    `linear-gradient(...)`, which is a background *image*. A `background-color`
//!    alone would sit behind that gradient and change nothing.
//!
//! Colours are derived from whichever theme is active (including all the ported
//! tesseract palettes), so glass mode is a modifier on the current theme rather
//! than a theme of its own.
//!
//! Note for GNOME/Mutter (the target here): the compositor does **not** blur
//! behind arbitrary app windows, so this is clean translucency, not frost. That
//! is why the body alpha floor is deliberately kept fairly high — text has to
//! stay readable over an unblurred wallpaper.

use crate::core::data::AppTheme;

/// The four surface colours glass mode needs out of a theme, plus whether the
/// theme is dark (which picks the hairline / glow colours).
pub struct GlassColors {
    /// Window body.
    pub base: String,
    /// Sidebar — reads clearer than the body.
    pub side: String,
    /// Headerbar and status bar — the clearest "glass edge".
    pub head: String,
    /// Cards and the note editor.
    pub surf: String,
    /// Hover/selected fills, which must stay legible against the desktop.
    pub overlay: String,
    pub dark: bool,
}

/// Map the active theme onto [`GlassColors`].
///
/// The two built-in themes are gradients rather than flat colours, so we pick a
/// representative mid-stop from each gradient; the ported palettes already have
/// named fields for exactly these surfaces.
pub fn colors_for(theme: &AppTheme) -> GlassColors {
    match theme {
        AppTheme::Dark => GlassColors {
            base: "#0c0c0f".into(),
            side: "#101012".into(),
            head: "#141418".into(),
            surf: "#0e0e12".into(),
            overlay: "#1a1a1f".into(),
            dark: true,
        },
        AppTheme::Light => GlassColors {
            base: "#f2f2f2".into(),
            side: "#ffffff".into(),
            head: "#e6e6e6".into(),
            surf: "#ffffff".into(),
            overlay: "#e6e6e6".into(),
            dark: false,
        },
        AppTheme::Palette(id) => {
            let p = crate::theme::find_theme(id);
            GlassColors {
                base: p.window_bg.clone(),
                side: p.sidebar.clone(),
                head: p.headerbar.clone(),
                // `compile_css` maps @surface_color (used by .content-view) to
                // the palette's card colour, so match it here.
                surf: p.card.clone(),
                overlay: p.surface_alt.clone(),
                dark: p.dark,
            }
        }
    }
}

/// Parse a `#rrggbb` (or `#rgb`) string into an `rgba(r,g,b,a)` CSS function.
/// Unparseable input falls back to mid-grey so a bad palette entry degrades to
/// something visible rather than to a CSS parse error.
fn rgba(hex: &str, alpha: f32) -> String {
    let h = hex.trim().trim_start_matches('#');
    let (r, g, b) = match h.len() {
        6 => (
            u8::from_str_radix(&h[0..2], 16).ok(),
            u8::from_str_radix(&h[2..4], 16).ok(),
            u8::from_str_radix(&h[4..6], 16).ok(),
        ),
        3 => {
            let dup = |c: &str| u8::from_str_radix(&c.repeat(2), 16).ok();
            (dup(&h[0..1]), dup(&h[1..2]), dup(&h[2..3]))
        }
        _ => (None, None, None),
    };
    match (r, g, b) {
        (Some(r), Some(g), Some(b)) => {
            format!("rgba({},{},{},{:.3})", r, g, b, alpha.clamp(0.0, 1.0))
        }
        _ => format!("rgba(128,128,128,{:.3})", alpha.clamp(0.0, 1.0)),
    }
}

/// Lowest alpha we will emit. Below this, unblurred wallpaper bleeds through
/// enough to make note text genuinely hard to read on GNOME.
const MIN_ALPHA: f32 = 0.20;

/// Build the glass stylesheet for a theme at a given body opacity (percent).
///
/// The layer alphas step down from the body so panels read progressively
/// clearer, in the same proportions used by Box: sidebars -0.20, the headerbar
/// edge -0.25, the editor -0.15.
pub fn glass_css(theme: &AppTheme, opacity_pct: u32) -> String {
    let c = colors_for(theme);

    let a = (opacity_pct.clamp(30, 100) as f32) / 100.0;
    let step = |delta: f32| (a - delta).max(MIN_ALPHA);
    let a_side = step(0.20);
    let a_head = step(0.25);
    let a_content = step(0.15);

    // Hairline + inner glow. On dark themes the edge is a white sliver; on light
    // themes it has to be a dark line or it simply is not visible.
    let (edge, glow) = if c.dark {
        ("rgba(255,255,255,0.09)", "rgba(255,255,255,0.05)")
    } else {
        ("rgba(0,0,0,0.10)", "rgba(255,255,255,0.35)")
    };

    let body = rgba(&c.base, a);
    let sidebar = rgba(&c.side, a_side);
    let editor_area = rgba(&c.base, a_side);
    let header = rgba(&c.head, a_head);
    let content = rgba(&c.surf, a_content);
    // Popovers and the find bar sit *over* already-translucent surfaces, so they
    // need to be denser than the body or their text stacks onto the wallpaper.
    let raised = rgba(&c.surf, (a + 0.12).min(1.0));
    // Row hover/selection must remain readable, hence near-opaque.
    let row = rgba(&c.overlay, (a + 0.08).min(1.0));

    format!(
        "/* Notas glass mode — generated; scoped to window.glassy so dialogs stay opaque. */\n\
         window.glassy, window.glassy.background {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {body};\n\
         }}\n\
         window.glassy.lock-screen {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {body};\n\
         }}\n\
         window.glassy .sidebar {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {sidebar};\n\
         \x20   border-right: 1px solid {edge};\n\
         }}\n\
         window.glassy .sidebar-header {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: transparent;\n\
         \x20   border-bottom: 1px solid {edge};\n\
         }}\n\
         window.glassy .editor-area {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {editor_area};\n\
         }}\n\
         /* The glass edge: header + status bar get the hairline and top glow. */\n\
         window.glassy .custom-headerbar,\n\
         window.glassy headerbar,\n\
         window.glassy .titlebar {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {header};\n\
         \x20   border-bottom: 1px solid {edge};\n\
         \x20   box-shadow: inset 0 1px 0 {glow};\n\
         }}\n\
         window.glassy .status-bar {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {header};\n\
         \x20   border-top: 1px solid {edge};\n\
         \x20   box-shadow: inset 0 1px 0 {glow};\n\
         }}\n\
         window.glassy .content-view {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {content};\n\
         \x20   border: 1px solid {edge};\n\
         }}\n\
         window.glassy .content-view text {{\n\
         \x20   background-color: transparent;\n\
         }}\n\
         /* Scrollers/viewports would otherwise paint an opaque view background\n\
            over the translucent surfaces they sit on. */\n\
         window.glassy scrolledwindow,\n\
         window.glassy viewport,\n\
         window.glassy stack,\n\
         window.glassy listbox,\n\
         window.glassy .note-list,\n\
         window.glassy textview {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: transparent;\n\
         }}\n\
         window.glassy .note-list row:hover {{\n\
         \x20   background-color: {row};\n\
         \x20   border-color: {edge};\n\
         }}\n\
         window.glassy .note-list row:selected {{\n\
         \x20   background-color: {row};\n\
         }}\n\
         window.glassy .find-bar {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {raised};\n\
         \x20   border-bottom: 1px solid {edge};\n\
         }}\n\
         /* Popovers are child surfaces of the glassy window, so they inherit the\n\
            look but stay denser to keep menu text legible. */\n\
         window.glassy popover > contents,\n\
         window.glassy popover contents {{\n\
         \x20   background-image: none;\n\
         \x20   background-color: {raised};\n\
         \x20   border: 1px solid {edge};\n\
         }}\n",
        body = body,
        sidebar = sidebar,
        editor_area = editor_area,
        header = header,
        content = content,
        raised = raised,
        row = row,
        edge = edge,
        glow = glow,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgba_parses_six_and_three_digit_hex() {
        assert_eq!(rgba("#ff8000", 0.5), "rgba(255,128,0,0.500)");
        assert_eq!(rgba("f80", 1.0), "rgba(255,136,0,1.000)");
    }

    #[test]
    fn rgba_falls_back_on_garbage() {
        assert_eq!(rgba("not-a-colour", 0.25), "rgba(128,128,128,0.250)");
    }

    #[test]
    fn alphas_step_down_and_respect_the_floor() {
        // At the minimum opacity every derived layer clamps to the floor rather
        // than going transparent (or negative).
        let css = glass_css(&AppTheme::Dark, 30);
        assert!(css.contains("rgba(16,16,18,0.200)"), "sidebar clamped: {css}");
        // At a normal opacity the layers are distinct and ordered.
        let css = glass_css(&AppTheme::Dark, 78);
        assert!(css.contains("0.780")); // body
        assert!(css.contains("0.580")); // sidebar
        assert!(css.contains("0.530")); // header
        assert!(css.contains("0.630")); // editor
    }

    #[test]
    fn every_rule_is_scoped_to_the_glassy_window() {
        // A rule that escaped the scope would make Preferences translucent too.
        for theme in [
            AppTheme::Dark,
            AppTheme::Light,
            AppTheme::Palette("dracula".into()),
        ] {
            let css = glass_css(&theme, 78);
            for line in css.lines() {
                let line = line.trim();
                let is_selector = line.ends_with('{') || line.ends_with(',');
                if is_selector && !line.starts_with("/*") {
                    assert!(
                        line.starts_with("window.glassy"),
                        "unscoped selector: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn light_theme_uses_a_dark_hairline() {
        let css = glass_css(&AppTheme::Light, 78);
        assert!(css.contains("rgba(0,0,0,0.10)"));
    }
}
