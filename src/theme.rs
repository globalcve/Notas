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

        // ── Ported from the Ptyxis / Gogh terminal palettes ──────────────────
        // Generated from the raw `.palette` keyfiles (and the curated accent set
        // in the Android theme port), then checked in. Background, Foreground and
        // the accent slots are verbatim from each palette; the UI surfaces
        // (view/sidebar/headerbar/card/border) are blends of Background toward
        // black or white in the same proportions the hand-written entries above
        // use, so each theme keeps its own hue. Themes shipping both Light and
        // Dark variants contribute their Dark one, matching the set above.
        palette!("aci", "Aci", dark = true,
            win = "#0d1926", view = "#0b141f", surface = "#202b37", alt = "#2f3944",
            header = "#0b141f", side = "#0c1723", card = "#1c2733", pop = "#202b37",
            text = "#b4e1fd", dim = "#7595ab",
            accent = "#1e8eff", accent_fg = "#0d1926", accent2 = "#8e1eff",
            ok = "#83ff08", warn = "#ff8e1e", err = "#ff1e8e", border = "#343e49",
            radius = 12, glow = false, serif = false),
        palette!("afterglow", "Afterglow", dark = true,
            win = "#222222", view = "#1c1c1c", surface = "#343434", alt = "#414141",
            header = "#1c1c1c", side = "#1f1f1f", card = "#2f2f2f", pop = "#343434",
            text = "#d0d0d0", dim = "#8e8e8e",
            accent = "#6c99bb", accent_fg = "#222222", accent2 = "#9f4e85",
            ok = "#7b9246", warn = "#d3a04d", err = "#a53c23", border = "#454545",
            radius = 12, glow = false, serif = false),
        palette!("argonaut", "Argonaut", dark = true,
            win = "#0e1019", view = "#0b0d14", surface = "#21232b", alt = "#303139",
            header = "#0b0d14", side = "#0d0f17", card = "#1c1e27", pop = "#21232b",
            text = "#fffaf4", dim = "#a3a1a1",
            accent = "#0092ff", accent_fg = "#fffaf4", accent2 = "#9a5feb",
            ok = "#8ce10b", warn = "#ffb900", err = "#ff2740", border = "#35363e",
            radius = 12, glow = false, serif = false),
        palette!("aura", "Aura", dark = true,
            win = "#15141b", view = "#111016", surface = "#28272d", alt = "#36353b",
            header = "#111016", side = "#131219", card = "#232229", pop = "#28272d",
            text = "#edecee", dim = "#9b9a9e",
            accent = "#a277ff", accent_fg = "#15141b", accent2 = "#a277ff",
            ok = "#61ffca", warn = "#ffca85", err = "#ffca85", border = "#3a3a3f",
            radius = 12, glow = false, serif = false),
        palette!("ayu-mirage", "Ayu Mirage", dark = true,
            win = "#1f2430", view = "#191e27", surface = "#313641", alt = "#3e434d",
            header = "#191e27", side = "#1d212c", card = "#2c313c", pop = "#313641",
            text = "#cbccc6", dim = "#8a8c8d",
            accent = "#73d0ff", accent_fg = "#1f2430", accent2 = "#d4bfff",
            ok = "#bae67e", warn = "#ffa759", err = "#ff3333", border = "#434751",
            radius = 12, glow = false, serif = false),
        palette!("belafonte", "Belafonte", dark = true,
            win = "#20111b", view = "#1a0e16", surface = "#32242d", alt = "#3f323b",
            header = "#1a0e16", side = "#1d1019", card = "#2d1f29", pop = "#32242d",
            text = "#968c83", dim = "#695d5b",
            accent = "#426a79", accent_fg = "#20111b", accent2 = "#97522c",
            ok = "#858162", warn = "#eaa549", err = "#be100e", border = "#44373f",
            radius = 12, glow = false, serif = false),
        palette!("birds-of-paradise", "Birds Of Paradise", dark = true,
            win = "#2a1f1d", view = "#221918", surface = "#3b312f", alt = "#483e3d",
            header = "#221918", side = "#271d1b", card = "#372c2b", pop = "#3b312f",
            text = "#e0dbb7", dim = "#9b947c",
            accent = "#b8d3ed", accent_fg = "#2a1f1d", accent2 = "#d19ecb",
            ok = "#95d8ba", warn = "#d0d150", err = "#e84627", border = "#4c4341",
            radius = 12, glow = false, serif = false),
        palette!("blazer", "Blazer", dark = true,
            win = "#0d1926", view = "#0b141f", surface = "#202b37", alt = "#2f3944",
            header = "#0b141f", side = "#0c1723", card = "#1c2733", pop = "#202b37",
            text = "#d9e6f2", dim = "#8b98a4",
            accent = "#bdbddb", accent_fg = "#0d1926", accent2 = "#dbbddb",
            ok = "#bddbbd", warn = "#dbdbbd", err = "#dbbdbd", border = "#343e49",
            radius = 12, glow = false, serif = false),
        palette!("brogrammer", "Brogrammer", dark = true,
            win = "#131313", view = "#101010", surface = "#262626", alt = "#343434",
            header = "#101010", side = "#111111", card = "#212121", pop = "#262626",
            text = "#d6dbe5", dim = "#8c8f95",
            accent = "#1081d6", accent_fg = "#d6dbe5", accent2 = "#4e5ab7",
            ok = "#1dd361", warn = "#f3bd09", err = "#de352e", border = "#393939",
            radius = 12, glow = false, serif = false),
        palette!("chalkboard", "Chalkboard", dark = true,
            win = "#29262f", view = "#221f27", surface = "#3a3740", alt = "#47444c",
            header = "#221f27", side = "#26232b", card = "#36333b", pop = "#3a3740",
            text = "#d9e6f2", dim = "#969da8",
            accent = "#aaaadb", accent_fg = "#29262f", accent2 = "#dbaada",
            ok = "#aadbaa", warn = "#dadbaa", err = "#dbaaaa", border = "#4b4950",
            radius = 12, glow = false, serif = false),
        palette!("espresso-libre", "Espresso Libre", dark = true,
            win = "#2a211c", view = "#221b17", surface = "#3b332e", alt = "#48403c",
            header = "#221b17", side = "#271e1a", card = "#372e2a", pop = "#3b332e",
            text = "#b8a898", dim = "#827569",
            accent = "#43a8ed", accent_fg = "#2a211c", accent2 = "#ff818a",
            ok = "#9aff87", warn = "#fffb5c", err = "#ef2929", border = "#4c4540",
            radius = 12, glow = false, serif = false),
        palette!("everforest", "Everforest", dark = true,
            win = "#2d353b", view = "#252b30", surface = "#3e454b", alt = "#4a5156",
            header = "#252b30", side = "#293136", card = "#3a4147", pop = "#3e454b",
            text = "#d3c6aa", dim = "#948f80",
            accent = "#7fbbb3", accent_fg = "#2d353b", accent2 = "#d699b6",
            ok = "#8da101", warn = "#dfa000", err = "#e67e80", border = "#4f555a",
            radius = 12, glow = false, serif = false),
        palette!("flatland", "Flatland", dark = true,
            win = "#1d1f21", view = "#18191b", surface = "#2f3133", alt = "#3d3e40",
            header = "#18191b", side = "#1b1d1e", card = "#2b2c2e", pop = "#2f3133",
            text = "#b8dbef", dim = "#7d94a1",
            accent = "#61b9d0", accent_fg = "#1d1f21", accent2 = "#695abc",
            ok = "#a7d42c", warn = "#f4ef6d", err = "#f18339", border = "#414345",
            radius = 12, glow = false, serif = false),
        palette!("github", "Github", dark = true,
            win = "#101216", view = "#0d0f12", surface = "#232529", alt = "#313337",
            header = "#0d0f12", side = "#0f1114", card = "#1e2024", pop = "#232529",
            text = "#8b949e", dim = "#5c636a",
            accent = "#6ca4f8", accent_fg = "#101216", accent2 = "#db61a2",
            ok = "#56d364", warn = "#e3b341", err = "#f78166", border = "#36383b",
            radius = 12, glow = false, serif = false),
        palette!("ibm3270", "Ibm3270", dark = true,
            win = "#000000", view = "#000000", surface = "#141414", alt = "#242424",
            header = "#000000", side = "#000000", card = "#0f0f0f", pop = "#141414",
            text = "#fdfdfd", dim = "#9d9d9d",
            accent = "#b3bfef", accent_fg = "#000000", accent2 = "#efb3e3",
            ok = "#24d830", warn = "#f0d824", err = "#ef8383", border = "#292929",
            radius = 12, glow = false, serif = false),
        palette!("ic-green-ppl", "Ic Green Ppl", dark = true,
            win = "#3a3d3f", view = "#303234", surface = "#4a4d4e", alt = "#56585a",
            header = "#303234", side = "#35383a", card = "#46494b", pop = "#4a4d4e",
            text = "#d9efd3", dim = "#9dab9b",
            accent = "#72ffb5", accent_fg = "#3a3d3f", accent2 = "#50ff3e",
            ok = "#9fff6d", warn = "#d2ff6d", err = "#a7ff3f", border = "#5a5c5e",
            radius = 12, glow = false, serif = false),
        palette!("kanagawa", "Kanagawa", dark = true,
            win = "#1f1f28", view = "#191921", surface = "#313139", alt = "#3e3e46",
            header = "#191921", side = "#1d1d25", card = "#2c2c35", pop = "#313139",
            text = "#dcd7ba", dim = "#949183",
            accent = "#7fb4ca", accent_fg = "#1f1f28", accent2 = "#957fb8",
            ok = "#98bb6c", warn = "#e6c384", err = "#e82424", border = "#43434a",
            radius = 12, glow = false, serif = false),
        palette!("material", "Material", dark = true,
            win = "#1e282c", view = "#192124", surface = "#30393d", alt = "#3e464a",
            header = "#192124", side = "#1c2528", card = "#2c3539", pop = "#30393d",
            text = "#c3c7d1", dim = "#848b92",
            accent = "#80cbc3", accent_fg = "#1e282c", accent2 = "#ff2490",
            ok = "#c3e88d", warn = "#f7eb95", err = "#eb606b", border = "#424a4e",
            radius = 12, glow = false, serif = false),
        palette!("mona-lisa", "Mona Lisa", dark = true,
            win = "#120b0d", view = "#0f090b", surface = "#251f20", alt = "#332d2f",
            header = "#0f090b", side = "#110a0c", card = "#201a1c", pop = "#251f20",
            text = "#f7d66a", dim = "#a08947",
            accent = "#9eb2b4", accent_fg = "#120b0d", accent2 = "#ff5b6a",
            ok = "#b4b264", warn = "#ff9566", err = "#ff4331", border = "#383234",
            radius = 12, glow = false, serif = false),
        palette!("monokai-pro", "Monokai Pro", dark = true,
            win = "#363537", view = "#2c2b2d", surface = "#464547", alt = "#525153",
            header = "#2c2b2d", side = "#323133", card = "#424143", pop = "#464547",
            text = "#fdf9f3", dim = "#b1afac",
            accent = "#fc9867", accent_fg = "#363537", accent2 = "#ab9df2",
            ok = "#a9dc76", warn = "#ffd866", err = "#ff6188", border = "#565557",
            radius = 12, glow = false, serif = false),
        palette!("omni", "Omni", dark = true,
            win = "#191622", view = "#14121c", surface = "#2b2934", alt = "#393741",
            header = "#14121c", side = "#17141f", card = "#27242f", pop = "#2b2934",
            text = "#abb2bf", dim = "#747783",
            accent = "#78d1e1", accent_fg = "#191622", accent2 = "#988bc7",
            ok = "#67e480", warn = "#e89e64", err = "#e96379", border = "#3e3b45",
            radius = 12, glow = false, serif = false),
        palette!("paraiso-dark", "Paraiso Dark", dark = true,
            win = "#2f1e2e", view = "#271926", surface = "#40303f", alt = "#4c3e4b",
            header = "#271926", side = "#2b1c2a", card = "#3b2c3b", pop = "#40303f",
            text = "#a39e9b", dim = "#776d72",
            accent = "#06b6ef", accent_fg = "#2f1e2e", accent2 = "#815ba4",
            ok = "#48b685", warn = "#fec418", err = "#ef6155", border = "#50424f",
            radius = 12, glow = false, serif = false),
        palette!("pixiefloss", "Pixiefloss", dark = true,
            win = "#241f33", view = "#1e192a", surface = "#363143", alt = "#433e50",
            header = "#1e192a", side = "#211d2f", card = "#312c3f", pop = "#363143",
            text = "#d1cae8", dim = "#8f89a3",
            accent = "#c5a3ff", accent_fg = "#241f33", accent2 = "#ef6155",
            ok = "#5adba2", warn = "#e6c000", err = "#ff857f", border = "#474354",
            radius = 12, glow = false, serif = false),
        palette!("powershell", "Powershell", dark = true,
            win = "#052454", view = "#041e45", surface = "#193662", alt = "#28436c",
            header = "#041e45", side = "#05214d", card = "#14315e", pop = "#193662",
            text = "#f6f6f7", dim = "#9aa6b9",
            accent = "#268ad2", accent_fg = "#f6f6f7", accent2 = "#fe13fa",
            ok = "#1cfe3c", warn = "#fefe45", err = "#ef2929", border = "#2d476f",
            radius = 12, glow = false, serif = false),
        palette!("relaxed", "Relaxed", dark = true,
            win = "#353a44", view = "#2b3038", surface = "#454a53", alt = "#51565e",
            header = "#2b3038", side = "#31353f", card = "#41464f", pop = "#454a53",
            text = "#d9d9d9", dim = "#9b9da0",
            accent = "#7eaac7", accent_fg = "#353a44", accent2 = "#b06698",
            ok = "#a0ac77", warn = "#ebc17a", err = "#bc5653", border = "#555a62",
            radius = 12, glow = false, serif = false),
        palette!("sea-shells", "Sea Shells", dark = true,
            win = "#09141b", view = "#071016", surface = "#1d272d", alt = "#2b353b",
            header = "#071016", side = "#081219", card = "#182229", pop = "#1d272d",
            text = "#deb88d", dim = "#8d7a62",
            accent = "#1bbcdd", accent_fg = "#09141b", accent2 = "#68d4f1",
            ok = "#027c9b", warn = "#fdd39f", err = "#d48678", border = "#303a3f",
            radius = 12, glow = false, serif = false),
        palette!("solarized", "Solarized", dark = true,
            win = "#002b36", view = "#00232c", surface = "#143c46", alt = "#244952",
            header = "#00232c", side = "#002832", card = "#0f3842", pop = "#143c46",
            text = "#839496", dim = "#516c72",
            accent = "#2699ff", accent_fg = "#002b36", accent2 = "#d33682",
            ok = "#859900", warn = "#cf9a6b", err = "#d87979", border = "#294d56",
            radius = 12, glow = false, serif = false),
        palette!("spacedust", "Spacedust", dark = true,
            win = "#0a1e24", view = "#08191e", surface = "#1e3036", alt = "#2c3e43",
            header = "#08191e", side = "#091c21", card = "#192c31", pop = "#1e3036",
            text = "#ecf0c1", dim = "#96a085",
            accent = "#67a0ce", accent_fg = "#0a1e24", accent2 = "#ff8a3a",
            ok = "#aecab8", warn = "#ffc878", err = "#ff8a3a", border = "#314247",
            radius = 12, glow = false, serif = false),
        palette!("spring", "Spring", dark = true,
            win = "#0a1e24", view = "#08191e", surface = "#1e3036", alt = "#2c3e43",
            header = "#08191e", side = "#091c21", card = "#192c31", pop = "#1e3036",
            text = "#ecf0c1", dim = "#96a085",
            accent = "#1dd3ee", accent_fg = "#0a1e24", accent2 = "#8959a8",
            ok = "#1fc231", warn = "#d5b807", err = "#ff4d83", border = "#314247",
            radius = 12, glow = false, serif = false),
        palette!("twilight", "Twilight", dark = true,
            win = "#141414", view = "#101010", surface = "#272727", alt = "#353535",
            header = "#101010", side = "#121212", card = "#222222", pop = "#272727",
            text = "#ffffd4", dim = "#a6a68b",
            accent = "#5a5e62", accent_fg = "#ffffd4", accent2 = "#d0dc8e",
            ok = "#ccd88c", warn = "#e2c47e", err = "#de7c4c", border = "#3a3a3a",
            radius = 12, glow = false, serif = false),
        palette!("urple", "Urple", dark = true,
            win = "#1b1b23", view = "#16161d", surface = "#2d2d35", alt = "#3b3b42",
            header = "#16161d", side = "#191920", card = "#292930", pop = "#2d2d35",
            text = "#877a9b", dim = "#5e566d",
            accent = "#867aed", accent_fg = "#1b1b23", accent2 = "#a05eee",
            ok = "#29e620", warn = "#f08161", err = "#ff6388", border = "#3f3f46",
            radius = 12, glow = false, serif = false),
        palette!("xterm", "XTerm", dark = true,
            win = "#000000", view = "#000000", surface = "#141414", alt = "#242424",
            header = "#000000", side = "#000000", card = "#0f0f0f", pop = "#141414",
            text = "#ffffff", dim = "#9e9e9e",
            accent = "#5c5cff", accent_fg = "#ffffff", accent2 = "#ff00ff",
            ok = "#00ff00", warn = "#ffff00", err = "#ff0000", border = "#292929",
            radius = 12, glow = false, serif = false),
        palette!("nord", "Nord", dark = true,
            win = "#2e3440", view = "#262b34", surface = "#3f444f", alt = "#4b505b",
            header = "#262b34", side = "#2a303b", card = "#3b404b", pop = "#3f444f",
            text = "#d8dee9", dim = "#979da9",
            accent = "#88c0d0", accent_fg = "#2e3440", accent2 = "#81a1c1",
            ok = "#8fbcbb", warn = "#9ac9d7", err = "#bf616a", border = "#4f545f",
            radius = 12, glow = false, serif = false),
        palette!("bim", "Bim", dark = true,
            win = "#012849", view = "#01213c", surface = "#153958", alt = "#254662",
            header = "#01213c", side = "#012543", card = "#103554", pop = "#153958",
            text = "#a9bed8", dim = "#6985a2",
            accent = "#5ea2ec", accent_fg = "#012849", accent2 = "#f557a0",
            ok = "#a9ee55", warn = "#76b0ef", err = "#f557a0", border = "#2a4a66",
            radius = 12, glow = false, serif = false),
        palette!("cobalt-neon", "Cobalt Neon", dark = true,
            win = "#142838", view = "#10212e", surface = "#273948", alt = "#354654",
            header = "#10212e", side = "#122534", card = "#223544", pop = "#273948",
            text = "#8ff586", dim = "#60a768",
            accent = "#8ff586", accent_fg = "#142838", accent2 = "#3ba5ff",
            ok = "#e9e75c", warn = "#a0f698", err = "#ff2320", border = "#3a4a58",
            radius = 12, glow = false, serif = false),
        palette!("homebrew-ocean", "Homebrew Ocean", dark = true,
            win = "#224fbc", view = "#1c419a", surface = "#345dc1", alt = "#4168c5",
            header = "#1c419a", side = "#1f49ad", card = "#2f5ac0", pop = "#345dc1",
            text = "#ffffff", dim = "#abbce6",
            accent = "#00a6b2", accent_fg = "#ffffff", accent2 = "#00a600",
            ok = "#999900", warn = "#26b3be", err = "#990000", border = "#456bc7",
            radius = 12, glow = false, serif = false),
        palette!("mono-amber", "Mono Amber", dark = true,
            win = "#2b1900", view = "#231400", surface = "#3c2b14", alt = "#493924",
            header = "#231400", side = "#281700", card = "#38270f", pop = "#3c2b14",
            text = "#ff9400", dim = "#ae6500",
            accent = "#ff9400", accent_fg = "#2b1900", accent2 = "#ff9400",
            ok = "#ff9400", warn = "#ffa426", err = "#ff9400", border = "#4d3e29",
            radius = 12, glow = false, serif = false),
        palette!("mono-red", "Mono Red", dark = true,
            win = "#2b0c00", view = "#230a00", surface = "#3c1f14", alt = "#492e24",
            header = "#230a00", side = "#280b00", card = "#381b0f", pop = "#3c1f14",
            text = "#ff3600", dim = "#ae2600",
            accent = "#ff3600", accent_fg = "#2b0c00", accent2 = "#ff3600",
            ok = "#ff3600", warn = "#ff5426", err = "#ff3600", border = "#4d3329",
            radius = 12, glow = false, serif = false),
        palette!("synthwave", "Synthwave", dark = true,
            win = "#262335", view = "#1f1d2b", surface = "#373545", alt = "#444251",
            header = "#1f1d2b", side = "#232031", card = "#333041", pop = "#373545",
            text = "#ffffff", dim = "#adabb2",
            accent = "#ff7edb", accent_fg = "#262335", accent2 = "#03edf9",
            ok = "#fede5d", warn = "#ff91e0", err = "#fe4450", border = "#494655",
            radius = 12, glow = false, serif = false),
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
    ) + crate::MENU_CSS + crate::CONTROL_CSS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every colour a palette carries, so the checks below cannot silently skip
    /// a field somebody adds later.
    fn colours(p: &Palette) -> Vec<(&'static str, &str)> {
        vec![
            ("window_bg", &p.window_bg), ("view_bg", &p.view_bg),
            ("surface", &p.surface), ("surface_alt", &p.surface_alt),
            ("headerbar", &p.headerbar), ("sidebar", &p.sidebar),
            ("card", &p.card), ("popover", &p.popover),
            ("text", &p.text), ("text_dim", &p.text_dim),
            ("accent", &p.accent), ("accent_fg", &p.accent_fg),
            ("accent2", &p.accent2), ("success", &p.success),
            ("warning", &p.warning), ("error", &p.error), ("border", &p.border),
        ]
    }

    fn luminance(hex: &str) -> f32 {
        let h = hex.trim_start_matches('#');
        let ch = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).unwrap() as f32 / 255.0;
        0.2126 * ch(0) + 0.7152 * ch(2) + 0.0722 * ch(4)
    }

    #[test]
    fn palette_ids_are_unique() {
        // A duplicate id would make `find_theme` return the wrong palette and the
        // settings dropdown select the wrong row.
        let mut ids: Vec<String> = builtin_themes().into_iter().map(|p| p.id).collect();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate palette id");
    }

    #[test]
    fn every_colour_is_a_six_digit_hex_triplet() {
        // These are interpolated straight into CSS; a malformed one takes out the
        // whole stylesheet, not just its own rule.
        for p in builtin_themes() {
            for (field, value) in colours(&p) {
                assert!(
                    value.len() == 7
                        && value.starts_with('#')
                        && value[1..].chars().all(|c| c.is_ascii_hexdigit()),
                    "{}.{field} = {value:?} is not #rrggbb",
                    p.id
                );
            }
        }
    }

    #[test]
    fn text_stands_off_its_background() {
        // Guards the derived palettes in particular: a blend that lands too close
        // to the background would ship an unreadable theme.
        for p in builtin_themes() {
            let contrast = (luminance(&p.text) - luminance(&p.window_bg)).abs();
            assert!(contrast > 0.2, "{}: text/background contrast {contrast:.2}", p.id);
            let dim = (luminance(&p.text_dim) - luminance(&p.window_bg)).abs();
            assert!(dim > 0.05, "{}: dim-text contrast {dim:.2}", p.id);
        }
    }

    #[test]
    fn find_theme_falls_back_for_unknown_ids() {
        assert_eq!(find_theme("dracula").id, "dracula");
        assert_eq!(find_theme("synthwave").name, "Synthwave");
        assert_eq!(find_theme("no-such-theme").id, builtin_themes()[0].id);
    }
}
