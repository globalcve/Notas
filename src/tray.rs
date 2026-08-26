//! System tray icon (freedesktop StatusNotifierItem) + quick-note menu.
//!
//! # Why StatusNotifierItem and not libappindicator
//!
//! `libappindicator` is a **GTK3** library — linking it into this GTK4 process
//! would pull two incompatible GTK versions into one address space and abort at
//! startup. `ksni` speaks the StatusNotifierItem D-Bus protocol directly over
//! `zbus` (pure Rust, no C dependency), which is exactly what GNOME's
//! `ubuntu-appindicators` extension consumes. It runs on its own thread with its
//! own single-threaded executor, entirely separate from the app's tokio runtime.
//!
//! # Why the icon is a generated pixmap rather than an icon name
//!
//! An `IconName` only resolves if the icon is installed in a theme directory the
//! shell happens to search — which is not true for a binary run straight out of
//! `target/debug`, and depends on the shell honouring `IconThemePath` otherwise.
//! When the name fails to resolve you get a broken-image placeholder, and there
//! is no fallback to the pixmap. So we hand the shell ARGB32 pixel data we
//! rasterise ourselves: no theme lookup, no install step, identical result in a
//! dev build and from the `.deb`.
//!
//! The glyph is the **real app icon**, decoded from the compiled-in PNG, trimmed
//! to its own bounding box and flattened to white with the artwork's luminance
//! carried through as alpha. Redrawing an approximation from geometry was tried
//! first and never matched: the mark has outlines, lettering and a specific
//! three-tone shading that are not worth reconstructing. Sampling the artwork is
//! correct by construction and tracks any future redraw of the icon for free.
//!
//! It is flattened to monochrome white rather than kept in colour because that
//! is the idiom of the Ubuntu 26.04 top bar — every other app's indicator is a
//! flat white symbolic glyph, and a colour icon reads as out of place.

use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, ToolTip, Tray};

/// What the tray asks the GTK main thread to do.
///
/// The tray lives on a D-Bus thread and GTK widgets are `!Send`, so menu
/// activations cannot touch the UI directly — they post one of these down a
/// channel that the main thread drains (see `main.rs::install_tray`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    /// Bring the existing window (lock screen or main window) to the front.
    Present,
    /// Focus the window and start a new, empty note in it.
    QuickNote,
    /// Lock the vault and drop back to the password screen.
    Lock,
    /// Flush, lock and quit.
    Quit,
}

pub struct NotasTray {
    tx: async_channel::Sender<TrayCommand>,
    /// Rasterised once at construction rather than on every `icon_pixmap` call,
    /// which the host may make repeatedly.
    icons: Vec<Icon>,
}

impl NotasTray {
    pub fn new(tx: async_channel::Sender<TrayCommand>) -> Self {
        let icons = app_icon_pixmaps().unwrap_or_else(|| {
            eprintln!("Notas: could not render the app icon for the tray, using the fallback mark");
            ICON_SIZES.iter().copied().map(cube_icon).collect()
        });
        Self { tx, icons }
    }

    /// Post a command to the UI thread. The channel is unbounded, so the only
    /// way this fails is a closed receiver (the app is shutting down), in which
    /// case there is nothing useful left to do.
    fn post(&self, cmd: TrayCommand) {
        let _ = self.tx.try_send(cmd);
    }
}

impl Tray for NotasTray {
    fn id(&self) -> String {
        "notas".into()
    }

    fn title(&self) -> String {
        "Notas".into()
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            title: "Notas".into(),
            description: "Encrypted notes".into(),
            ..Default::default()
        }
    }

    /// Deliberately no `icon_name` — see the module docs. Several sizes are
    /// offered so the shell can pick one for the panel height and for HiDPI
    /// without upscaling a small bitmap.
    fn icon_pixmap(&self) -> Vec<Icon> {
        self.icons.clone()
    }

    /// Left click opens the app rather than the menu — the menu stays on right
    /// click, which is what the tray already gives us for free.
    fn activate(&mut self, _x: i32, _y: i32) {
        self.post(TrayCommand::Present);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Quick note".into(),
                activate: Box::new(|this: &mut Self| this.post(TrayCommand::QuickNote)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Open Notas".into(),
                activate: Box::new(|this: &mut Self| this.post(TrayCommand::Present)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Lock vault".into(),
                activate: Box::new(|this: &mut Self| this.post(TrayCommand::Lock)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|this: &mut Self| this.post(TrayCommand::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

// ── Tray icon from the real app icon ─────────────────────────────────────────

/// Panel sizes offered to the shell, so it can pick one for the panel height and
/// for HiDPI rather than upscaling a small bitmap.
const ICON_SIZES: [i32; 3] = [22, 32, 48];

/// The app icon itself, compiled in. Same trick the bundled font already uses:
/// a binary run straight out of `target/debug` has no installed icon theme to
/// read from, so carrying the bytes makes dev builds and the `.deb` identical.
const APP_ICON_PNG: &[u8] = include_bytes!("../icons/hicolor/512x512/apps/notas.png");

/// Darkest the icon's own shading is allowed to become once expressed as alpha.
/// The mark's top faces are near-black (grey ~48), which mapped literally would
/// leave them all but invisible as white on a dark panel; the source range is
/// compressed into `MIN_SHADE..=1.0` so the tonal *relationships* survive while
/// every face stays visible.
const MIN_SHADE: f32 = 0.30;

/// Percentiles used to find the artwork's own light and dark extremes before
/// mapping them onto alpha. Percentiles rather than plain min/max so a handful of
/// pure-black outline pixels or a stray highlight cannot flatten everything else.
const LEVEL_LO_PCT: f32 = 0.02;
const LEVEL_HI_PCT: f32 = 0.98;

/// Coverage below which a source pixel counts as background when finding the
/// mark's bounding box.
const BBOX_ALPHA: f32 = 0.1;

/// A decoded greyscale + alpha image, 0..1 per channel. Only luminance and
/// coverage are kept because the tray glyph is monochrome white.
struct Mask {
    w: usize,
    h: usize,
    lum: Vec<f32>,
    alpha: Vec<f32>,
}

/// Render the tray pixmaps from the actual app icon.
///
/// Earlier revisions redrew an approximation of the mark from geometry, which
/// never quite matched — the real icon carries outlines, lettering and a
/// specific three-tone shading that are not worth reverse-engineering. Sampling
/// the real artwork makes the tray glyph correct by construction, and it tracks
/// automatically if the icon is ever redrawn.
///
/// Returns `None` if the decode fails, leaving the caller to fall back to the
/// drawn mark.
fn app_icon_pixmaps() -> Option<Vec<Icon>> {
    let mask = decode_app_icon()?;
    let squared = crop_to_content(&mask)?;
    let levels = content_levels(&squared);
    Some(
        ICON_SIZES
            .iter()
            .map(|&s| downscale_to_icon(&squared, s, &levels))
            .collect(),
    )
}

/// The artwork's own darkest and lightest tones, as luminance.
///
/// Needed because the Notas mark is drawn in *greys* — its lightest face is only
/// about 168/255. Mapping that range straight onto alpha left every face between
/// 45% and 77% opaque, so the tray glyph read as a uniform grey lump next to the
/// crisp flat-white indicators GNOME puts beside it. Stretching the mark's actual
/// range to fill 0..1 lets the lit faces reach true white while the shaded faces
/// stay proportionally darker.
struct Levels {
    lo: f32,
    hi: f32,
}

fn content_levels(m: &Mask) -> Levels {
    let mut lums: Vec<f32> = m
        .lum
        .iter()
        .zip(&m.alpha)
        .filter(|(_, &a)| a > BBOX_ALPHA)
        .map(|(&l, _)| l)
        .collect();
    if lums.is_empty() {
        return Levels { lo: 0.0, hi: 1.0 };
    }
    lums.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let at = |p: f32| lums[((lums.len() - 1) as f32 * p).round() as usize];
    let (lo, hi) = (at(LEVEL_LO_PCT), at(LEVEL_HI_PCT));
    // Guard against a flat (single-tone) mark, which would divide by zero.
    if hi - lo < 0.05 {
        Levels { lo: 0.0, hi: 1.0 }
    } else {
        Levels { lo, hi }
    }
}

/// Decode the compiled-in PNG to luminance + alpha.
///
/// Handles whichever colour type the asset happens to use — it is greyscale+alpha
/// today, but an icon redraw could easily land as RGBA, and silently failing then
/// would be a nasty surprise.
fn decode_app_icon() -> Option<Mask> {
    use png::{BitDepth, ColorType};

    let decoder = png::Decoder::new(std::io::Cursor::new(APP_ICON_PNG));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buf).ok()?;

    if info.bit_depth != BitDepth::Eight {
        return None;
    }
    let (w, h) = (info.width as usize, info.height as usize);
    let px = &buf[..info.buffer_size()];

    let channels = match info.color_type {
        ColorType::Grayscale => 1,
        ColorType::GrayscaleAlpha => 2,
        ColorType::Rgb => 3,
        ColorType::Rgba => 4,
        // Indexed should already have been expanded by the decoder.
        ColorType::Indexed => return None,
    };

    let mut lum = Vec::with_capacity(w * h);
    let mut alpha = Vec::with_capacity(w * h);
    for i in 0..(w * h) {
        let p = &px[i * channels..];
        let (l, a) = match channels {
            1 => (p[0] as f32, 255.0),
            2 => (p[0] as f32, p[1] as f32),
            3 => (rec709(p[0], p[1], p[2]), 255.0),
            _ => (rec709(p[0], p[1], p[2]), p[3] as f32),
        };
        lum.push(l / 255.0);
        alpha.push(a / 255.0);
    }
    Some(Mask { w, h, lum, alpha })
}

fn rec709(r: u8, g: u8, b: u8) -> f32 {
    0.2126 * r as f32 + 0.7152 * g as f32 + 0.0722 * b as f32
}

/// Trim the transparent margin so the mark fills the panel slot, then pad the
/// crop back out to a square — scaling a 4:3 mark straight into a square box
/// would stretch it.
fn crop_to_content(src: &Mask) -> Option<Mask> {
    let (mut x0, mut y0, mut x1, mut y1) = (usize::MAX, usize::MAX, 0usize, 0usize);
    for y in 0..src.h {
        for x in 0..src.w {
            if src.alpha[y * src.w + x] > BBOX_ALPHA {
                x0 = x0.min(x);
                y0 = y0.min(y);
                x1 = x1.max(x);
                y1 = y1.max(y);
            }
        }
    }
    if x0 > x1 || y0 > y1 {
        return None;
    }

    let (cw, ch) = (x1 - x0 + 1, y1 - y0 + 1);
    let side = cw.max(ch);
    let (ox, oy) = ((side - cw) / 2, (side - ch) / 2);
    let mut out = Mask {
        w: side,
        h: side,
        lum: vec![0.0; side * side],
        alpha: vec![0.0; side * side],
    };
    for y in 0..ch {
        for x in 0..cw {
            let si = (y0 + y) * src.w + (x0 + x);
            let di = (oy + y) * side + (ox + x);
            out.lum[di] = src.lum[si];
            out.alpha[di] = src.alpha[si];
        }
    }
    Some(out)
}

/// Box-filter down to `size` and flatten to a monochrome-white SNI icon.
///
/// An area average rather than bilinear sampling: this is better than a 10x
/// reduction, where point-sampling filters miss most of the source pixels and
/// alias the mark's fine outlines into noise.
///
/// Luminance is averaged **weighted by coverage**, so transparent pixels do not
/// drag edge colours toward black — the usual halo bug when downscaling images
/// with alpha.
///
/// The source's luminance then becomes alpha: bright faces stay solid, the dark
/// top faces become translucent, and the mark keeps its three-dimensional read
/// while matching the flat white icons every other app puts in the Ubuntu top
/// bar. Output is ARGB32 in network byte order (`[A,R,G,B]` per pixel), **not**
/// premultiplied — GNOME's appindicator extension feeds this straight into
/// `GdkPixbuf` (non-premultiplied), as does KDE's `QImage::Format_ARGB32`.
fn downscale_to_icon(src: &Mask, size: i32, levels: &Levels) -> Icon {
    let n = size as usize;
    let mut data = vec![0u8; n * n * 4];

    for dy in 0..n {
        for dx in 0..n {
            // Source rectangle covering this destination pixel.
            let sx0 = dx * src.w / n;
            let sx1 = (((dx + 1) * src.w).div_ceil(n)).min(src.w).max(sx0 + 1);
            let sy0 = dy * src.h / n;
            let sy1 = (((dy + 1) * src.h).div_ceil(n)).min(src.h).max(sy0 + 1);

            let mut sum_a = 0.0f32;
            let mut sum_la = 0.0f32;
            let mut count = 0.0f32;
            for sy in sy0..sy1 {
                for sx in sx0..sx1 {
                    let i = sy * src.w + sx;
                    sum_a += src.alpha[i];
                    sum_la += src.lum[i] * src.alpha[i];
                    count += 1.0;
                }
            }

            let avg_a = sum_a / count;
            let lum = if sum_a > 0.0 { sum_la / sum_a } else { 0.0 };
            // Stretch the artwork's own tonal range to fill 0..1 first, so its
            // lightest face becomes fully opaque white rather than a dull grey.
            let t = ((lum - levels.lo) / (levels.hi - levels.lo)).clamp(0.0, 1.0);
            let shade = MIN_SHADE + (1.0 - MIN_SHADE) * t;

            let o = (dy * n + dx) * 4;
            data[o] = ((avg_a * shade).clamp(0.0, 1.0) * 255.0).round() as u8;
            data[o + 1] = 255;
            data[o + 2] = 255;
            data[o + 3] = 255;
        }
    }

    Icon {
        width: size,
        height: size,
        data,
    }
}

// ── Fallback mark ────────────────────────────────────────────────────────────
//
// Used only when the app icon cannot be decoded. Kept because a tray entry with
// no icon at all is worse than an approximation.



/// The Notas mark is **four** cubes in a 2×2 isometric block, not one — the app
/// icon's alpha bounding box is 434×325, a 4:3 ratio, which is exactly what a
/// 2×2 grid of unit cubes gives in 2:1 isometric projection (width 4w, height
/// 3w). A single cube reads as a different logo entirely.
///
/// Design space is 24×24. With `w = 5` the block spans x∈[2,22] and, centred
/// vertically, y∈[4.5,19.5], leaving a margin so the silhouette is never clipped
/// by the panel.
///
/// A cube sitting at grid position `(i, j)` has its top vertex at
/// `(12 + (i-j)·w, 4.5 + (i+j)·w/2)`, and its faces are:
///
/// ```text
///        T (X, Y)
///      /          \
///  L (X-w, Y+w/2)  R (X+w, Y+w/2)     top:   T  R  C  L
///      \    C     /                   left:  L  C  Cb Lb
///       (X, Y+w)                      right: C  R  Rb Cb
///  ...each side vertex dropping by the vertical edge length e = w.
/// ```
type Quad = [(f32, f32); 4];

/// Half-width of one cube; the vertical edge is the same length, which is what
/// makes it read as a cube rather than a box.
const W: f32 = 5.0;
/// Left edge of the block, and the y of the topmost cube's apex.
const ORIGIN: (f32, f32) = (12.0, 4.5);

/// Face shades, taken from the app icon's own three greys (sampled: 48 dark tops,
/// 168 light left faces, 80 mid right faces) and re-expressed as alpha on white.
///
/// The icon is dark-topped and light-sided — the opposite of the conventional
/// "sun overhead" isometric shading — so keeping that ordering is what makes the
/// tray glyph read as *this* logo. The range is compressed rather than mapped
/// literally, because a 48/255 top face would be all but invisible as white on a
/// dark panel.
const SHADE_LEFT: f32 = 1.00;
const SHADE_RIGHT: f32 = 0.66;
const SHADE_TOP: f32 = 0.42;

/// Fraction each cube shrinks toward its own centre, leaving a transparent
/// hairline between neighbours. Without it, two adjacent top faces share a shade
/// and merge into one blob; the app icon uses drawn outlines for the same job,
/// which do not survive to 22px.
const GAP: f32 = 0.13;

/// Design-space extent the block is laid out in.
const DESIGN: f32 = 24.0;

/// Supersampling factor per axis. 3×3 = 9 samples/pixel, plenty to smooth the
/// diagonals at panel sizes and free at these dimensions.
const SS: i32 = 3;

/// The block's faces in **front-to-back** order, which is what the compositor in
/// [`cube_icon`] needs to resolve occlusion.
///
/// Painting order for a 2×2 iso grid runs by descending `i + j`: the `(1,1)` cube
/// is nearest the viewer, `(0,0)` is furthest, and the two middle cubes never
/// overlap each other.
fn block_faces() -> Vec<(Quad, f32)> {
    let mut cells = [(1, 1), (1, 0), (0, 1), (0, 0)];
    cells.sort_by_key(|(i, j)| -(i + j));

    let mut faces = Vec::with_capacity(12);
    for (i, j) in cells {
        let x = ORIGIN.0 + (i - j) as f32 * W;
        let y = ORIGIN.1 + (i + j) as f32 * (W / 2.0);
        // Vertices: apex, right, centre, left, then the three lower corners.
        let (t, r, c, l) = ((x, y), (x + W, y + W / 2.0), (x, y + W), (x - W, y + W / 2.0));
        let drop = |(px, py): (f32, f32)| (px, py + W);
        let (rb, cb, lb) = (drop(r), drop(c), drop(l));

        // Shrink toward the cube's own centre so neighbours stay separable.
        let centre = (x, y + W);
        let inset = |q: Quad| -> Quad {
            q.map(|(px, py)| {
                (
                    centre.0 + (px - centre.0) * (1.0 - GAP),
                    centre.1 + (py - centre.1) * (1.0 - GAP),
                )
            })
        };

        // Within one cube the top is drawn first: it can never be occluded by
        // that cube's own sides, and listing it first keeps the front-to-back
        // walk simple.
        faces.push((inset([t, r, c, l]), SHADE_TOP));
        faces.push((inset([l, c, cb, lb]), SHADE_LEFT));
        faces.push((inset([c, r, rb, cb]), SHADE_RIGHT));
    }
    faces
}

/// Rasterise the four-cube block at `size`×`size` as an SNI icon.
///
/// The format is ARGB32 in network byte order, i.e. bytes laid out `[A,R,G,B]`
/// per pixel, **not** premultiplied — GNOME's appindicator extension feeds this
/// straight into `GdkPixbuf` (which is non-premultiplied), as does KDE's
/// `QImage::Format_ARGB32`. Since the colour is pure white, RGB is a constant
/// 255 and only the alpha channel carries the drawing.
fn cube_icon(size: i32) -> Icon {
    let faces = block_faces();
    let scale = size as f32 / DESIGN;
    let samples = (SS * SS) as f32;
    let mut data = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            // Front-to-back compositing: each face contributes only over the
            // portion of the pixel no nearer face has already claimed. This is
            // what makes the front cubes correctly hide the ones behind them,
            // while still antialiasing every edge.
            let mut alpha = 0.0f32;
            let mut remaining = 1.0f32;
            for (quad, shade) in &faces {
                if remaining <= 0.001 {
                    break;
                }
                let mut hits = 0;
                for sy in 0..SS {
                    for sx in 0..SS {
                        let px = (x as f32 + (sx as f32 + 0.5) / SS as f32) / scale;
                        let py = (y as f32 + (sy as f32 + 0.5) / SS as f32) / scale;
                        if point_in_quad(px, py, quad) {
                            hits += 1;
                        }
                    }
                }
                if hits > 0 {
                    let coverage = hits as f32 / samples;
                    alpha += shade * coverage * remaining;
                    remaining *= 1.0 - coverage;
                }
            }

            let i = ((y * size + x) * 4) as usize;
            data[i] = (alpha.clamp(0.0, 1.0) * 255.0).round() as u8;
            data[i + 1] = 255;
            data[i + 2] = 255;
            data[i + 3] = 255;
        }
    }

    Icon {
        width: size,
        height: size,
        data,
    }
}

/// Even-odd ray casting against a convex quad. Points exactly on an edge may
/// land either side; at 9 samples per pixel that is invisible.
fn point_in_quad(px: f32, py: f32, quad: &Quad) -> bool {
    let mut inside = false;
    let mut j = quad.len() - 1;
    for i in 0..quad.len() {
        let (xi, yi) = quad[i];
        let (xj, yj) = quad[j];
        if (yi > py) != (yj > py) && px < (xj - xi) * (py - yi) / (yj - yi) + xi {
            inside = !inside;
        }
        j = i;
    }
    inside
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha_at(icon: &Icon, x: i32, y: i32) -> u8 {
        icon.data[((y * icon.width + x) * 4) as usize]
    }

    #[test]
    fn icon_has_the_right_shape_and_stride() {
        let icon = cube_icon(22);
        assert_eq!(icon.width, 22);
        assert_eq!(icon.height, 22);
        assert_eq!(icon.data.len(), 22 * 22 * 4);
    }

    #[test]
    fn all_four_cubes_are_drawn() {
        assert_eq!(block_faces().len(), 12, "4 cubes x 3 visible faces");
    }

    #[test]
    fn faces_are_ordered_front_to_back() {
        // The compositor depends on this: a back-to-front list would let distant
        // cubes paint over near ones.
        let faces = block_faces();
        // Every cube contributes 3 consecutive faces; the first cube's centre must
        // be the lowest on screen (nearest the viewer).
        let cube_centre_y = |chunk: &[(Quad, f32)]| {
            chunk.iter().flat_map(|(q, _)| q.iter().map(|(_, y)| *y)).sum::<f32>()
        };
        let first = cube_centre_y(&faces[0..3]);
        let last = cube_centre_y(&faces[9..12]);
        assert!(first > last, "nearest cube ({first}) should sit below furthest ({last})");
    }

    #[test]
    fn corners_are_transparent_and_the_block_is_drawn() {
        let icon = cube_icon(48);
        // The block is a hexagon inside the square, so all four corners are clear.
        for (x, y) in [(0, 0), (47, 0), (0, 47), (47, 47)] {
            assert_eq!(alpha_at(&icon, x, y), 0, "corner ({x},{y}) should be clear");
        }
        // Centre of the block is covered by the nearest cube.
        assert!(alpha_at(&icon, 24, 24) > 0);
    }

    #[test]
    fn shading_matches_the_app_icon_ordering() {
        // The app icon is dark-topped and light-sided; losing that ordering is
        // what made the first attempt read as a different logo.
        assert!(SHADE_LEFT > SHADE_RIGHT, "left face is the lightest");
        assert!(SHADE_RIGHT > SHADE_TOP, "top face is the darkest");
        // ...but the darkest face still has to be visible as white on a panel.
        assert!(SHADE_TOP > 0.3);
    }

    #[test]
    fn the_block_fills_its_box_without_touching_the_edge() {
        // Guards the geometry constants: a 2x2 block is 4W wide and 3W tall.
        let icon = cube_icon(48);
        let opaque: Vec<(i32, i32)> = (0..48)
            .flat_map(|y| (0..48).map(move |x| (x, y)))
            .filter(|&(x, y)| alpha_at(&icon, x, y) > 8)
            .collect();
        let (min_x, max_x) = (
            opaque.iter().map(|p| p.0).min().unwrap(),
            opaque.iter().map(|p| p.0).max().unwrap(),
        );
        let (min_y, max_y) = (
            opaque.iter().map(|p| p.1).min().unwrap(),
            opaque.iter().map(|p| p.1).max().unwrap(),
        );
        assert!(min_x >= 2 && max_x <= 45, "x span {min_x}..{max_x}");
        assert!(min_y >= 6 && max_y <= 41, "y span {min_y}..{max_y}");
        // 4:3 block ratio, the same as the app icon's alpha bounding box.
        let ratio = (max_x - min_x) as f32 / (max_y - min_y) as f32;
        assert!((ratio - 4.0 / 3.0).abs() < 0.15, "aspect {ratio:.2}");
    }

    /// Regression guard for the tray glyph reading as a grey lump beside GNOME's
    /// flat-white indicators. The Notas mark's lightest face is only grey ~168, so
    /// without stretching its tonal range to fill 0..1 nothing ever reaches full
    /// opacity and the whole icon sits in a narrow mid-grey band.
    #[test]
    fn lit_faces_reach_full_white_with_real_contrast() {
        let icons = app_icon_pixmaps().expect("app icon should decode");
        for icon in icons {
            let alphas: Vec<u8> = icon.data.iter().step_by(4).copied().collect();
            let peak = *alphas.iter().max().unwrap();
            assert!(peak >= 250, "{}px peak alpha {peak}, expected ~255", icon.width);

            // And the shaded faces must stay clearly darker, or we have traded a
            // grey lump for a white blob with no form.
            let mut opaque: Vec<u8> = alphas.into_iter().filter(|&a| a > 20).collect();
            opaque.sort_unstable();
            let low = opaque[opaque.len() / 10];
            assert!(
                (peak as i32 - low as i32) > 60,
                "{}px has too little tonal spread: {low}..{peak}",
                icon.width
            );
        }
    }

    #[test]
    fn colour_is_pure_white_everywhere() {
        let icon = cube_icon(22);
        for px in icon.data.chunks_exact(4) {
            assert_eq!(&px[1..], &[255, 255, 255], "non-premultiplied white RGB");
        }
    }
}

#[cfg(test)]
mod preview {
    /// `cargo test tray::preview -- --ignored --nocapture` to eyeball the glyph.
    #[test]
    #[ignore]
    fn ascii_dump() {
        for size in [22, 32] {
            let icon = super::app_icon_pixmaps()
                .map(|v| v.into_iter().find(|i| i.width == size).unwrap())
                .unwrap_or_else(|| super::cube_icon(size));
            let ramp = [' ', '.', ':', '-', '=', '+', '*', '#', '%', '@'];
            println!("--- {size}px ---");
            for y in 0..icon.height {
                let mut line = String::new();
                for x in 0..icon.width {
                    let a = icon.data[((y * icon.width + x) * 4) as usize] as usize;
                    let c = ramp[a * (ramp.len() - 1) / 255];
                    line.push(c);
                    line.push(c);
                }
                println!("{line}");
            }
        }
    }
}

#[cfg(test)]
mod seccomp_probe {
    /// Regression test for a real failure: on GTK 4.22 the app icon was decoded
    /// through gdk-pixbuf, which routes to **glycin** — and glycin decodes in a
    /// sandboxed *subprocess*, so it needs `execve`, the exact syscall the
    /// hardening filter blocks. The tray silently fell back to the drawn mark in
    /// the real app while every test passed, because tests run unhardened.
    ///
    /// Decoding now goes through the pure-Rust `png` crate. This forks a child,
    /// installs the real filter, and only *then* decodes — no pre-warmed loader,
    /// matching the order the app actually runs in.
    #[test]
    fn app_icon_decodes_after_the_seccomp_filter_is_installed() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let installed = matches!(
                    crate::hardening::install_seccomp_filter_for_test(),
                    crate::hardening::SeccompStatus::Installed { .. }
                );
                // Cold decode, under the filter, exactly as the app does it.
                let icons = super::app_icon_pixmaps();
                let ok = icons
                    .as_ref()
                    .is_some_and(|v| v.len() == super::ICON_SIZES.len()
                        && v.iter().any(|i| i.data.iter().step_by(4).any(|&a| a > 0)));
                libc::_exit(match (installed, ok) {
                    (true, true) => 0,
                    (true, false) => 1,
                    (false, _) => 3,
                });
            }
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
            let code = libc::WEXITSTATUS(st);
            assert_eq!(
                code, 0,
                "1 = decode failed or produced a blank icon under seccomp, \
                 3 = filter would not install"
            );
        }
    }
}
