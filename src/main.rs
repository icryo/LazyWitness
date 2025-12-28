use ansi_to_tui::IntoText;
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use headless_chrome::{protocol::cdp::Page, Browser, LaunchOptions};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    DefaultTerminal, Frame,
};
use readability_rust::Readability;
use std::{
    env, fs,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime},
};

/// Catppuccin Mocha color theme
mod theme {
    use ratatui::style::Color;

    // Base colors
    pub const BG: Color = Color::Rgb(17, 17, 27);              // #11111b - Crust
    pub const SURFACE0: Color = Color::Rgb(49, 50, 68);        // #313244
    pub const FG: Color = Color::Rgb(205, 214, 244);           // #cdd6f4 - Text
    pub const FG_DIM: Color = Color::Rgb(147, 153, 178);       // #9399b2 - Subtext1

    // Accent colors
    pub const MAUVE: Color = Color::Rgb(203, 166, 247);        // #cba6f7
    pub const LAVENDER: Color = Color::Rgb(180, 190, 254);     // #b4befe
    pub const PEACH: Color = Color::Rgb(250, 179, 135);        // #fab387
    pub const TEAL: Color = Color::Rgb(148, 226, 213);         // #94e2d5

    // UI elements
    pub const BORDER: Color = SURFACE0;
    pub const BORDER_FOCUSED: Color = MAUVE;
    pub const SELECTION_BG: Color = SURFACE0;
    pub const SELECTION_FG: Color = LAVENDER;
    pub const STATUS_FG: Color = PEACH;
}

const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "ico"];

// ASCII density presets (sparse → dense)
const DENSITY_PRESETS: &[(&str, &str)] = &[
    ("block", "Block"),
    ("block+border", "Block+"),
    ("ascii", "ASCII"),
    ("block+border+ascii", "Mixed"),
    ("braille", "Braille"),
    ("all", "All"),
];

// Screenshot resolution presets (width, height, label)
const RESOLUTION_PRESETS: &[(u32, u32, &str)] = &[
    (1920, 1080, "1080p"),
    (2560, 1440, "1440p"),
    (3840, 2160, "4K"),
    (1280, 720, "720p"),
];

#[derive(Default, PartialEq, Clone)]
enum InputMode {
    #[default]
    Normal,
    UrlInput,
}

struct App {
    dir: PathBuf,
    images: Vec<PathBuf>,
    list_state: ListState,
    zoom_percent: u16,    // 100 = full image, 200 = 2x zoom (50% crop), etc.
    pan_x: i16,           // pan offset X (-50 to +50, percentage from center)
    pan_y: i16,           // pan offset Y (-50 to +50, percentage from center)
    density_index: usize, // index into DENSITY_PRESETS
    resolution_index: usize, // index into RESOLUTION_PRESETS
    preview_cache: Option<Text<'static>>,
    cached_index: Option<usize>,
    cached_zoom: u16,
    cached_pan: (i16, i16),
    cached_density: usize,
    cached_size: (u16, u16),
    input_mode: InputMode,
    url_input: String,
    status_message: Option<String>,
    show_file_list: bool,
    show_text_pane: bool,    // Show readable text alongside image
    text_scroll: u16,        // Scroll position for text pane
}

impl App {
    fn new(dir: PathBuf) -> Result<Self> {
        let images = Self::scan_images(&dir)?;
        let mut list_state = ListState::default();
        if !images.is_empty() {
            list_state.select(Some(0));
        }

        Ok(Self {
            dir,
            images,
            list_state,
            zoom_percent: 100,   // 100% = full image
            pan_x: 0,
            pan_y: 0,
            density_index: 3,    // "Mixed" default
            resolution_index: 0, // 1080p default
            preview_cache: None,
            cached_index: None,
            cached_zoom: 0,
            cached_pan: (0, 0),
            cached_density: 0,
            cached_size: (0, 0),
            input_mode: InputMode::Normal,
            url_input: String::new(),
            status_message: None,
            show_file_list: true,
            show_text_pane: false,
            text_scroll: 0,
        })
    }

    fn scan_images(dir: &PathBuf) -> Result<Vec<PathBuf>> {
        let mut images: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| IMAGE_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
                    .unwrap_or(false)
            })
            .collect();

        images.sort();
        Ok(images)
    }

    fn refresh_images(&mut self) -> Result<()> {
        let old_selection = self.selected_image().map(|p| p.clone());
        self.images = Self::scan_images(&self.dir)?;

        // Try to maintain selection or select the new image
        if let Some(old_path) = old_selection {
            if let Some(pos) = self.images.iter().position(|p| p == &old_path) {
                self.list_state.select(Some(pos));
            }
        }

        // If nothing selected but we have images, select last (newest)
        if self.list_state.selected().is_none() && !self.images.is_empty() {
            self.list_state.select(Some(self.images.len() - 1));
        }

        // Invalidate cache
        self.preview_cache = None;

        Ok(())
    }

    fn selected_index(&self) -> Option<usize> {
        self.list_state.selected()
    }

    fn selected_image(&self) -> Option<&PathBuf> {
        self.selected_index().and_then(|i| self.images.get(i))
    }

    fn next(&mut self) {
        if self.images.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => (i + 1) % self.images.len(),
            None => 0,
        };
        self.list_state.select(Some(i));
        self.reset_view();
    }

    fn previous(&mut self) {
        if self.images.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.images.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
        self.reset_view();
    }

    fn reset_view(&mut self) {
        self.zoom_percent = 100;
        self.pan_x = 0;
        self.pan_y = 0;
        self.preview_cache = None;
        self.text_scroll = 0;
    }

    fn zoom_in(&mut self) {
        self.zoom_percent = self.zoom_percent.saturating_add(50).min(800);
        self.clamp_pan();
        self.preview_cache = None;
    }

    fn zoom_out(&mut self) {
        self.zoom_percent = self.zoom_percent.saturating_sub(50).max(100);
        self.clamp_pan();
        self.preview_cache = None;
    }

    // Pan the view (moves which part of the image we're looking at)
    fn pan_up(&mut self) {
        self.pan_y = self.pan_y.saturating_sub(10);
        self.clamp_pan();
        self.preview_cache = None;
    }

    fn pan_down(&mut self) {
        self.pan_y = self.pan_y.saturating_add(10);
        self.clamp_pan();
        self.preview_cache = None;
    }

    fn pan_left(&mut self) {
        self.pan_x = self.pan_x.saturating_sub(10);
        self.clamp_pan();
        self.preview_cache = None;
    }

    fn pan_right(&mut self) {
        self.pan_x = self.pan_x.saturating_add(10);
        self.clamp_pan();
        self.preview_cache = None;
    }

    // Clamp pan to valid range based on current zoom
    fn clamp_pan(&mut self) {
        if self.zoom_percent <= 100 {
            self.pan_x = 0;
            self.pan_y = 0;
        } else {
            // crop_size as percentage = 10000 / zoom_percent
            // max offset from center = 50 - (crop_size / 2)
            let crop_size = 10000i32 / self.zoom_percent as i32;
            let max_pan = ((100 - crop_size) / 2) as i16;
            self.pan_x = self.pan_x.clamp(-max_pan, max_pan);
            self.pan_y = self.pan_y.clamp(-max_pan, max_pan);
        }
    }

    // Calculate crop region from zoom and pan
    // Returns (x_offset, y_offset, width, height) as percentages
    fn get_crop_region(&self) -> Option<(u32, u32, u32, u32)> {
        if self.zoom_percent <= 100 {
            return None;
        }

        // Crop size as percentage of image
        let size = 10000u32 / self.zoom_percent as u32;

        // Calculate offset: pan=0 means centered, pan ranges let us reach edges
        // pan_x of +max means we want to see the right side
        // So x_offset should increase when pan_x increases
        let max_offset = (100 - size) / 2;
        let x = (max_offset as i32 + self.pan_x as i32).max(0) as u32;
        let y = (max_offset as i32 + self.pan_y as i32).max(0) as u32;

        // Clamp to ensure we don't go past image bounds
        let x = x.min(100 - size);
        let y = y.min(100 - size);

        Some((x, y, size, size))
    }

    fn density_up(&mut self) {
        self.density_index = (self.density_index + 1) % DENSITY_PRESETS.len();
        self.preview_cache = None;
    }

    fn density_down(&mut self) {
        self.density_index = if self.density_index == 0 {
            DENSITY_PRESETS.len() - 1
        } else {
            self.density_index - 1
        };
        self.preview_cache = None;
    }

    fn current_density(&self) -> (&str, &str) {
        DENSITY_PRESETS[self.density_index]
    }

    fn resolution_cycle(&mut self) {
        self.resolution_index = (self.resolution_index + 1) % RESOLUTION_PRESETS.len();
    }

    fn current_resolution(&self) -> (u32, u32, &str) {
        RESOLUTION_PRESETS[self.resolution_index]
    }

    fn generate_screenshot_filename(&self, url: &str) -> PathBuf {
        // Create filename from URL + timestamp
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Sanitize URL for filename
        let sanitized: String = url
            .replace("https://", "")
            .replace("http://", "")
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
            .take(50)
            .collect();

        self.dir.join(format!("{}_{}.png", sanitized, timestamp))
    }

    fn take_screenshot(&mut self, url: &str) -> Result<()> {
        let output_path = self.generate_screenshot_filename(url);

        // Ensure URL has a scheme
        let full_url = if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("https://{}", url)
        };

        self.status_message = Some(format!("Capturing {}...", full_url));

        match self.capture_with_chrome(&full_url, &output_path) {
            Ok(()) => {
                // Also extract readable text content
                self.extract_readable_content(&full_url, &output_path);

                self.status_message = Some(format!("Saved: {}", output_path.display()));
                self.refresh_images()?;
                // Select the new screenshot
                if let Some(pos) = self.images.iter().position(|p| p == &output_path) {
                    self.list_state.select(Some(pos));
                    self.preview_cache = None;
                }
            }
            Err(e) => {
                self.status_message = Some(format!("Screenshot error: {}", e));
            }
        }

        Ok(())
    }

    fn extract_readable_content(&self, url: &str, image_path: &PathBuf) {
        // Generate .txt path from image path
        let txt_path = image_path.with_extension("txt");

        // Fetch HTML natively with ureq
        let html = match ureq::get(url)
            .timeout(std::time::Duration::from_secs(10))
            .call()
        {
            Ok(response) => match response.into_string() {
                Ok(body) => body,
                Err(_) => return,
            },
            Err(_) => return,
        };

        // Use readability-rust library to extract readable content
        if let Ok(mut parser) = Readability::new(&html, None) {
            if let Some(article) = parser.parse() {
                // Article content is HTML (Option<String>), convert to plain text
                let plain_text = article.content
                    .as_ref()
                    .map(|c| Self::html_to_text(c))
                    .unwrap_or_default();

                // Prepend title if available
                let output = if let Some(title) = &article.title {
                    format!("{}\n\n{}", title, plain_text)
                } else {
                    plain_text
                };

                if !output.is_empty() {
                    let _ = fs::write(&txt_path, output);
                }
            }
        }
    }

    /// Convert HTML to plain text by stripping tags and decoding entities
    fn html_to_text(html: &str) -> String {
        let mut result = String::new();
        let mut in_tag = false;
        let mut last_was_space = false;

        // Replace common block elements with newlines
        let html = html
            .replace("<br>", "\n")
            .replace("<br/>", "\n")
            .replace("<br />", "\n")
            .replace("</p>", "\n\n")
            .replace("</div>", "\n")
            .replace("</li>", "\n")
            .replace("</h1>", "\n\n")
            .replace("</h2>", "\n\n")
            .replace("</h3>", "\n\n")
            .replace("</h4>", "\n")
            .replace("</h5>", "\n")
            .replace("</h6>", "\n");

        for c in html.chars() {
            match c {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => {
                    if c.is_whitespace() {
                        if !last_was_space {
                            result.push(if c == '\n' { '\n' } else { ' ' });
                            last_was_space = true;
                        } else if c == '\n' && !result.ends_with("\n\n") {
                            result.push('\n');
                        }
                    } else {
                        result.push(c);
                        last_was_space = false;
                    }
                }
                _ => {}
            }
        }

        // Decode common HTML entities
        result
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&#39;", "'")
            .replace("&nbsp;", " ")
            .replace("&#x27;", "'")
            .replace("&#x2F;", "/")
            .trim()
            .to_string()
    }

    fn get_text_content(&self) -> Option<String> {
        self.selected_image().and_then(|img_path| {
            let txt_path = img_path.with_extension("txt");
            fs::read_to_string(&txt_path).ok()
        })
    }

    fn find_chrome() -> Option<PathBuf> {
        let candidates = [
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/snap/bin/chromium",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ];

        // Check CHROME_PATH env var first
        if let Ok(path) = env::var("CHROME_PATH") {
            let p = PathBuf::from(&path);
            if p.exists() {
                return Some(p);
            }
        }

        // Try common locations
        for candidate in candidates {
            let p = PathBuf::from(candidate);
            if p.exists() {
                return Some(p);
            }
        }

        None
    }

    fn capture_with_chrome(&self, url: &str, output_path: &PathBuf) -> Result<()> {
        let chrome_path = Self::find_chrome()
            .ok_or_else(|| color_eyre::eyre::eyre!("Chrome/Chromium not found. Set CHROME_PATH or install chromium-browser"))?;

        let (width, height, _) = self.current_resolution();
        let options = LaunchOptions::default_builder()
            .path(Some(chrome_path))
            .headless(true)
            .window_size(Some((width, height)))
            .build()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to build launch options: {}", e))?;

        let browser = Browser::new(options)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to launch browser: {}", e))?;

        let tab = browser
            .new_tab()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create tab: {}", e))?;

        tab.navigate_to(url)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to navigate: {}", e))?;

        // Wait for page to load
        tab.wait_until_navigated()
            .map_err(|e| color_eyre::eyre::eyre!("Navigation timeout: {}", e))?;

        // Small delay for dynamic content
        std::thread::sleep(Duration::from_millis(500));

        // Capture screenshot as PNG
        let png_data = tab
            .capture_screenshot(Page::CaptureScreenshotFormatOption::Png, None, None, true)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to capture screenshot: {}", e))?;

        fs::write(output_path, png_data)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to save screenshot: {}", e))?;

        Ok(())
    }

    fn render_chafa(&mut self, width: u16, height: u16) -> Text<'static> {
        let current_index = self.selected_index();
        let current_size = (width, height);
        let current_pan = (self.pan_x, self.pan_y);

        // Check cache validity
        if self.cached_index == current_index
            && self.cached_zoom == self.zoom_percent
            && self.cached_pan == current_pan
            && self.cached_density == self.density_index
            && self.cached_size == current_size
        {
            if let Some(ref cached) = self.preview_cache {
                return cached.clone();
            }
        }

        let text = if let Some(path) = self.selected_image() {
            // Always render at full terminal size for maximum detail
            let size_arg = format!("{}x{}", width.max(10), height.saturating_sub(2).max(5));
            let (symbols, _) = self.current_density();

            // Get crop region from zoom/pan state
            let crop_region = self.get_crop_region();

            let output = if let Some((x_pct, y_pct, w_pct, h_pct)) = crop_region {
                // Get image dimensions first
                let identify = Command::new("identify")
                    .arg("-format")
                    .arg("%wx%h")
                    .arg(path)
                    .output();

                let (img_w, img_h) = match identify {
                    Ok(out) if out.status.success() => {
                        let dims = String::from_utf8_lossy(&out.stdout);
                        let parts: Vec<&str> = dims.trim().split('x').collect();
                        if parts.len() == 2 {
                            (
                                parts[0].parse::<u32>().unwrap_or(1920),
                                parts[1].parse::<u32>().unwrap_or(1080),
                            )
                        } else {
                            (1920, 1080)
                        }
                    }
                    _ => (1920, 1080),
                };

                // Convert percentages to pixels
                let crop_w = img_w * w_pct / 100;
                let crop_h = img_h * h_pct / 100;
                let crop_x = img_w * x_pct / 100;
                let crop_y = img_h * y_pct / 100;

                let crop_spec = format!("{}x{}+{}+{}", crop_w, crop_h, crop_x, crop_y);

                let convert = Command::new("convert")
                    .arg(path)
                    .arg("-crop")
                    .arg(&crop_spec)
                    .arg("+repage")
                    .arg("png:-")
                    .output();

                match convert {
                    Ok(convert_out) if convert_out.status.success() => {
                        use std::process::Stdio;
                        use std::io::Write;

                        let chafa = Command::new("chafa")
                            .arg("-s")
                            .arg(&size_arg)
                            .arg("--symbols")
                            .arg(symbols)
                            .arg("-")
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped())
                            .spawn();

                        match chafa {
                            Ok(mut child) => {
                                if let Some(ref mut stdin) = child.stdin {
                                    let _ = stdin.write_all(&convert_out.stdout);
                                }
                                drop(child.stdin.take());
                                child.wait_with_output()
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Ok(convert_out) => {
                        return Text::raw(format!(
                            "ImageMagick error: {}",
                            String::from_utf8_lossy(&convert_out.stderr)
                        ));
                    }
                    Err(e) => {
                        return Text::raw(format!(
                            "Failed to run ImageMagick: {} (is imagemagick installed?)",
                            e
                        ));
                    }
                }
            } else {
                // No crop (100% zoom), use chafa directly
                Command::new("chafa")
                    .arg("-s")
                    .arg(&size_arg)
                    .arg("--symbols")
                    .arg(symbols)
                    .arg(path)
                    .output()
            };

            match output {
                Ok(out) => {
                    if out.status.success() {
                        out.stdout
                            .into_text()
                            .unwrap_or_else(|_| Text::raw("Failed to parse ANSI output"))
                    } else {
                        Text::raw(format!(
                            "chafa error: {}",
                            String::from_utf8_lossy(&out.stderr)
                        ))
                    }
                }
                Err(e) => Text::raw(format!("Failed to run chafa: {}", e)),
            }
        } else {
            Text::raw("No image selected")
        };

        // Update cache
        self.preview_cache = Some(text.clone());
        self.cached_index = current_index;
        self.cached_zoom = self.zoom_percent;
        self.cached_pan = current_pan;
        self.cached_density = self.density_index;
        self.cached_size = current_size;

        text
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap());

    let mut app = App::new(dir)?;

    let terminal = ratatui::init();
    let result = run(terminal, &mut app);
    ratatui::restore();

    result
}

fn run(mut terminal: DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| ui(frame, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match app.input_mode {
                InputMode::Normal => match key.code {
                    // Quit
                    KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,

                    // Navigation (arrows or j/k)
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.previous(),
                    KeyCode::Home => {
                        app.list_state.select(Some(0));
                        app.reset_view();
                    }
                    KeyCode::End => {
                        if !app.images.is_empty() {
                            app.list_state.select(Some(app.images.len() - 1));
                            app.reset_view();
                        }
                    }

                    // WASD panning (moves viewport when zoomed in)
                    KeyCode::Char('w') => app.pan_up(),
                    KeyCode::Char('a') => app.pan_left(),
                    KeyCode::Char('s') => app.pan_down(),
                    KeyCode::Char('d') => app.pan_right(),

                    // Zoom: e = in (crop tighter), q = out (show more)
                    KeyCode::Char('e') | KeyCode::Char('+') | KeyCode::Char('=') => app.zoom_in(),
                    KeyCode::Char('q') | KeyCode::Char('-') | KeyCode::Char('_') => app.zoom_out(),
                    KeyCode::Char('f') => {
                        app.reset_view();
                        app.status_message = Some("View reset to 100%".to_string());
                    }

                    // Density: [ = sparser, ] = denser
                    KeyCode::Char('[') => {
                        app.density_down();
                        let (_, name) = app.current_density();
                        app.status_message = Some(format!("Density: {}", name));
                    }
                    KeyCode::Char(']') => {
                        app.density_up();
                        let (_, name) = app.current_density();
                        app.status_message = Some(format!("Density: {}", name));
                    }

                    // Screenshot resolution: t cycles through presets
                    KeyCode::Char('t') => {
                        app.resolution_cycle();
                        let (w, h, name) = app.current_resolution();
                        app.status_message = Some(format!("Screenshot: {} ({}x{})", name, w, h));
                    }

                    // Actions
                    KeyCode::Char('c') | KeyCode::Char('/') => {
                        app.input_mode = InputMode::UrlInput;
                        app.url_input.clear();
                        app.status_message = None;
                    }
                    KeyCode::Char('r') => {
                        app.preview_cache = None;
                        app.refresh_images()?;
                        app.status_message = Some("Refreshed image list".to_string());
                    }

                    // Toggle file list
                    KeyCode::Tab => {
                        app.show_file_list = !app.show_file_list;
                    }

                    // Toggle text pane (readable content)
                    KeyCode::Char('v') => {
                        if app.get_text_content().is_some() {
                            app.show_text_pane = !app.show_text_pane;
                            app.text_scroll = 0;
                        } else {
                            app.status_message = Some("No text content for this image".to_string());
                        }
                    }

                    // Text pane scrolling (when visible)
                    KeyCode::Char('W') => {
                        if app.show_text_pane {
                            app.text_scroll = app.text_scroll.saturating_sub(5);
                        }
                    }
                    KeyCode::Char('S') => {
                        if app.show_text_pane {
                            app.text_scroll = app.text_scroll.saturating_add(5);
                        }
                    }

                    _ => {}
                },
                InputMode::UrlInput => match key.code {
                    KeyCode::Enter => {
                        if !app.url_input.is_empty() {
                            let url = app.url_input.clone();
                            app.input_mode = InputMode::Normal;
                            app.take_screenshot(&url)?;
                        }
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.url_input.clear();
                    }
                    KeyCode::Backspace => {
                        app.url_input.pop();
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.url_input.clear();
                    }
                    KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Delete last word
                        let trimmed = app.url_input.trim_end();
                        if let Some(pos) = trimmed.rfind(|c: char| c.is_whitespace() || c == '/') {
                            app.url_input.truncate(pos);
                        } else {
                            app.url_input.clear();
                        }
                    }
                    KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Cycle resolution in URL input mode
                        app.resolution_cycle();
                    }
                    KeyCode::Char(c) => {
                        app.url_input.push(c);
                    }
                    _ => {}
                },
            }
        }
    }

    Ok(())
}

fn ui(frame: &mut Frame, app: &mut App) {
    let main_chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(1)])
        .split(frame.area());

    // Determine layout based on what panels are visible
    let content_area = main_chunks[0];

    if app.show_file_list && app.show_text_pane {
        // File list + Image + Text: 15% | 45% | 40%
        let chunks = Layout::horizontal([
            Constraint::Percentage(15),
            Constraint::Percentage(45),
            Constraint::Percentage(40),
        ]).split(content_area);
        render_file_list(frame, app, chunks[0]);
        render_preview(frame, app, chunks[1]);
        render_text_pane(frame, app, chunks[2]);
    } else if app.show_file_list {
        // File list + Image: 15% | 85%
        let chunks = Layout::horizontal([
            Constraint::Percentage(15),
            Constraint::Percentage(85),
        ]).split(content_area);
        render_file_list(frame, app, chunks[0]);
        render_preview(frame, app, chunks[1]);
    } else if app.show_text_pane {
        // Image + Text: 55% | 45%
        let chunks = Layout::horizontal([
            Constraint::Percentage(55),
            Constraint::Percentage(45),
        ]).split(content_area);
        render_preview(frame, app, chunks[0]);
        render_text_pane(frame, app, chunks[1]);
    } else {
        // Image only
        render_preview(frame, app, content_area);
    }

    render_status_bar(frame, app, main_chunks[1]);

    // Render URL input popup if in input mode
    if app.input_mode == InputMode::UrlInput {
        render_url_input(frame, app);
    }
}

fn render_file_list(frame: &mut Frame, app: &mut App, area: Rect) {
    // Available width for filename (minus borders, highlight symbol)
    let max_name_len = area.width.saturating_sub(5) as usize;

    let items: Vec<ListItem> = app
        .images
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("???");
            // Truncate with ellipsis if too long
            let display_name = if name.len() > max_name_len && max_name_len > 3 {
                format!("{}...", &name[..max_name_len - 3])
            } else {
                name.to_string()
            };
            ListItem::new(display_name).style(Style::default().fg(theme::FG_DIM))
        })
        .collect();

    let title = format!(" ({}) Tab:hide ", app.images.len());
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .title_style(Style::default().fg(theme::LAVENDER))
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .highlight_style(
            Style::default()
                .bg(theme::SELECTION_BG)
                .fg(theme::SELECTION_FG)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn render_preview(frame: &mut Frame, app: &mut App, area: Rect) {
    let inner_width = area.width.saturating_sub(2);
    let inner_height = area.height.saturating_sub(2);

    let preview_text = app.render_chafa(inner_width, inner_height);

    let (_, density_name) = app.current_density();

    // Build title showing zoom level and pan position
    let title = match app.selected_image() {
        Some(path) => {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("???");
            if app.zoom_percent > 100 {
                format!(" {} [{}% {} pan:{},{}] ", name, app.zoom_percent, density_name, app.pan_x, app.pan_y)
            } else {
                format!(" {} [{}% {}] ", name, app.zoom_percent, density_name)
            }
        }
        None => " No image ".to_string(),
    };

    let has_text = app.get_text_content().is_some();
    let help = if app.show_file_list {
        if has_text {
            keybindings_line(&[("j/k", "nav"), ("WASD", "pan"), ("e/q", "zoom"), ("v", "text"), ("[]", "dens"), ("/", "url"), ("Esc", "quit")])
        } else {
            keybindings_line(&[("j/k", "nav"), ("WASD", "pan"), ("e/q", "zoom"), ("[]", "dens"), ("f", "reset"), ("/", "url"), ("Esc", "quit")])
        }
    } else {
        if has_text {
            keybindings_line(&[("Tab", "list"), ("j/k", "nav"), ("WASD", "pan"), ("e/q", "zoom"), ("v", "text"), ("[]", "dens"), ("/", "url"), ("Esc", "quit")])
        } else {
            keybindings_line(&[("Tab", "list"), ("j/k", "nav"), ("WASD", "pan"), ("e/q", "zoom"), ("[]", "dens"), ("f", "reset"), ("/", "url"), ("Esc", "quit")])
        }
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD))
        .title_bottom(help)
        .border_style(Style::default().fg(theme::BORDER_FOCUSED));

    let paragraph = Paragraph::new(preview_text).block(block);
    frame.render_widget(paragraph, area);
}

fn keybindings_line(bindings: &[(&str, &str)]) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (key, desc) in bindings {
        spans.push(Span::styled(
            format!(" {} ", key),
            Style::default().bg(theme::MAUVE).fg(theme::BG).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {}  ", desc),
            Style::default().fg(theme::FG_DIM),
        ));
    }
    Line::from(spans)
}

fn render_text_pane(frame: &mut Frame, app: &App, area: Rect) {
    let content = app.get_text_content().unwrap_or_default();

    let title = " Readable Content (v:hide, Shift+W/S:scroll) ";

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(Style::default().fg(theme::TEAL))
        .border_style(Style::default().fg(theme::BORDER));

    let paragraph = Paragraph::new(content)
        .block(block)
        .style(Style::default().fg(theme::FG))
        .wrap(Wrap { trim: false })
        .scroll((app.text_scroll, 0));

    frame.render_widget(paragraph, area);
}

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let msg = app
        .status_message
        .as_deref()
        .unwrap_or("");

    let status = Paragraph::new(msg)
        .style(Style::default().fg(theme::STATUS_FG));

    frame.render_widget(status, area);
}

fn render_url_input(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Center popup
    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 3;
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind popup
    frame.render_widget(Clear, popup_area);

    let (_, _, res_name) = app.current_resolution();
    let input = Paragraph::new(app.url_input.as_str())
        .style(Style::default().fg(theme::FG))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::MAUVE))
                .title(format!(" URL [{}] (Enter=capture, ^t=res, Esc=cancel) ", res_name))
                .title_style(Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD)),
        );

    frame.render_widget(input, popup_area);

    // Show cursor
    let cursor_x = popup_area.x + 1 + app.url_input.len() as u16;
    let cursor_y = popup_area.y + 1;
    if cursor_x < popup_area.x + popup_area.width - 1 {
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}
