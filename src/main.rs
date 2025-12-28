use ansi_to_tui::IntoText;
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use headless_chrome::{protocol::cdp::Page, Browser, LaunchOptions};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    DefaultTerminal, Frame,
};
use std::{
    env, fs,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime},
};

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

#[derive(Default, PartialEq)]
enum InputMode {
    #[default]
    Normal,
    UrlInput,
}

struct App {
    dir: PathBuf,
    images: Vec<PathBuf>,
    list_state: ListState,
    zoom_percent: u16,  // 100 = fit to window, >100 = zoomed in
    density_index: usize,  // index into DENSITY_PRESETS
    scroll_offset: (u16, u16),  // (vertical, horizontal) scroll
    preview_cache: Option<Text<'static>>,
    cached_index: Option<usize>,
    cached_zoom: u16,
    cached_density: usize,
    cached_size: (u16, u16),
    input_mode: InputMode,
    url_input: String,
    status_message: Option<String>,
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
            zoom_percent: 100,  // 100% = fit to window
            density_index: 3,   // "Mixed" default
            scroll_offset: (0, 0),
            preview_cache: None,
            cached_index: None,
            cached_zoom: 0,
            cached_density: 0,
            cached_size: (0, 0),
            input_mode: InputMode::Normal,
            url_input: String::new(),
            status_message: None,
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
        self.scroll_offset = (0, 0);  // Reset scroll on image change
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
        self.scroll_offset = (0, 0);  // Reset scroll on image change
    }

    fn zoom_in(&mut self) {
        self.zoom_percent = self.zoom_percent.saturating_add(25).min(400);
        self.preview_cache = None;  // Force re-render
    }

    fn zoom_out(&mut self) {
        self.zoom_percent = self.zoom_percent.saturating_sub(25).max(25);
        self.preview_cache = None;  // Force re-render
        // Adjust scroll if needed
        self.scroll_offset.0 = self.scroll_offset.0.min(self.zoom_percent);
        self.scroll_offset.1 = self.scroll_offset.1.min(self.zoom_percent);
    }

    fn zoom_reset(&mut self) {
        self.zoom_percent = 100;
        self.scroll_offset = (0, 0);
        self.preview_cache = None;
    }

    fn scroll_up(&mut self) {
        self.scroll_offset.0 = self.scroll_offset.0.saturating_sub(3);
    }

    fn scroll_down(&mut self) {
        self.scroll_offset.0 = self.scroll_offset.0.saturating_add(3);
    }

    fn scroll_left(&mut self) {
        self.scroll_offset.1 = self.scroll_offset.1.saturating_sub(5);
    }

    fn scroll_right(&mut self) {
        self.scroll_offset.1 = self.scroll_offset.1.saturating_add(5);
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

        let options = LaunchOptions::default_builder()
            .path(Some(chrome_path))
            .headless(true)
            .window_size(Some((1920, 1080)))
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

        // Check cache validity
        if self.cached_index == current_index
            && self.cached_zoom == self.zoom_percent
            && self.cached_density == self.density_index
            && self.cached_size == current_size
        {
            if let Some(ref cached) = self.preview_cache {
                return cached.clone();
            }
        }

        let text = if let Some(path) = self.selected_image() {
            // Apply zoom: 100% = fit to window, 200% = 2x size, etc.
            let scaled_width = (width as u32 * self.zoom_percent as u32 / 100) as u16;
            let scaled_height = (height.saturating_sub(2) as u32 * self.zoom_percent as u32 / 100) as u16;
            let size_arg = format!("{}x{}", scaled_width.max(10), scaled_height.max(5));

            let (symbols, _) = self.current_density();
            let output = Command::new("chafa")
                .arg("-s")
                .arg(&size_arg)
                .arg("--symbols")
                .arg(symbols)
                .arg(path)
                .output();

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
                    // Quit (Esc only)
                    KeyCode::Esc => break,

                    // Navigation (arrows or j/k)
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.previous(),
                    KeyCode::Home => {
                        app.list_state.select(Some(0));
                        app.scroll_offset = (0, 0);
                    }
                    KeyCode::End => {
                        if !app.images.is_empty() {
                            app.list_state.select(Some(app.images.len() - 1));
                        }
                    }

                    // WASD panning
                    KeyCode::Char('w') => app.scroll_up(),
                    KeyCode::Char('a') => app.scroll_left(),
                    KeyCode::Char('s') => app.scroll_down(),
                    KeyCode::Char('d') => app.scroll_right(),

                    // Zoom: e = in, q = out
                    KeyCode::Char('e') | KeyCode::Char('+') | KeyCode::Char('=') => app.zoom_in(),
                    KeyCode::Char('q') | KeyCode::Char('-') | KeyCode::Char('_') => app.zoom_out(),
                    KeyCode::Char('f') => {
                        app.zoom_reset();
                        app.status_message = Some("Zoom reset to 100%".to_string());
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

    let content_chunks =
        Layout::horizontal([Constraint::Percentage(25), Constraint::Percentage(75)])
            .split(main_chunks[0]);

    render_file_list(frame, app, content_chunks[0]);
    render_preview(frame, app, content_chunks[1]);
    render_status_bar(frame, app, main_chunks[1]);

    // Render URL input popup if in input mode
    if app.input_mode == InputMode::UrlInput {
        render_url_input(frame, app);
    }
}

fn render_file_list(frame: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .images
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("???");
            ListItem::new(name.to_string())
        })
        .collect();

    let title = format!(" Images ({}) ", app.images.len());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
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
    let title = match app.selected_image() {
        Some(path) => {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("???");
            format!(" {} [{}% {}] ", name, app.zoom_percent, density_name)
        }
        None => " No image ".to_string(),
    };

    let help = Line::raw(" ↑↓:nav  WASD:pan  e/q:zoom  []:density  f:fit  /:url  Esc:quit ");

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_bottom(help);

    let paragraph = Paragraph::new(preview_text)
        .block(block)
        .scroll(app.scroll_offset);
    frame.render_widget(paragraph, area);
}

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let msg = app
        .status_message
        .as_deref()
        .unwrap_or("");

    let status = Paragraph::new(msg)
        .style(Style::default().fg(Color::Yellow));

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

    let input = Paragraph::new(app.url_input.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Enter URL (Enter to capture, Esc to cancel) "),
        );

    frame.render_widget(input, popup_area);

    // Show cursor
    let cursor_x = popup_area.x + 1 + app.url_input.len() as u16;
    let cursor_y = popup_area.y + 1;
    if cursor_x < popup_area.x + popup_area.width - 1 {
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}
