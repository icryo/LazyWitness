# Towser

A TUI image browser with ASCII art rendering via chafa, web screenshot capture, and readable content extraction.

## Features

- Browse images in a directory with file list navigation
- ASCII art preview via [chafa](https://hpjansson.org/chafa/)
- Zoom and pan with real image cropping for detailed viewing
- Screenshot websites using headless Chrome
- Extract readable text content from web pages (via readability-rust)
- WASD gaming-style controls for panning
- Collapsible panels for flexible layouts
- Catppuccin Mocha theme

## Dependencies

- [chafa](https://hpjansson.org/chafa/) - for image to ASCII conversion
- [ImageMagick](https://imagemagick.org/) - for image cropping when zoomed
- Chromium/Chrome - for web screenshots (optional)

## Installation

```bash
cargo build --release
```

## Usage

```bash
./target/release/imgbrowse [directory]
```

If no directory is specified, the current working directory is used.

## Keybindings

| Key | Action |
|-----|--------|
| `j`/`k` or arrows | Navigate file list |
| `w`/`a`/`s`/`d` | Pan when zoomed in |
| `e`/`+` | Zoom in |
| `q`/`-` | Zoom out |
| `f` | Reset view to 100% |
| `[`/`]` | Decrease/increase ASCII density |
| `/` or `c` | Enter URL for screenshot |
| `t` | Cycle screenshot resolution |
| `Tab` | Toggle file list panel |
| `v` | Toggle readable text panel |
| `Shift+W`/`S` | Scroll text pane |
| `r` | Refresh image list |
| `Esc` or `Ctrl-C` | Quit |

## Screenshot Mode

Press `/` to enter a URL. The app will:
1. Take a screenshot using headless Chrome
2. Extract readable content using readability-rust
3. Save both as `<url>_<timestamp>.png` and `.txt`

Press `v` to view the extracted text alongside the screenshot.

## License

MIT
