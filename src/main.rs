use ansi_to_tui::IntoText;
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use headless_chrome::{protocol::cdp::Page, Browser, LaunchOptions};
use image::DynamicImage;
use image_hasher::{HasherConfig, ImageHash};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    DefaultTerminal, Frame,
};
use ratatui_image::{picker::Picker, protocol::StatefulProtocol, Resize, StatefulImage, FilterType};
use rayon::prelude::*;
use readability_rust::Readability;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
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
}

const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "ico"];

// ASCII density presets
const DENSITY_PRESETS: &[(&str, &str)] = &[
    ("block", "Block"),
    ("block+border", "Block+"),
    ("braille", "Braille"),
    ("ascii", "ASCII"),
    ("all", "All"),
];

// Screenshot resolution presets (width, height, label)
const RESOLUTION_PRESETS: &[(u32, u32, &str)] = &[
    (1920, 1080, "1080p"),
    (2560, 1440, "1440p"),
    (3840, 2160, "4K"),
    (1280, 720, "720p"),
];

// Port presets for scanning (matching gowitness)
const SCAN_PORTS: &[u16] = &[
    80, 443, 8080, 8443, 81, 3000, 3128, 8000, 8008, 8081, 8082, 8888, 8800, 10000,
];

/// Result of capturing a URL - stored in SQLite
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CaptureResult {
    url: String,
    final_url: String,
    title: String,
    status_code: u16,
    headers: HashMap<String, String>,
    technologies: Vec<String>,
    screenshot_path: String,
    timestamp: u64,
}

/// Technology fingerprint patterns
struct TechFingerprint {
    name: &'static str,
    headers: &'static [(&'static str, &'static str)],  // (header_name, pattern)
    html_patterns: &'static [&'static str],
}

const TECH_FINGERPRINTS: &[TechFingerprint] = &[
    TechFingerprint {
        name: "nginx",
        headers: &[("server", "nginx")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "Apache",
        headers: &[("server", "apache")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "IIS",
        headers: &[("server", "microsoft-iis")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "Cloudflare",
        headers: &[("server", "cloudflare"), ("cf-ray", "")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "WordPress",
        headers: &[("x-powered-by", "wp")],
        html_patterns: &["wp-content", "wp-includes", "wordpress"],
    },
    TechFingerprint {
        name: "React",
        headers: &[],
        html_patterns: &["react", "_reactroot", "data-reactroot"],
    },
    TechFingerprint {
        name: "Vue.js",
        headers: &[],
        html_patterns: &["vue.js", "vue.min.js", "data-v-", "__vue__"],
    },
    TechFingerprint {
        name: "Angular",
        headers: &[],
        html_patterns: &["ng-version", "angular.js", "angular.min.js"],
    },
    TechFingerprint {
        name: "jQuery",
        headers: &[],
        html_patterns: &["jquery.js", "jquery.min.js", "jquery-"],
    },
    TechFingerprint {
        name: "Bootstrap",
        headers: &[],
        html_patterns: &["bootstrap.css", "bootstrap.min.css", "bootstrap.js"],
    },
    TechFingerprint {
        name: "PHP",
        headers: &[("x-powered-by", "php")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "ASP.NET",
        headers: &[("x-powered-by", "asp.net"), ("x-aspnet-version", "")],
        html_patterns: &["__viewstate", "__eventvalidation"],
    },
    TechFingerprint {
        name: "Express",
        headers: &[("x-powered-by", "express")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "Django",
        headers: &[("x-frame-options", "deny")],  // Common Django default
        html_patterns: &["csrfmiddlewaretoken", "django"],
    },
    TechFingerprint {
        name: "Laravel",
        headers: &[],
        html_patterns: &["laravel", "csrf-token"],
    },
    TechFingerprint {
        name: "Drupal",
        headers: &[("x-drupal-cache", ""), ("x-generator", "drupal")],
        html_patterns: &["drupal.js", "drupal.css", "/sites/default/"],
    },
    TechFingerprint {
        name: "Joomla",
        headers: &[],
        html_patterns: &["joomla", "/media/system/js/", "/templates/"],
    },
    TechFingerprint {
        name: "Shopify",
        headers: &[("x-shopify-stage", "")],
        html_patterns: &["cdn.shopify.com", "shopify.com"],
    },
    TechFingerprint {
        name: "Wix",
        headers: &[],
        html_patterns: &["wix.com", "static.wixstatic.com"],
    },
    TechFingerprint {
        name: "Squarespace",
        headers: &[],
        html_patterns: &["squarespace.com", "static.squarespace.com"],
    },
];

/// Application signature for default credentials detection (like EyeWitness)
struct AppSignature {
    name: &'static str,
    patterns: &'static [&'static str],
    default_creds: &'static [(&'static str, &'static str)],
    admin_paths: &'static [&'static str],
}

const APP_SIGNATURES: &[AppSignature] = &[
    // Web Application Servers
    AppSignature {
        name: "Apache Tomcat",
        patterns: &["apache tomcat", "tomcat manager", "/manager/html"],
        default_creds: &[("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager"), ("tomcat", "s3cret")],
        admin_paths: &["/manager/html", "/host-manager/html", "/manager/status"],
    },
    AppSignature {
        name: "JBoss/WildFly",
        patterns: &["jboss", "wildfly", "jboss application server"],
        default_creds: &[("admin", "admin"), ("jboss", "jboss")],
        admin_paths: &["/admin-console", "/jmx-console", "/web-console"],
    },
    AppSignature {
        name: "WebLogic",
        patterns: &["weblogic", "oracle weblogic"],
        default_creds: &[("weblogic", "weblogic"), ("system", "password"), ("weblogic", "welcome1")],
        admin_paths: &["/console", "/em"],
    },
    AppSignature {
        name: "GlassFish",
        patterns: &["glassfish", "sun glassfish"],
        default_creds: &[("admin", "admin"), ("admin", "adminadmin")],
        admin_paths: &["/common/index.jsf"],
    },
    // CI/CD & DevOps
    AppSignature {
        name: "Jenkins",
        patterns: &["dashboard [jenkins]", "jenkins", "hudson"],
        default_creds: &[("admin", "admin"), ("jenkins", "jenkins")],
        admin_paths: &["/manage", "/script", "/configure"],
    },
    AppSignature {
        name: "GitLab",
        patterns: &["gitlab", "sign in · gitlab"],
        default_creds: &[("root", "5iveL!fe"), ("admin@local.host", "5iveL!fe")],
        admin_paths: &["/admin", "/users/sign_in"],
    },
    AppSignature {
        name: "Gitea",
        patterns: &["gitea", "git with a cup of tea"],
        default_creds: &[("gitea", "gitea")],
        admin_paths: &["/admin", "/user/login"],
    },
    AppSignature {
        name: "Gogs",
        patterns: &["gogs", "gogs - go git service"],
        default_creds: &[("gogs", "gogs")],
        admin_paths: &["/admin", "/user/login"],
    },
    AppSignature {
        name: "TeamCity",
        patterns: &["teamcity", "log in to teamcity"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/admin/admin.html", "/login.html"],
    },
    AppSignature {
        name: "Bamboo",
        patterns: &["atlassian bamboo", "bamboo"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/admin", "/userlogin!default.action"],
    },
    AppSignature {
        name: "SonarQube",
        patterns: &["sonarqube", "sonar"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/sessions/new", "/admin"],
    },
    AppSignature {
        name: "Nexus Repository",
        patterns: &["nexus repository", "sonatype nexus"],
        default_creds: &[("admin", "admin123")],
        admin_paths: &["/nexus", "/#admin"],
    },
    AppSignature {
        name: "Artifactory",
        patterns: &["jfrog artifactory", "artifactory"],
        default_creds: &[("admin", "password")],
        admin_paths: &["/artifactory", "/ui/login"],
    },
    AppSignature {
        name: "Portainer",
        patterns: &["portainer"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/#/auth", "/#/init/admin"],
    },
    AppSignature {
        name: "Rancher",
        patterns: &["rancher", "rancher labs"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/login", "/g"],
    },
    // Monitoring & Observability
    AppSignature {
        name: "Grafana",
        patterns: &["grafana"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/login", "/admin"],
    },
    AppSignature {
        name: "Kibana",
        patterns: &["kibana"],
        default_creds: &[("elastic", "changeme")],
        admin_paths: &["/app/kibana", "/login"],
    },
    AppSignature {
        name: "Prometheus",
        patterns: &["prometheus time series", "prometheus"],
        default_creds: &[],
        admin_paths: &["/graph", "/targets", "/config"],
    },
    AppSignature {
        name: "Nagios",
        patterns: &["nagios core", "nagios xi"],
        default_creds: &[("nagiosadmin", "nagios"), ("nagiosadmin", "nagiosadmin")],
        admin_paths: &["/nagios", "/nagiosxi"],
    },
    AppSignature {
        name: "Zabbix",
        patterns: &["zabbix"],
        default_creds: &[("Admin", "zabbix"), ("guest", "")],
        admin_paths: &["/zabbix.php", "/index.php"],
    },
    AppSignature {
        name: "Cacti",
        patterns: &["cacti", "the complete rrd"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/cacti", "/index.php"],
    },
    AppSignature {
        name: "PRTG",
        patterns: &["prtg network monitor", "prtg"],
        default_creds: &[("prtgadmin", "prtgadmin")],
        admin_paths: &["/index.htm", "/public/login.htm"],
    },
    // CMS
    AppSignature {
        name: "WordPress",
        patterns: &["wp-content", "wp-login", "wordpress"],
        default_creds: &[("admin", "admin"), ("admin", "password"), ("admin", "admin123")],
        admin_paths: &["/wp-admin", "/wp-login.php"],
    },
    AppSignature {
        name: "Joomla",
        patterns: &["joomla", "/administrator"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/administrator", "/administrator/index.php"],
    },
    AppSignature {
        name: "Drupal",
        patterns: &["drupal", "powered by drupal"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/admin", "/user/login"],
    },
    AppSignature {
        name: "Magento",
        patterns: &["magento", "mage."],
        default_creds: &[("admin", "admin123"), ("admin", "magento")],
        admin_paths: &["/admin", "/index.php/admin"],
    },
    // Database Management
    AppSignature {
        name: "phpMyAdmin",
        patterns: &["phpmyadmin"],
        default_creds: &[("root", ""), ("root", "root"), ("root", "password"), ("admin", "admin")],
        admin_paths: &["/phpmyadmin", "/pma"],
    },
    AppSignature {
        name: "Adminer",
        patterns: &["adminer", "database management in a single php"],
        default_creds: &[("root", ""), ("root", "root")],
        admin_paths: &["/adminer.php", "/adminer"],
    },
    AppSignature {
        name: "pgAdmin",
        patterns: &["pgadmin"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/login", "/browser"],
    },
    AppSignature {
        name: "MongoDB Express",
        patterns: &["mongo express", "mongodb"],
        default_creds: &[("admin", "pass")],
        admin_paths: &["/", "/db"],
    },
    // Network Devices
    AppSignature {
        name: "Cisco",
        patterns: &["cisco", "cisco systems"],
        default_creds: &[("admin", "admin"), ("cisco", "cisco"), ("admin", "")],
        admin_paths: &["/level/15/exec/-"],
    },
    AppSignature {
        name: "Netgear",
        patterns: &["netgear"],
        default_creds: &[("admin", "password"), ("admin", "1234")],
        admin_paths: &["/currentsetting.htm", "/start.htm"],
    },
    AppSignature {
        name: "TP-Link",
        patterns: &["tp-link"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/userRpm/LoginRpm.htm"],
    },
    AppSignature {
        name: "D-Link",
        patterns: &["d-link"],
        default_creds: &[("admin", ""), ("admin", "admin")],
        admin_paths: &["/login.html", "/index.cgi"],
    },
    AppSignature {
        name: "Ubiquiti/UniFi",
        patterns: &["ubiquiti", "unifi"],
        default_creds: &[("ubnt", "ubnt"), ("admin", "admin")],
        admin_paths: &["/manage", "/login"],
    },
    AppSignature {
        name: "MikroTik",
        patterns: &["mikrotik", "routerboard", "routeros"],
        default_creds: &[("admin", "")],
        admin_paths: &["/webfig", "/winbox"],
    },
    // Firewalls
    AppSignature {
        name: "pfSense",
        patterns: &["pfsense"],
        default_creds: &[("admin", "pfsense")],
        admin_paths: &["/index.php"],
    },
    AppSignature {
        name: "OPNsense",
        patterns: &["opnsense"],
        default_creds: &[("root", "opnsense")],
        admin_paths: &["/index.php"],
    },
    AppSignature {
        name: "Fortinet/FortiGate",
        patterns: &["fortinet", "fortigate"],
        default_creds: &[("admin", "")],
        admin_paths: &["/ng/login", "/login"],
    },
    AppSignature {
        name: "SonicWall",
        patterns: &["sonicwall"],
        default_creds: &[("admin", "password")],
        admin_paths: &["/main.html", "/auth.html"],
    },
    // NAS/Storage
    AppSignature {
        name: "Synology DSM",
        patterns: &["synology", "diskstation"],
        default_creds: &[("admin", "")],
        admin_paths: &["/webman/index.cgi"],
    },
    AppSignature {
        name: "QNAP",
        patterns: &["qnap", "qts"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/cgi-bin/login.html"],
    },
    AppSignature {
        name: "FreeNAS/TrueNAS",
        patterns: &["freenas", "truenas"],
        default_creds: &[("root", "freenas"), ("admin", "freenas")],
        admin_paths: &["/ui/sessions/signin"],
    },
    // Remote Access
    AppSignature {
        name: "Apache Guacamole",
        patterns: &["guacamole", "apache guacamole"],
        default_creds: &[("guacadmin", "guacadmin")],
        admin_paths: &["/#/", "/#/settings"],
    },
    AppSignature {
        name: "VNC Web",
        patterns: &["vnc", "novnc"],
        default_creds: &[],
        admin_paths: &["/vnc.html"],
    },
    // Webmail
    AppSignature {
        name: "Roundcube",
        patterns: &["roundcube"],
        default_creds: &[],
        admin_paths: &["/?_task=login"],
    },
    AppSignature {
        name: "Zimbra",
        patterns: &["zimbra"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/zimbraAdmin", "/zimbra"],
    },
    // Virtualization
    AppSignature {
        name: "Proxmox VE",
        patterns: &["proxmox virtual environment", "proxmox"],
        default_creds: &[("root", "pve")],
        admin_paths: &["/#v1:0:18:4"],
    },
    AppSignature {
        name: "VMware vSphere",
        patterns: &["vmware vsphere", "vsphere"],
        default_creds: &[("admin", "admin"), ("root", "vmware")],
        admin_paths: &["/ui/"],
    },
    AppSignature {
        name: "XenServer/XCP-ng",
        patterns: &["xenserver", "xcp-ng", "citrix hypervisor"],
        default_creds: &[("root", "xenserver")],
        admin_paths: &["/"],
    },
    // Other
    AppSignature {
        name: "Webmin",
        patterns: &["webmin"],
        default_creds: &[("admin", "admin"), ("root", "root")],
        admin_paths: &["/"],
    },
    AppSignature {
        name: "cPanel",
        patterns: &["cpanel", "whm"],
        default_creds: &[],
        admin_paths: &["/cpanel", "/whm"],
    },
    AppSignature {
        name: "Plesk",
        patterns: &["plesk"],
        default_creds: &[("admin", "setup")],
        admin_paths: &["/login_up.php"],
    },
    AppSignature {
        name: "Elasticsearch",
        patterns: &["elasticsearch", "you know, for search"],
        default_creds: &[("elastic", "changeme")],
        admin_paths: &["/_cat/indices", "/_cluster/health"],
    },
    AppSignature {
        name: "RabbitMQ",
        patterns: &["rabbitmq"],
        default_creds: &[("guest", "guest")],
        admin_paths: &["/#/", "/api/overview"],
    },
    AppSignature {
        name: "Splunk",
        patterns: &["splunk"],
        default_creds: &[("admin", "changeme")],
        admin_paths: &["/en-US/account/login", "/en-US/app/launcher/home"],
    },
    AppSignature {
        name: "Graylog",
        patterns: &["graylog"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/", "/system/overview"],
    },
    AppSignature {
        name: "AWX/Ansible Tower",
        patterns: &["awx", "ansible tower"],
        default_creds: &[("admin", "password")],
        admin_paths: &["/#/login", "/#/home"],
    },
    AppSignature {
        name: "Apache Airflow",
        patterns: &["airflow"],
        default_creds: &[("admin", "admin"), ("airflow", "airflow")],
        admin_paths: &["/login/", "/home"],
    },
    AppSignature {
        name: "MinIO",
        patterns: &["minio", "high performance object storage"],
        default_creds: &[("minioadmin", "minioadmin")],
        admin_paths: &["/minio/login"],
    },
    AppSignature {
        name: "HashiCorp Vault",
        patterns: &["vault", "hashicorp vault"],
        default_creds: &[],
        admin_paths: &["/ui/vault/auth"],
    },
    AppSignature {
        name: "HashiCorp Consul",
        patterns: &["consul"],
        default_creds: &[],
        admin_paths: &["/ui/", "/v1/agent/self"],
    },
    AppSignature {
        name: "Traefik Dashboard",
        patterns: &["traefik"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/dashboard/", "/api/overview"],
    },
];

/// Detect application signature from text content
fn detect_app_signature(content: &str) -> Option<&'static AppSignature> {
    let content_lower = content.to_lowercase();
    for sig in APP_SIGNATURES {
        for pattern in sig.patterns {
            if content_lower.contains(pattern) {
                return Some(sig);
            }
        }
    }
    None
}


/// Parse Nmap XML file and extract URLs to scan
fn parse_nmap_xml(path: &PathBuf) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to read nmap file: {}", e))?;

    let doc = roxmltree::Document::parse(&content)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse nmap XML: {}", e))?;

    let mut urls = Vec::new();

    // Find all host elements
    for host in doc.descendants().filter(|n| n.has_tag_name("host")) {
        // Get host address
        let addr = host.descendants()
            .find(|n| n.has_tag_name("address") && n.attribute("addrtype") == Some("ipv4"))
            .and_then(|n| n.attribute("addr"));

        // Also check for hostname
        let hostname = host.descendants()
            .find(|n| n.has_tag_name("hostname"))
            .and_then(|n| n.attribute("name"));

        let host_str = hostname.or(addr);

        if let Some(host_str) = host_str {
            // Find open ports with http/https services
            for port in host.descendants().filter(|n| n.has_tag_name("port")) {
                let state = port.descendants()
                    .find(|n| n.has_tag_name("state"))
                    .and_then(|n| n.attribute("state"));

                if state != Some("open") {
                    continue;
                }

                let port_num = port.attribute("portid").and_then(|p| p.parse::<u16>().ok());
                let service = port.descendants()
                    .find(|n| n.has_tag_name("service"))
                    .and_then(|n| n.attribute("name"))
                    .unwrap_or("");

                if let Some(port_num) = port_num {
                    // Determine protocol based on service name or port
                    let is_ssl = service.contains("ssl") || service.contains("https")
                        || port_num == 443 || port_num == 8443;

                    let is_http = is_ssl || service.contains("http")
                        || port_num == 80 || port_num == 8080 || port_num == 8000
                        || port_num == 3000 || port_num == 8888;

                    if is_http {
                        let scheme = if is_ssl { "https" } else { "http" };
                        let url = if port_num == 80 || port_num == 443 {
                            format!("{}://{}", scheme, host_str)
                        } else {
                            format!("{}://{}:{}", scheme, host_str, port_num)
                        };
                        urls.push(url);
                    }
                }
            }
        }
    }

    Ok(urls)
}

/// Initialize SQLite database
fn init_database(db_path: &PathBuf) -> Result<Connection> {
    let conn = Connection::open(db_path)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to open database: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS captures (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            final_url TEXT,
            title TEXT,
            status_code INTEGER,
            headers TEXT,
            technologies TEXT,
            screenshot_path TEXT,
            timestamp INTEGER,
            phash TEXT
        )",
        [],
    ).map_err(|e| color_eyre::eyre::eyre!("Failed to create table: {}", e))?;

    // Create index on URL for faster lookups
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_url ON captures(url)",
        [],
    ).ok();

    Ok(conn)
}

/// Save capture result to database
fn save_to_database(conn: &Connection, result: &CaptureResult, phash: Option<&str>) -> Result<()> {
    let headers_json = serde_json::to_string(&result.headers).unwrap_or_default();
    let tech_json = serde_json::to_string(&result.technologies).unwrap_or_default();

    conn.execute(
        "INSERT INTO captures (url, final_url, title, status_code, headers, technologies, screenshot_path, timestamp, phash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            result.url,
            result.final_url,
            result.title,
            result.status_code,
            headers_json,
            tech_json,
            result.screenshot_path,
            result.timestamp,
            phash.unwrap_or(""),
        ],
    ).map_err(|e| color_eyre::eyre::eyre!("Failed to insert: {}", e))?;

    Ok(())
}

/// Detect technologies from headers and HTML content
fn detect_technologies(headers: &HashMap<String, String>, html: &str) -> Vec<String> {
    let mut detected = Vec::new();
    let html_lower = html.to_lowercase();

    for fp in TECH_FINGERPRINTS {
        let mut matched = false;

        // Check headers
        for (header_name, pattern) in fp.headers {
            if let Some(value) = headers.get(&header_name.to_lowercase()) {
                if pattern.is_empty() || value.to_lowercase().contains(pattern) {
                    matched = true;
                    break;
                }
            }
        }

        // Check HTML patterns
        if !matched {
            for pattern in fp.html_patterns {
                if html_lower.contains(pattern) {
                    matched = true;
                    break;
                }
            }
        }

        if matched {
            detected.push(fp.name.to_string());
        }
    }

    detected
}

/// Extract title from HTML
fn extract_title(html: &str) -> String {
    let title_re = Regex::new(r"<title[^>]*>([^<]+)</title>").ok();
    if let Some(re) = title_re {
        if let Some(caps) = re.captures(html) {
            if let Some(m) = caps.get(1) {
                return m.as_str().trim().to_string();
            }
        }
    }
    String::new()
}

#[derive(Default, PartialEq, Clone)]
enum InputMode {
    #[default]
    Normal,
    UrlInput,
    ScanInput,
    Help,
    ConfirmDelete,
    Filter,
}

#[derive(Default, PartialEq, Clone, Copy)]
enum RenderMode {
    #[default]
    Native,  // Use ratatui-image (Kitty/iTerm2/Sixel/Halfblocks)
    Chafa,   // Use chafa CLI (ASCII art)
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
    scan_input: String,      // Host/IP for port scanning
    status_message: Option<String>,
    show_file_list: bool,
    show_text_pane: bool,    // Show readable text alongside image
    text_scroll: u16,        // Scroll position for text pane
    fullscreen: bool,        // Fullscreen mode (hide all panels)
    prev_file_list: bool,    // Previous state before fullscreen
    prev_text_pane: bool,    // Previous state before fullscreen
    // Native graphics protocol support (yazi-style)
    render_mode: RenderMode,
    picker: Option<Picker>,
    image_state: Option<StatefulProtocol>,
    loaded_image: Option<DynamicImage>,
    native_image_index: Option<usize>,  // Which image is loaded for native rendering
    native_render_size: (u16, u16),     // Track area size to invalidate on resize
    native_zoom: u16,                   // Track zoom to invalidate on change
    native_pan: (i16, i16),             // Track pan to invalidate on change
    native_img_dims: Option<(u32, u32)>, // Dimensions of image being rendered (for debug)
    needs_full_redraw: bool,             // Flag to force terminal.clear() on next frame
    filter_input: String,                // Current filter pattern
    // Performance caches
    cached_file_ages: Vec<String>,       // Cached file ages (updated on refresh)
    cached_filter_set: std::collections::HashSet<usize>, // O(1) filter lookup
    cached_filter_vec: Vec<usize>,       // Sorted filter indices for navigation
    cached_filter_pattern: String,       // Pattern used to generate cached_filter_set
}

impl App {
    fn new(dir: PathBuf) -> Result<Self> {
        let images = Self::scan_images(&dir)?;
        let mut list_state = ListState::default();
        if !images.is_empty() {
            list_state.select(Some(0));
        }

        // Try to detect native graphics protocol support
        let (picker, render_mode) = match Picker::from_query_stdio() {
            Ok(p) => (Some(p), RenderMode::Native),
            Err(_) => (None, RenderMode::Chafa), // Fallback to chafa for SSH/unsupported terminals
        };

        // Pre-compute caches
        let cached_file_ages: Vec<String> = images.iter().map(|p| format_age(p)).collect();
        let cached_filter_set: std::collections::HashSet<usize> = (0..images.len()).collect();
        let cached_filter_vec: Vec<usize> = (0..images.len()).collect();

        Ok(Self {
            dir,
            images,
            list_state,
            zoom_percent: 100,   // 100% = full image
            pan_x: 0,
            pan_y: 0,
            density_index: 0,    // "Block" default (best compatibility)
            resolution_index: 0, // 1080p default
            preview_cache: None,
            cached_index: None,
            cached_zoom: 0,
            cached_pan: (0, 0),
            cached_density: 0,
            cached_size: (0, 0),
            input_mode: InputMode::Normal,
            url_input: String::new(),
            scan_input: String::new(),
            status_message: None,
            show_file_list: true,
            show_text_pane: false,
            text_scroll: 0,
            fullscreen: false,
            prev_file_list: true,
            prev_text_pane: false,
            // Native graphics protocol
            render_mode,
            picker,
            image_state: None,
            loaded_image: None,
            native_image_index: None,
            native_render_size: (0, 0),
            native_zoom: 100,
            native_pan: (0, 0),
            native_img_dims: None,
            needs_full_redraw: false,
            filter_input: String::new(),
            cached_file_ages,
            cached_filter_set,
            cached_filter_vec,
            cached_filter_pattern: String::new(),
        })
    }

    fn toggle_fullscreen(&mut self) {
        if self.fullscreen {
            // Restore previous state
            self.show_file_list = self.prev_file_list;
            self.show_text_pane = self.prev_text_pane;
            self.fullscreen = false;
        } else {
            // Save current state and go fullscreen
            self.prev_file_list = self.show_file_list;
            self.prev_text_pane = self.show_text_pane;
            self.show_file_list = false;
            self.show_text_pane = false;
            self.fullscreen = true;
        }
        self.preview_cache = None; // Invalidate cache for resize
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

        // Cache file ages (avoids syscalls during render)
        self.cached_file_ages = self.images.iter().map(|p| format_age(p)).collect();

        // Invalidate caches
        self.preview_cache = None;
        self.update_filter_cache();

        Ok(())
    }

    fn update_filter_cache(&mut self) {
        if self.filter_input == self.cached_filter_pattern {
            return;
        }
        self.cached_filter_pattern = self.filter_input.clone();
        self.cached_filter_set.clear();
        self.cached_filter_vec.clear();

        if self.filter_input.is_empty() {
            // All indices match when no filter
            self.cached_filter_set = (0..self.images.len()).collect();
            self.cached_filter_vec = (0..self.images.len()).collect();
        } else {
            let pattern = self.filter_input.to_lowercase();
            for (i, path) in self.images.iter().enumerate() {
                if path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|name| name.to_lowercase().contains(&pattern))
                    .unwrap_or(false)
                {
                    self.cached_filter_set.insert(i);
                    self.cached_filter_vec.push(i);
                }
            }
        }
    }

    fn delete_current(&mut self) -> Result<bool> {
        let Some(idx) = self.selected_index() else {
            return Ok(false);
        };
        let Some(path) = self.images.get(idx).cloned() else {
            return Ok(false);
        };

        // Delete the image file
        fs::remove_file(&path)?;

        // Also delete associated .txt file if it exists
        let txt_path = path.with_extension("txt");
        if txt_path.exists() {
            fs::remove_file(&txt_path).ok();
        }

        // Remove from list and adjust selection
        self.images.remove(idx);
        if self.images.is_empty() {
            self.list_state.select(None);
        } else if idx >= self.images.len() {
            self.list_state.select(Some(self.images.len() - 1));
        } else {
            self.list_state.select(Some(idx));
        }

        // Invalidate all caches
        self.preview_cache = None;
        self.image_state = None;
        self.loaded_image = None;
        self.native_image_index = None;

        Ok(true)
    }

    fn selected_index(&self) -> Option<usize> {
        self.list_state.selected()
    }

    fn selected_image(&self) -> Option<&PathBuf> {
        self.selected_index().and_then(|i| self.images.get(i))
    }

    fn next(&mut self) {
        if self.cached_filter_vec.is_empty() {
            return;
        }
        let current = self.list_state.selected();
        let next_idx = match current {
            Some(i) => {
                // Find next filtered index after current
                self.cached_filter_vec.iter()
                    .find(|&&idx| idx > i)
                    .or(self.cached_filter_vec.first())
                    .copied()
                    .unwrap_or(i)
            }
            None => self.cached_filter_vec[0],
        };
        self.list_state.select(Some(next_idx));
        self.reset_view();
        self.status_message = None;
    }

    fn previous(&mut self) {
        if self.cached_filter_vec.is_empty() {
            return;
        }
        let current = self.list_state.selected();
        let prev_idx = match current {
            Some(i) => {
                // Find previous filtered index before current
                self.cached_filter_vec.iter().rev()
                    .find(|&&idx| idx < i)
                    .or(self.cached_filter_vec.last())
                    .copied()
                    .unwrap_or(i)
            }
            None => *self.cached_filter_vec.last().unwrap(),
        };
        self.list_state.select(Some(prev_idx));
        self.reset_view();
        self.status_message = None;
    }

    fn clear_filter(&mut self) {
        self.filter_input.clear();
        self.update_filter_cache();
    }

    fn apply_filter(&mut self) {
        // Update cache first
        self.update_filter_cache();

        // Select first matching item if current selection doesn't match
        if self.cached_filter_set.is_empty() {
            return;
        }
        if let Some(current) = self.list_state.selected() {
            if !self.cached_filter_set.contains(&current) {
                // Find first matching index
                if let Some(&first) = self.cached_filter_set.iter().min() {
                    self.list_state.select(Some(first));
                    self.reset_view();
                }
            }
        }
    }

    fn reset_view(&mut self) {
        self.zoom_percent = 100;
        self.pan_x = 0;
        self.pan_y = 0;
        self.preview_cache = None;
        self.text_scroll = 0;
        // Reset native image state for new image
        self.image_state = None;
    }

    fn zoom_in(&mut self) {
        self.zoom_percent = self.zoom_percent.saturating_add(50).min(800);
        self.clamp_pan();
        self.preview_cache = None;
        self.image_state = None; // Force native mode to re-render
    }

    fn zoom_out(&mut self) {
        self.zoom_percent = self.zoom_percent.saturating_sub(50).max(100);
        self.clamp_pan();
        self.preview_cache = None;
        self.image_state = None; // Force native mode to re-render
    }

    // Pan the view (moves which part of the image we're looking at)
    fn pan_up(&mut self) {
        self.pan_y = self.pan_y.saturating_sub(10);
        self.clamp_pan();
        self.preview_cache = None;
        self.image_state = None;
    }

    fn pan_down(&mut self) {
        self.pan_y = self.pan_y.saturating_add(10);
        self.clamp_pan();
        self.preview_cache = None;
        self.image_state = None;
    }

    fn pan_left(&mut self) {
        self.pan_x = self.pan_x.saturating_sub(10);
        self.clamp_pan();
        self.preview_cache = None;
        self.image_state = None;
    }

    fn pan_right(&mut self) {
        self.pan_x = self.pan_x.saturating_add(10);
        self.clamp_pan();
        self.preview_cache = None;
        self.image_state = None;
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

    fn scan_host(&mut self, input: &str, terminal: &mut DefaultTerminal) -> Result<()> {
        use ipnet::IpNet;
        use std::net::TcpStream;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::mpsc;

        let input = input.trim();
        if input.is_empty() {
            return Ok(());
        }

        // Collect hosts to scan - either from CIDR or single host
        let hosts: Vec<String> = if input.contains('/') {
            // Parse as CIDR
            match input.parse::<IpNet>() {
                Ok(net) => net.hosts().map(|ip| ip.to_string()).collect(),
                Err(_) => {
                    self.status_message = Some(format!("Invalid CIDR: {}", input));
                    return Ok(());
                }
            }
        } else {
            // Single host - could be IP or hostname
            vec![input.to_string()]
        };

        let total_hosts = hosts.len();
        let ports = SCAN_PORTS;
        let total_checks = total_hosts * ports.len();

        // === Phase 1: Parallel port discovery with live progress ===
        // Build socket list: port-first order (like RustScan's SocketIterator)
        let sockets: Vec<(String, u16)> = ports
            .iter()
            .flat_map(|&port| hosts.iter().map(move |host| (host.clone(), port)))
            .collect();

        // Progress tracking with atomics and channel for found ports
        let checked = Arc::new(AtomicUsize::new(0));
        let found_count = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<(String, u16)>();
        let timeout = Duration::from_millis(150); // Faster timeout for local networks

        // Spawn scanning in a thread so we can update UI
        let checked_clone = Arc::clone(&checked);
        let found_clone = Arc::clone(&found_count);
        let cancelled_clone = Arc::clone(&cancelled);
        let scan_handle = std::thread::spawn(move || {
            sockets
                .par_iter()
                .for_each(|(host, port)| {
                    // Check for cancellation
                    if cancelled_clone.load(Ordering::Relaxed) {
                        return;
                    }

                    // Try to parse as socket address
                    let addr = format!("{}:{}", host, port);
                    let socket_addr: std::net::SocketAddr = match addr.parse() {
                        Ok(a) => a,
                        Err(_) => {
                            checked_clone.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };

                    // TCP connect with timeout
                    let is_open = TcpStream::connect_timeout(&socket_addr, timeout).is_ok();

                    checked_clone.fetch_add(1, Ordering::Relaxed);

                    if is_open {
                        found_clone.fetch_add(1, Ordering::Relaxed);
                        let _ = tx.send((host.clone(), *port));
                    }
                });
        });

        // Collect results while updating UI, checking for cancel
        let mut open_ports = Vec::new();
        let mut was_cancelled = false;
        loop {
            // Check for Esc key to cancel
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Esc {
                        cancelled.store(true, Ordering::Relaxed);
                        was_cancelled = true;
                        self.status_message = Some("Cancelling scan...".to_string());
                        terminal.draw(|frame| ui(frame, self))?;
                        break;
                    }
                }
            }

            // Try to receive any found ports (non-blocking)
            while let Ok(port_info) = rx.try_recv() {
                open_ports.push(port_info);
            }

            let current_checked = checked.load(Ordering::Relaxed);
            let current_found = found_count.load(Ordering::Relaxed);
            let pct = (current_checked * 100) / total_checks.max(1);

            self.status_message = Some(format!(
                "Scanning: {}% ({}/{}) - {} open [Esc to cancel]",
                pct, current_checked, total_checks, current_found
            ));
            terminal.draw(|frame| ui(frame, self))?;

            // Check if scan is complete
            if current_checked >= total_checks {
                break;
            }
        }

        // Wait for scan thread to finish and collect remaining results
        let _ = scan_handle.join();
        while let Ok(port_info) = rx.try_recv() {
            open_ports.push(port_info);
        }

        if was_cancelled {
            self.status_message = Some(format!("Scan cancelled. {} open ports found.", open_ports.len()));
            return Ok(());
        }

        // === Phase 2: Sequential screenshot capture ===
        let open_count = open_ports.len();
        if open_count == 0 {
            self.status_message = Some("Scan complete: no open ports found".to_string());
            return Ok(());
        }

        let mut captured = 0;
        for (idx, (host, port)) in open_ports.iter().enumerate() {
            // Check for Esc key to cancel before each capture
            if event::poll(Duration::from_millis(0))? {
                if let Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Esc {
                        self.refresh_images()?;
                        self.status_message = Some(format!(
                            "Scan cancelled. {} captured of {} open ports.",
                            captured, open_count
                        ));
                        return Ok(());
                    }
                }
            }

            // Try both protocols, prefer HTTPS
            for scheme in &["https", "http"] {
                let url = format!("{}://{}:{}", scheme, host, port);
                self.status_message = Some(format!(
                    "[{}/{}] Capturing {} [Esc to cancel]",
                    idx + 1, open_count, url
                ));
                terminal.draw(|frame| ui(frame, self))?;

                let output_path = self.generate_screenshot_filename(&url);

                if self.capture_with_chrome(&url, &output_path).is_ok() {
                    self.extract_readable_content(&url, &output_path);
                    captured += 1;

                    // Refresh image list so user sees new screenshots appear
                    self.refresh_images()?;

                    self.status_message = Some(format!(
                        "[{}/{}] Captured! ({} total) [Esc to cancel]",
                        idx + 1, open_count, captured
                    ));
                    terminal.draw(|frame| ui(frame, self))?;
                    break;
                }
            }
        }

        self.refresh_images()?;
        self.status_message = Some(format!(
            "Scan complete: {} open, {} captured",
            open_count, captured
        ));

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
            let content = fs::read_to_string(&txt_path).ok()?;

            // Check for app signatures and prepend credential info
            if let Some(sig) = detect_app_signature(&content) {
                let mut output = String::new();
                output.push_str("═══════════════════════════════════════════\n");
                output.push_str(&format!(" DETECTED: {}\n", sig.name));
                output.push_str("═══════════════════════════════════════════\n\n");

                if !sig.default_creds.is_empty() {
                    output.push_str(" DEFAULT CREDENTIALS:\n");
                    for (user, pass) in sig.default_creds {
                        if pass.is_empty() {
                            output.push_str(&format!("   {} : (blank)\n", user));
                        } else {
                            output.push_str(&format!("   {} : {}\n", user, pass));
                        }
                    }
                    output.push('\n');
                }

                if !sig.admin_paths.is_empty() {
                    output.push_str(" TRY THESE PATHS:\n");
                    for path in sig.admin_paths {
                        output.push_str(&format!("   {}\n", path));
                    }
                    output.push('\n');
                }

                output.push_str("───────────────────────────────────────────\n\n");
                output.push_str(&content);
                Some(output)
            } else {
                Some(content)
            }
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
        use std::ffi::OsStr;

        let chrome_path = Self::find_chrome()
            .ok_or_else(|| color_eyre::eyre::eyre!("Chrome/Chromium not found. Set CHROME_PATH or install chromium-browser"))?;

        let (width, height, _) = self.current_resolution();

        // Anti-detection flags
        let stealth_args: Vec<&OsStr> = vec![
            OsStr::new("--disable-blink-features=AutomationControlled"),
            OsStr::new("--disable-features=IsolateOrigins,site-per-process"),
            OsStr::new("--disable-site-isolation-trials"),
            OsStr::new("--disable-web-security"),
            OsStr::new("--disable-features=BlockInsecurePrivateNetworkRequests"),
            OsStr::new("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        ];

        let options = LaunchOptions::default_builder()
            .path(Some(chrome_path))
            .headless(true)
            .window_size(Some((width, height)))
            .args(stealth_args)
            .build()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to build launch options: {}", e))?;

        let browser = Browser::new(options)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to launch browser: {}", e))?;

        let tab = browser
            .new_tab()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create tab: {}", e))?;

        // Inject stealth JS before page loads
        let _ = tab.evaluate(
            r#"
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            window.chrome = { runtime: {} };
            "#,
            false,
        );

        tab.navigate_to(url)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to navigate: {}", e))?;

        // Wait for page to load
        tab.wait_until_navigated()
            .map_err(|e| color_eyre::eyre::eyre!("Navigation timeout: {}", e))?;

        // Small delay for dynamic content
        std::thread::sleep(Duration::from_millis(1000));

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
                            .arg("--colors=full")
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
                    .arg("--colors=full")
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

    fn toggle_render_mode(&mut self) {
        self.render_mode = match self.render_mode {
            RenderMode::Native => RenderMode::Chafa,
            RenderMode::Chafa => {
                // Only switch to Native if we have a picker
                if self.picker.is_some() {
                    RenderMode::Native
                } else {
                    RenderMode::Chafa
                }
            }
        };
        // Clear caches when switching modes
        self.preview_cache = None;
        self.image_state = None;
    }

    fn render_mode_name(&self) -> &'static str {
        match self.render_mode {
            RenderMode::Native => "Native",
            RenderMode::Chafa => "Chafa",
        }
    }

    fn load_native_image(&mut self) {
        let current_index = self.selected_index();

        // Check if we already have this image loaded
        if self.native_image_index == current_index && self.loaded_image.is_some() {
            return;
        }

        // Load new image
        if let Some(path) = self.selected_image() {
            match image::ImageReader::open(path) {
                Ok(reader) => match reader.decode() {
                    Ok(img) => {
                        self.loaded_image = Some(img);
                        self.native_image_index = current_index;
                        self.image_state = None; // Reset state for new image
                    }
                    Err(_) => {
                        self.loaded_image = None;
                        self.native_image_index = None;
                    }
                },
                Err(_) => {
                    self.loaded_image = None;
                    self.native_image_index = None;
                }
            }
        }
    }

    fn prepare_image_protocol(&mut self, _target_cols: u16, _target_rows: u16) -> Option<(u32, u32)> {
        if self.image_state.is_some() {
            return None; // Already prepared
        }

        // Get crop region before borrowing other fields
        let crop_region = self.get_crop_region();
        let zoom = self.zoom_percent;
        let pan = (self.pan_x, self.pan_y);
        let mut result_dims = None;

        if let (Some(picker), Some(img)) = (&mut self.picker, &self.loaded_image) {
            // Apply crop if zoomed (this is our zoom implementation)
            let display_img = if let Some((x_pct, y_pct, w_pct, h_pct)) = crop_region {
                let (img_w, img_h) = (img.width(), img.height());
                let crop_x = (img_w * x_pct / 100) as u32;
                let crop_y = (img_h * y_pct / 100) as u32;
                let crop_w = (img_w * w_pct / 100).max(1) as u32;
                let crop_h = (img_h * h_pct / 100).max(1) as u32;
                img.crop_imm(crop_x, crop_y, crop_w, crop_h)
            } else {
                img.clone()
            };

            result_dims = Some((display_img.width(), display_img.height()));

            // Let ratatui-image handle the scaling to terminal size
            self.image_state = Some(picker.new_resize_protocol(display_img));
        }

        self.native_zoom = zoom;
        self.native_pan = pan;
        result_dims
    }
}

/// Compute perception hash for an image
fn compute_phash(path: &PathBuf) -> Option<ImageHash> {
    let img = image::open(path).ok()?;
    let hasher = HasherConfig::new().to_hasher();
    Some(hasher.hash_image(&img))
}

/// Group images by perceptual similarity
fn group_by_phash(paths: &[PathBuf], threshold: u32) -> Vec<Vec<PathBuf>> {
    let hashes: Vec<(PathBuf, ImageHash)> = paths
        .par_iter()
        .filter_map(|p| compute_phash(p).map(|h| (p.clone(), h)))
        .collect();

    let mut groups: Vec<Vec<PathBuf>> = Vec::new();
    let mut used: Vec<bool> = vec![false; hashes.len()];

    for i in 0..hashes.len() {
        if used[i] {
            continue;
        }

        let mut group = vec![hashes[i].0.clone()];
        used[i] = true;

        for j in (i + 1)..hashes.len() {
            if used[j] {
                continue;
            }

            let dist = hashes[i].1.dist(&hashes[j].1);
            if dist <= threshold {
                group.push(hashes[j].0.clone());
                used[j] = true;
            }
        }

        groups.push(group);
    }

    // Sort groups by size (largest first)
    groups.sort_by(|a, b| b.len().cmp(&a.len()));
    groups
}

/// Run batch capture mode with SQLite database and tech fingerprinting
fn run_batch_urls(urls: Vec<String>, output_dir: &PathBuf, db_path: &PathBuf, threads: usize) -> Result<()> {
    println!("lazywitness batch mode");
    println!("  URLs: {}", urls.len());
    println!("  Output: {}", output_dir.display());
    println!("  Database: {}", db_path.display());
    println!("  Threads: {}", threads);
    println!();

    // Create output directory if needed
    fs::create_dir_all(output_dir)?;

    // Initialize database
    let conn = init_database(db_path)?;
    let db = Arc::new(Mutex::new(conn));

    // Configure thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .ok();

    let resolution = (1920, 1080);
    let results = Arc::new(Mutex::new(Vec::new()));
    let total = urls.len();

    // Parallel capture with metadata collection
    urls.par_iter().enumerate().for_each(|(i, url)| {
        print!("[{}/{}] {} ... ", i + 1, total, url);
        std::io::Write::flush(&mut std::io::stdout()).ok();

        if let Some(result) = batch_capture_with_metadata(url, output_dir, resolution) {
            // Show detected technologies
            let tech_str = if result.technologies.is_empty() {
                String::new()
            } else {
                format!(" [{}]", result.technologies.join(", "))
            };
            println!("OK{}", tech_str);

            // Compute phash
            let phash = compute_phash(&PathBuf::from(&result.screenshot_path))
                .map(|h| h.to_base64());

            // Save to database
            if let Ok(db_lock) = db.lock() {
                save_to_database(&db_lock, &result, phash.as_deref()).ok();
            }

            results.lock().unwrap().push(result);
        }
    });

    let captured_results = results.lock().unwrap().clone();
    let captured_paths: Vec<PathBuf> = captured_results.iter()
        .map(|r| PathBuf::from(&r.screenshot_path))
        .collect();

    println!();
    println!("Captured: {}/{}", captured_paths.len(), total);

    // Technology summary
    let mut tech_counts: HashMap<String, usize> = HashMap::new();
    for result in &captured_results {
        for tech in &result.technologies {
            *tech_counts.entry(tech.clone()).or_insert(0) += 1;
        }
    }
    if !tech_counts.is_empty() {
        println!();
        println!("Technologies detected:");
        let mut sorted: Vec<_> = tech_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (tech, count) in sorted.iter().take(10) {
            println!("  {:20} {}", tech, count);
        }
    }

    // Compute perception hashes and group similar
    if captured_paths.len() > 1 {
        println!();
        println!("Computing perception hashes...");
        let groups = group_by_phash(&captured_paths, 10);

        let unique = groups.iter().filter(|g| g.len() == 1).count();
        let grouped = groups.iter().filter(|g| g.len() > 1).count();

        if grouped > 0 {
            println!();
            println!("Similar groups (threshold=10):");
            for (i, group) in groups.iter().enumerate() {
                if group.len() > 1 {
                    println!("  Group {} ({} images):", i + 1, group.len());
                    for path in group {
                        println!("    - {}", path.file_name().unwrap_or_default().to_string_lossy());
                    }
                }
            }
        }

        println!();
        println!("Summary: {} unique, {} groups with duplicates", unique, grouped);
    }

    println!();
    println!("Done! Run 'lazywitness {}' to browse.", output_dir.display());
    println!("Database: {}", db_path.display());

    Ok(())
}

/// Batch capture with full metadata collection
fn batch_capture_with_metadata(
    url: &str,
    output_dir: &PathBuf,
    resolution: (u32, u32),
) -> Option<CaptureResult> {
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

    let output_path = output_dir.join(format!("{}_{}.png", sanitized, timestamp));

    // Ensure URL has a scheme
    let full_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };

    // Capture screenshot and collect metadata
    match capture_with_metadata(&full_url, &output_path, resolution) {
        Ok((headers, html, status_code, final_url)) => {
            // Detect technologies
            let technologies = detect_technologies(&headers, &html);

            // Extract title
            let title = extract_title(&html);

            // Save readable content
            let txt_path = output_path.with_extension("txt");
            if let Ok(mut parser) = Readability::new(&html, None) {
                if let Some(article) = parser.parse() {
                    if let Some(text) = article.text_content {
                        fs::write(&txt_path, &text).ok();
                    }
                }
            }

            Some(CaptureResult {
                url: url.to_string(),
                final_url,
                title,
                status_code,
                headers,
                technologies,
                screenshot_path: output_path.to_string_lossy().to_string(),
                timestamp,
            })
        }
        Err(e) => {
            eprintln!("FAIL: {}", e);
            None
        }
    }
}

/// Capture screenshot and return metadata (headers, html, status_code, final_url)
fn capture_with_metadata(
    url: &str,
    output_path: &PathBuf,
    resolution: (u32, u32),
) -> Result<(HashMap<String, String>, String, u16, String)> {
    use std::ffi::OsStr;

    let chrome_path = App::find_chrome()
        .ok_or_else(|| color_eyre::eyre::eyre!("Chrome/Chromium not found"))?;

    let (width, height) = resolution;

    let stealth_args: Vec<&OsStr> = vec![
        OsStr::new("--disable-blink-features=AutomationControlled"),
        OsStr::new("--disable-features=IsolateOrigins,site-per-process"),
        OsStr::new("--disable-site-isolation-trials"),
        OsStr::new("--disable-web-security"),
        OsStr::new("--disable-features=BlockInsecurePrivateNetworkRequests"),
        OsStr::new("--ignore-certificate-errors"),
        OsStr::new("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    ];

    let options = LaunchOptions::default_builder()
        .path(Some(chrome_path))
        .headless(true)
        .window_size(Some((width, height)))
        .args(stealth_args)
        .build()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to build launch options: {}", e))?;

    let browser = Browser::new(options)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to launch browser: {}", e))?;

    let tab = browser
        .new_tab()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create tab: {}", e))?;

    // Inject stealth scripts
    let _ = tab.evaluate(
        r#"
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
        window.chrome = { runtime: {} };
        "#,
        false,
    );

    tab.navigate_to(url)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to navigate: {}", e))?;

    tab.wait_until_navigated()
        .map_err(|e| color_eyre::eyre::eyre!("Navigation timeout: {}", e))?;

    std::thread::sleep(Duration::from_millis(1000));

    // Get final URL after redirects
    let final_url = tab.get_url();

    // Get page HTML
    let html = tab.get_content()
        .unwrap_or_default();

    // Capture screenshot
    let png_data = tab
        .capture_screenshot(Page::CaptureScreenshotFormatOption::Png, None, None, true)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to capture screenshot: {}", e))?;

    fs::write(output_path, &png_data)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to save screenshot: {}", e))?;

    // Fetch headers via ureq (Chrome DevTools doesn't expose response headers easily)
    let mut headers = HashMap::new();
    if let Ok(resp) = ureq::get(url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
    {
        for name in resp.headers_names() {
            if let Some(value) = resp.header(&name) {
                headers.insert(name.to_lowercase(), value.to_string());
            }
        }
    }

    // Get status code (approximate - use 200 if we got content)
    let status_code = if !html.is_empty() { 200u16 } else { 0u16 };

    Ok((headers, html, status_code, final_url))
}

fn print_usage() {
    eprintln!("lazywitness - TUI web screenshot browser");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  lazywitness [directory]           Browse screenshots in directory (TUI mode)");
    eprintln!("  lazywitness -f <urls.txt> [opts]  Batch capture URLs from file");
    eprintln!("  lazywitness --nmap <scan.xml>     Capture from nmap XML output");
    eprintln!();
    eprintln!("BATCH OPTIONS:");
    eprintln!("  -f, --file <file>     File containing URLs (one per line)");
    eprintln!("  --nmap <file>         Nmap XML file (extracts http/https services)");
    eprintln!("  -o, --output <dir>    Output directory (default: current dir)");
    eprintln!("  -t, --threads <n>     Number of parallel threads (default: 4)");
    eprintln!("  --db <file>           SQLite database file (default: lazywitness.db)");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  lazywitness                        # Browse current directory");
    eprintln!("  lazywitness ./screenshots          # Browse screenshots folder");
    eprintln!("  lazywitness -f urls.txt            # Capture URLs to current dir");
    eprintln!("  lazywitness --nmap scan.xml -o out # Capture from nmap results");
    eprintln!("  lazywitness -f urls.txt -t 8       # Capture with 8 threads");
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args: Vec<String> = env::args().collect();

    // Parse common batch options
    let output_dir = args.iter()
        .position(|a| a == "-o" || a == "--output")
        .and_then(|p| args.get(p + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap());

    let threads: usize = args.iter()
        .position(|a| a == "-t" || a == "--threads")
        .and_then(|p| args.get(p + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);

    let db_path = args.iter()
        .position(|a| a == "--db")
        .and_then(|p| args.get(p + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| output_dir.join("lazywitness.db"));

    // Check for nmap mode
    if let Some(pos) = args.iter().position(|a| a == "--nmap") {
        let nmap_file = args.get(pos + 1)
            .map(PathBuf::from)
            .ok_or_else(|| color_eyre::eyre::eyre!("Missing nmap file after --nmap"))?;

        let urls = parse_nmap_xml(&nmap_file)?;
        if urls.is_empty() {
            println!("No HTTP/HTTPS services found in nmap file");
            return Ok(());
        }
        println!("Found {} URLs in nmap file", urls.len());
        return run_batch_urls(urls, &output_dir, &db_path, threads);
    }

    // Check for batch mode (-f flag)
    if let Some(pos) = args.iter().position(|a| a == "-f" || a == "--file") {
        let urls_file = args.get(pos + 1)
            .map(PathBuf::from)
            .ok_or_else(|| color_eyre::eyre::eyre!("Missing URL file after -f"))?;

        // Read URLs from file
        let file = fs::File::open(&urls_file)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to open URL file: {}", e))?;
        let reader = BufReader::new(file);
        let urls: Vec<String> = reader
            .lines()
            .filter_map(|l| l.ok())
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        if urls.is_empty() {
            println!("No URLs found in file");
            return Ok(());
        }
        return run_batch_urls(urls, &output_dir, &db_path, threads);
    }

    // Check for help
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        return Ok(());
    }

    // TUI mode - first non-flag argument is directory
    let dir = args.iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
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
        // Force full terminal clear if needed (for proper redraw after refresh/resize)
        if app.needs_full_redraw {
            terminal.clear()?;
            app.needs_full_redraw = false;
        }

        terminal.draw(|frame| ui(frame, app))?;

        let event = event::read()?;

        // Handle resize events
        if let Event::Resize(_, _) = event {
            // Terminal resized - clear all cached state to force re-render
            app.preview_cache = None;
            app.image_state = None;
            app.native_render_size = (0, 0);
            app.needs_full_redraw = true;
            continue;
        }

        if let Event::Key(key) = event {
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

                    // Port scan mode (Ctrl+S for "scan") - must be before 's' pan
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.input_mode = InputMode::ScanInput;
                        app.scan_input.clear();
                        app.status_message = None;
                    }

                    // WASD panning (moves viewport when zoomed in)
                    KeyCode::Char('w') => app.pan_up(),
                    KeyCode::Char('a') => app.pan_left(),
                    KeyCode::Char('s') => app.pan_down(),
                    KeyCode::Char('d') => app.pan_right(),

                    // Zoom: e = in (crop tighter), q = out (show more)
                    KeyCode::Char('e') | KeyCode::Char('+') | KeyCode::Char('=') => app.zoom_in(),
                    KeyCode::Char('q') | KeyCode::Char('-') | KeyCode::Char('_') => app.zoom_out(),
                    KeyCode::Char('F') => {
                        app.reset_view();
                        app.status_message = Some("View reset to 100%".to_string());
                    }
                    KeyCode::Char('f') => {
                        app.toggle_fullscreen();
                        app.needs_full_redraw = true;
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

                    // Toggle render mode: p switches between Native and Chafa
                    KeyCode::Char('p') => {
                        app.toggle_render_mode();
                        app.needs_full_redraw = true;
                        app.status_message = Some(format!("Render: {}", app.render_mode_name()));
                    }

                    // Capture URL (Ctrl+O for "open")
                    KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.input_mode = InputMode::UrlInput;
                        app.url_input.clear();
                        app.status_message = None;
                    }
                    KeyCode::Char('r') => {
                        // Clear all cached state
                        app.preview_cache = None;
                        app.image_state = None;
                        app.loaded_image = None;
                        app.native_image_index = None;
                        app.native_render_size = (0, 0);
                        // Re-detect terminal capabilities
                        app.picker = Picker::from_query_stdio().ok();
                        app.refresh_images()?;
                        // Force full terminal redraw
                        app.needs_full_redraw = true;
                        app.status_message = Some("Refreshed".to_string());
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

                    // Help
                    KeyCode::Char('?') => {
                        app.input_mode = InputMode::Help;
                    }

                    // Filter file list
                    KeyCode::Char('/') => {
                        app.input_mode = InputMode::Filter;
                    }

                    // Delete current screenshot
                    KeyCode::Char('x') | KeyCode::Delete => {
                        if app.selected_image().is_some() {
                            app.input_mode = InputMode::ConfirmDelete;
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
                InputMode::ScanInput => match key.code {
                    KeyCode::Enter => {
                        if !app.scan_input.is_empty() {
                            let host = app.scan_input.clone();
                            app.input_mode = InputMode::Normal;
                            app.scan_host(&host, &mut terminal)?;
                        }
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.scan_input.clear();
                    }
                    KeyCode::Backspace => {
                        app.scan_input.pop();
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.scan_input.clear();
                    }
                    KeyCode::Char(c) => {
                        app.scan_input.push(c);
                    }
                    _ => {}
                },
                InputMode::Help => {
                    // Any key closes help
                    app.input_mode = InputMode::Normal;
                },
                InputMode::ConfirmDelete => match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        app.input_mode = InputMode::Normal;
                        match app.delete_current() {
                            Ok(true) => {
                                app.status_message = Some("Deleted".to_string());
                            }
                            Ok(false) => {
                                app.status_message = Some("Nothing to delete".to_string());
                            }
                            Err(e) => {
                                app.status_message = Some(format!("Delete failed: {}", e));
                            }
                        }
                    }
                    _ => {
                        // Any other key cancels
                        app.input_mode = InputMode::Normal;
                    }
                },
                InputMode::Filter => match key.code {
                    KeyCode::Enter => {
                        app.input_mode = InputMode::Normal;
                        app.apply_filter();
                        let count = app.cached_filter_set.len();
                        if !app.filter_input.is_empty() {
                            app.status_message = Some(format!("Filter: {} ({} matches)", app.filter_input, count));
                        }
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.clear_filter();
                        app.status_message = None;
                    }
                    KeyCode::Backspace => {
                        app.filter_input.pop();
                        app.apply_filter();
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.clear_filter();
                    }
                    KeyCode::Char(c) => {
                        app.filter_input.push(c);
                        app.apply_filter();
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

    // Render input popups
    match app.input_mode {
        InputMode::UrlInput => render_url_input(frame, app),
        InputMode::ScanInput => render_scan_input(frame, app),
        InputMode::Help => render_help(frame),
        InputMode::ConfirmDelete => render_confirm_delete(frame, app),
        InputMode::Filter => render_filter_input(frame, app),
        InputMode::Normal => {}
    }
}

fn format_age(path: &PathBuf) -> String {
    let Ok(meta) = path.metadata() else {
        return String::new();
    };
    let Ok(modified) = meta.modified() else {
        return String::new();
    };
    let Ok(elapsed) = SystemTime::now().duration_since(modified) else {
        return String::new();
    };

    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

fn render_file_list(frame: &mut Frame, app: &mut App, area: Rect) {
    use ratatui::widgets::BorderType;

    // Reserve space for age indicator (e.g., " 2h")
    let age_width = 4;
    let max_name_len = area.width.saturating_sub(5 + age_width) as usize;

    // Use cached filter set (O(1) lookup instead of O(n))
    let has_filter = !app.filter_input.is_empty();

    let items: Vec<ListItem> = app
        .images
        .iter()
        .enumerate()
        .map(|(idx, path)| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("???");

            // Use cached file age (no syscall)
            let age = app.cached_file_ages.get(idx).map(|s| s.as_str()).unwrap_or("");

            // Truncate name with ellipsis if too long
            let display_name = if name.len() > max_name_len && max_name_len > 3 {
                format!("{}...", &name[..max_name_len - 3])
            } else {
                name.to_string()
            };

            // Dim non-matching items when filter is active (O(1) HashSet lookup)
            let matches_filter = !has_filter || app.cached_filter_set.contains(&idx);
            let name_style = if matches_filter {
                Style::default().fg(theme::FG_DIM)
            } else {
                Style::default().fg(theme::SURFACE0)
            };
            let age_style = if matches_filter {
                Style::default().fg(theme::FG_DIM).add_modifier(Modifier::DIM)
            } else {
                Style::default().fg(theme::SURFACE0)
            };

            // Create line with name and right-aligned age
            let padding = max_name_len.saturating_sub(display_name.len());
            let line = Line::from(vec![
                Span::styled(display_name, name_style),
                Span::raw(" ".repeat(padding)),
                Span::styled(format!("{:>3}", age), age_style),
            ]);

            ListItem::new(line)
        })
        .collect();

    let title = if has_filter {
        format!(" Screenshots ({}/{}) ", app.cached_filter_set.len(), app.images.len())
    } else {
        " Screenshots ".to_string()
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(title)
                .title_style(Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD))
                .border_style(Style::default().fg(theme::BORDER)),
        )
        .highlight_style(
            Style::default()
                .bg(theme::SELECTION_BG)
                .fg(theme::SELECTION_FG)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" > ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn render_preview(frame: &mut Frame, app: &mut App, area: Rect) {
    use ratatui::widgets::BorderType;

    let inner_width = area.width.saturating_sub(2);
    let inner_height = area.height.saturating_sub(2);

    // Build title - just show filename and zoom if zoomed
    let title = match app.selected_image() {
        Some(path) => {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("???");
            if app.zoom_percent > 100 {
                format!(" {} ({}%) ", name, app.zoom_percent)
            } else {
                format!(" {} ", name)
            }
        }
        None => " No image ".to_string(),
    };

    // Compact keybindings
    let help = keybindings_line(&[
        ("j/k", "nav"),
        ("^o", "capture"),
        ("^s", "scan"),
        ("p", "mode"),
        ("f", "full"),
        ("?", "help"),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(title)
        .title_style(Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD))
        .title_bottom(help)
        .border_style(Style::default().fg(theme::BORDER_FOCUSED));

    // Render block first
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    // Guard against rendering in too-small areas (prevents ratatui-image panics)
    if inner_area.width < 2 || inner_area.height < 2 {
        return;
    }

    // Render image based on mode
    match app.render_mode {
        RenderMode::Native => {
            // Invalidate state if render area size, zoom, or pan changed
            let current_size = (inner_area.width, inner_area.height);
            let current_pan = (app.pan_x, app.pan_y);
            if app.native_render_size != current_size
                || app.native_zoom != app.zoom_percent
                || app.native_pan != current_pan
            {
                app.image_state = None;
                app.native_render_size = current_size;
            }

            // Load image if needed
            app.load_native_image();
            if let Some(dims) = app.prepare_image_protocol(inner_area.width, inner_area.height) {
                app.native_img_dims = Some(dims);
            }

            // Clear the area first to prevent artifacts on resize
            frame.render_widget(Clear, inner_area);

            if let Some(ref mut state) = app.image_state {
                // Use Scale to fill the terminal area (ratatui-image handles aspect ratio)
                let image_widget = StatefulImage::new().resize(Resize::Scale(Some(FilterType::Lanczos3)));
                frame.render_stateful_widget(image_widget, inner_area, state);
            } else {
                // Fallback if image failed to load
                let text = Text::raw("Failed to load image");
                frame.render_widget(Paragraph::new(text), inner_area);
            }
        }
        RenderMode::Chafa => {
            let preview_text = app.render_chafa(inner_width, inner_height);
            frame.render_widget(Paragraph::new(preview_text), inner_area);
        }
    }
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
    use ratatui::widgets::BorderType;

    let content = app.get_text_content().unwrap_or_default();

    let title = " Content ";

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(title)
        .title_style(Style::default().fg(theme::TEAL).add_modifier(Modifier::BOLD))
        .border_style(Style::default().fg(theme::BORDER));

    let paragraph = Paragraph::new(content)
        .block(block)
        .style(Style::default().fg(theme::FG))
        .wrap(Wrap { trim: false })
        .scroll((app.text_scroll, 0));

    frame.render_widget(paragraph, area);
}

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![];

    // Tool name
    spans.push(Span::styled(
        " lazywitness ",
        Style::default().bg(theme::MAUVE).fg(theme::BG).add_modifier(Modifier::BOLD),
    ));

    // Image position
    if !app.images.is_empty() {
        let pos = app.list_state.selected().map(|i| i + 1).unwrap_or(0);
        spans.push(Span::styled(
            format!(" {}/{} ", pos, app.images.len()),
            Style::default().fg(theme::FG_DIM),
        ));
    }

    // Mode indicator
    let mode_str = match app.render_mode {
        RenderMode::Native => "Native",
        RenderMode::Chafa => {
            let (_, name) = app.current_density();
            name
        }
    };
    spans.push(Span::styled(
        format!("[{}]", mode_str),
        Style::default().fg(theme::TEAL),
    ));

    // Resolution
    let (w, h, _) = app.current_resolution();
    spans.push(Span::styled(
        format!(" {}x{}", w, h),
        Style::default().fg(theme::FG_DIM),
    ));

    // Spacer
    spans.push(Span::raw("  "));

    // Status message (if any)
    if let Some(msg) = &app.status_message {
        spans.push(Span::styled(
            msg.clone(),
            Style::default().fg(theme::PEACH),
        ));
    }

    let status = Paragraph::new(Line::from(spans))
        .style(Style::default().bg(theme::BG));

    frame.render_widget(status, area);
}

fn render_url_input(frame: &mut Frame, app: &App) {
    use ratatui::widgets::BorderType;

    let area = frame.area();

    // Center popup
    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 3;
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind popup
    frame.render_widget(Clear, popup_area);

    let (w, h, _) = app.current_resolution();
    let input = Paragraph::new(app.url_input.as_str())
        .style(Style::default().fg(theme::FG))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme::MAUVE))
                .title(format!(" Capture URL ({}x{}) ", w, h))
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

fn render_scan_input(frame: &mut Frame, app: &App) {
    use ratatui::widgets::BorderType;

    let area = frame.area();

    // Center popup
    let popup_width = 50.min(area.width.saturating_sub(4));
    let popup_height = 3;
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind popup
    frame.render_widget(Clear, popup_area);

    // Show placeholder if empty
    let display_text = if app.scan_input.is_empty() {
        Span::styled("192.168.1.0/24", Style::default().fg(theme::FG_DIM))
    } else {
        Span::styled(app.scan_input.as_str(), Style::default().fg(theme::FG))
    };

    let input = Paragraph::new(display_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme::TEAL))
                .title(" Scan Host/CIDR ")
                .title_style(Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD)),
        );

    frame.render_widget(input, popup_area);

    // Show cursor
    let cursor_x = popup_area.x + 1 + app.scan_input.len() as u16;
    let cursor_y = popup_area.y + 1;
    if cursor_x < popup_area.x + popup_area.width - 1 {
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

fn render_help(frame: &mut Frame) {
    use ratatui::widgets::BorderType;

    let area = frame.area();

    // Center popup
    let popup_width = 45.min(area.width.saturating_sub(4));
    let popup_height = 20.min(area.height.saturating_sub(4));
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind popup
    frame.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(vec![
            Span::styled("Navigation", Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("  j/k or ↑/↓    Move selection"),
        Line::from("  Home/End      Jump to first/last"),
        Line::from(""),
        Line::from(vec![
            Span::styled("View", Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("  e/q or +/-    Zoom in/out"),
        Line::from("  w/a/s/d       Pan when zoomed"),
        Line::from("  F             Reset view to 100%"),
        Line::from("  f             Toggle fullscreen"),
        Line::from("  p             Toggle Native/Chafa"),
        Line::from("  [/]           Chafa density (Chafa mode only)"),
        Line::from("  Tab           Toggle file list"),
        Line::from("  v             Toggle text pane"),
        Line::from("  /             Filter files"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Actions", Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("  Ctrl+O        Capture URL"),
        Line::from("  Ctrl+S        Scan host/CIDR"),
        Line::from("  x / Del       Delete screenshot"),
        Line::from("  t             Cycle resolution"),
        Line::from("  r             Refresh"),
        Line::from("  Esc           Quit"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Press any key to close", Style::default().fg(theme::FG_DIM)),
        ]),
    ];

    let help = Paragraph::new(help_text)
        .style(Style::default().fg(theme::FG))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme::MAUVE))
                .title(" Help ")
                .title_style(Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD)),
        );

    frame.render_widget(help, popup_area);
}

fn render_confirm_delete(frame: &mut Frame, app: &App) {
    use ratatui::widgets::BorderType;

    let area = frame.area();

    // Get filename for display
    let filename = app.selected_image()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("???");

    // Truncate filename if too long
    let display_name = if filename.len() > 30 {
        format!("{}...", &filename[..27])
    } else {
        filename.to_string()
    };

    // Center popup
    let popup_width = 40.min(area.width.saturating_sub(4));
    let popup_height = 5;
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind popup
    frame.render_widget(Clear, popup_area);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Delete "),
            Span::styled(&display_name, Style::default().fg(theme::PEACH)),
            Span::raw("?"),
        ]),
        Line::from(vec![
            Span::styled("  y", Style::default().fg(theme::TEAL).add_modifier(Modifier::BOLD)),
            Span::raw(" = yes, "),
            Span::styled("any other key", Style::default().fg(theme::FG_DIM)),
            Span::raw(" = cancel"),
        ]),
    ];

    let confirm = Paragraph::new(text)
        .style(Style::default().fg(theme::FG))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme::PEACH))
                .title(" Confirm Delete ")
                .title_style(Style::default().fg(theme::PEACH).add_modifier(Modifier::BOLD)),
        );

    frame.render_widget(confirm, popup_area);
}

fn render_filter_input(frame: &mut Frame, app: &App) {
    use ratatui::widgets::BorderType;

    let area = frame.area();

    // Center popup
    let popup_width = 50.min(area.width.saturating_sub(4));
    let popup_height = 3;
    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind popup
    frame.render_widget(Clear, popup_area);

    let match_count = app.cached_filter_set.len();
    let title = format!(" Filter ({} matches) ", match_count);

    let input = Paragraph::new(app.filter_input.as_str())
        .style(Style::default().fg(theme::FG))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme::LAVENDER))
                .title(title)
                .title_style(Style::default().fg(theme::LAVENDER).add_modifier(Modifier::BOLD)),
        );

    frame.render_widget(input, popup_area);

    // Show cursor
    let cursor_x = popup_area.x + 1 + app.filter_input.len() as u16;
    let cursor_y = popup_area.y + 1;
    if cursor_x < popup_area.x + popup_area.width - 1 {
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}
