//! Pure renderer: turn an [`NginxVhostSpec`] into the on-disk config string.
//!
//! Deterministic output is important — re-rendering the same spec produces
//! byte-identical bytes, otherwise observe/diff would see spurious drift.

use super::spec::NginxVhostSpec;
use std::fmt::Write as _;

pub const HEADER: &str = "# Managed by iac. Do not edit by hand.\n";

pub fn render(spec: &NginxVhostSpec) -> String {
    let mut out = String::new();
    out.push_str(HEADER);

    let listen = spec.effective_listen();
    let names = spec.server_names.join(" ");

    let tls = spec.tls.as_ref();
    let port_80 = listen.contains(&80);
    let port_443 = listen.contains(&443);
    let render_redirect = tls.is_some_and(|t| t.redirect_http) && port_80 && port_443;

    if render_redirect {
        // Standalone 80 → 443 redirect block. The main block below handles 443.
        out.push_str("server {\n");
        out.push_str("    listen 80;\n");
        out.push_str("    listen [::]:80;\n");
        let _ = writeln!(out, "    server_name {names};");
        out.push_str("    return 301 https://$host$request_uri;\n");
        out.push_str("}\n");
    }

    // Main block: TLS if configured (port 443 only), otherwise the listen list as-is.
    out.push_str("server {\n");
    let main_ports: Vec<u16> = if tls.is_some() {
        // When TLS is on, the main block handles 443 and the redirect block
        // (if any) handled 80. Any other ports the user listed remain on the
        // main block but won't have ssl on them.
        listen.iter().copied().filter(|p| !render_redirect || *p != 80).collect()
    } else {
        listen.clone()
    };
    for port in &main_ports {
        if tls.is_some() && *port == 443 {
            let _ = writeln!(out, "    listen {port} ssl;");
            let _ = writeln!(out, "    listen [::]:{port} ssl;");
        } else {
            let _ = writeln!(out, "    listen {port};");
            let _ = writeln!(out, "    listen [::]:{port};");
        }
    }
    let _ = writeln!(out, "    server_name {names};");
    if let Some(t) = tls {
        let _ = writeln!(out, "    ssl_certificate {};", t.certificate.display());
        let _ = writeln!(out, "    ssl_certificate_key {};", t.key.display());
        out.push_str("    ssl_protocols TLSv1.2 TLSv1.3;\n");
        out.push_str("    ssl_prefer_server_ciphers on;\n");
    }
    if let Some(s) = &spec.client_max_body_size {
        let _ = writeln!(out, "    client_max_body_size {s};");
    }
    out.push_str("    location / {\n");
    if let Some(upstream) = &spec.upstream {
        let _ = writeln!(out, "        proxy_pass {upstream};");
    }
    out.push_str("        proxy_http_version 1.1;\n");
    out.push_str("        proxy_set_header Host $host;\n");
    out.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
    out.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
    out.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
    if let Some(t) = &spec.proxy_read_timeout {
        let _ = writeln!(out, "        proxy_read_timeout {t};");
    }
    out.push_str("    }\n");

    // Phase 7aw: render any operator-declared extra location blocks AFTER
    // the default `/` block. Order matches the spec's declared order so
    // re-rendering the same spec is byte-identical (still important for
    // diff stability).
    for loc in &spec.extra_locations {
        let _ = writeln!(out, "    location {} {{", loc.path);
        if let Some(upstream) = &loc.proxy_pass {
            let _ = writeln!(out, "        proxy_pass {upstream};");
            // Same proxy headers as the default block — operators
            // proxying a /metrics endpoint expect the same Host /
            // X-Forwarded-* set.
            out.push_str("        proxy_http_version 1.1;\n");
            out.push_str("        proxy_set_header Host $host;\n");
            out.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
            out.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
            out.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
        }
        if let Some(root) = &loc.root {
            let _ = writeln!(out, "        root {root};");
        }
        out.push_str("    }\n");
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::super::spec::{NginxState, NginxVhostSpec, TlsConfig};
    use super::*;
    use std::path::PathBuf;

    fn base() -> NginxVhostSpec {
        NginxVhostSpec {
            config_path: PathBuf::from("/etc/nginx/conf.d/app.conf"),
            state: NginxState::Present,
            server_names: vec!["app.example.com".into()],
            listen: vec![80],
            upstream: Some("http://127.0.0.1:8080".into()),
            client_max_body_size: None,
            proxy_read_timeout: None,
            tls: None,
            extra_locations: vec![],
        }
    }

    #[test]
    fn render_is_deterministic() {
        let s = base();
        assert_eq!(render(&s), render(&s));
    }

    #[test]
    fn renders_minimal_proxy_pass() {
        let out = render(&base());
        let expected = r"# Managed by iac. Do not edit by hand.
server {
    listen 80;
    listen [::]:80;
    server_name app.example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
";
        assert_eq!(out, expected);
    }

    #[test]
    fn includes_optional_directives() {
        let mut s = base();
        s.client_max_body_size = Some("10M".into());
        s.proxy_read_timeout = Some("60s".into());
        s.listen = vec![80, 8080];
        s.server_names = vec!["a.example.com".into(), "b.example.com".into()];
        let out = render(&s);
        assert!(out.contains("client_max_body_size 10M;"));
        assert!(out.contains("proxy_read_timeout 60s;"));
        assert!(out.contains("listen 80;"));
        assert!(out.contains("listen 8080;"));
        assert!(out.contains("server_name a.example.com b.example.com;"));
    }

    #[test]
    fn renders_tls_with_redirect() {
        let mut s = base();
        s.tls = Some(TlsConfig {
            certificate: PathBuf::from("/etc/letsencrypt/live/app/fullchain.pem"),
            key: PathBuf::from("/etc/letsencrypt/live/app/privkey.pem"),
            redirect_http: true,
        });
        // listen contains 80; renderer auto-adds 443.
        let out = render(&s);
        // Two server blocks.
        assert_eq!(out.matches("server {").count(), 2);
        // The 80 block redirects to https.
        assert!(out.contains("return 301 https://$host$request_uri;"));
        // The 443 block has ssl + cert/key.
        assert!(out.contains("listen 443 ssl;"));
        assert!(out.contains("ssl_certificate /etc/letsencrypt/live/app/fullchain.pem;"));
        assert!(out.contains("ssl_certificate_key /etc/letsencrypt/live/app/privkey.pem;"));
        assert!(out.contains("ssl_protocols TLSv1.2 TLSv1.3;"));
        // proxy_pass appears only in the 443 block.
        let proxy_passes: Vec<&str> = out.matches("proxy_pass http://127.0.0.1:8080;").collect();
        assert_eq!(proxy_passes.len(), 1);
    }

    #[test]
    fn renders_tls_without_redirect_when_no_port_80() {
        let mut s = base();
        s.listen = vec![]; // user only wanted https
        s.tls = Some(TlsConfig {
            certificate: PathBuf::from("/etc/cert.pem"),
            key: PathBuf::from("/etc/key.pem"),
            redirect_http: true,
        });
        // effective_listen auto-adds 443 since TLS is configured.
        let out = render(&s);
        assert_eq!(out.matches("server {").count(), 1);
        assert!(!out.contains("return 301"));
        assert!(out.contains("listen 443 ssl;"));
    }

    #[test]
    fn renders_extra_location_with_proxy_pass() {
        let mut s = base();
        s.extra_locations = vec![super::super::spec::ExtraLocation {
            path: "/metrics".into(),
            proxy_pass: Some("http://127.0.0.1:9090".into()),
            root: None,
        }];
        let out = render(&s);
        // Default `/` block still present.
        assert!(out.contains("location / {"));
        assert!(out.contains("proxy_pass http://127.0.0.1:8080;"));
        // Extra `/metrics` block follows it.
        assert!(out.contains("location /metrics {"));
        assert!(out.contains("proxy_pass http://127.0.0.1:9090;"));
        // Default block must come before extra block (specificity ordering
        // matters less for nginx but byte-stable rendering matters for diff).
        let default_idx = out.find("location / {").unwrap();
        let extra_idx = out.find("location /metrics {").unwrap();
        assert!(default_idx < extra_idx);
    }

    #[test]
    fn renders_extra_location_with_root() {
        let mut s = base();
        s.extra_locations = vec![super::super::spec::ExtraLocation {
            path: "/static/".into(),
            proxy_pass: None,
            root: Some("/var/www/app".into()),
        }];
        let out = render(&s);
        assert!(out.contains("location /static/ {"));
        assert!(out.contains("root /var/www/app;"));
        // Static block must NOT carry proxy_* directives — they apply only
        // to the proxy_pass form.
        let static_block_start = out.find("location /static/ {").unwrap();
        let next_close = out[static_block_start..].find("}").unwrap();
        let static_block = &out[static_block_start..static_block_start + next_close];
        assert!(!static_block.contains("proxy_pass"));
        assert!(!static_block.contains("X-Real-IP"));
    }

    #[test]
    fn renders_multiple_extra_locations_in_declared_order() {
        let mut s = base();
        s.extra_locations = vec![
            super::super::spec::ExtraLocation {
                path: "/static/".into(),
                proxy_pass: None,
                root: Some("/var/www/static".into()),
            },
            super::super::spec::ExtraLocation {
                path: "= /healthz".into(),
                proxy_pass: Some("http://127.0.0.1:8080".into()),
                root: None,
            },
            super::super::spec::ExtraLocation {
                path: "/metrics".into(),
                proxy_pass: Some("http://127.0.0.1:9090".into()),
                root: None,
            },
        ];
        let out = render(&s);
        let static_idx = out.find("location /static/ {").unwrap();
        let healthz_idx = out.find("location = /healthz {").unwrap();
        let metrics_idx = out.find("location /metrics {").unwrap();
        assert!(static_idx < healthz_idx);
        assert!(healthz_idx < metrics_idx);
    }

    #[test]
    fn renders_tls_with_redirect_off() {
        let mut s = base();
        s.tls = Some(TlsConfig {
            certificate: PathBuf::from("/etc/cert.pem"),
            key: PathBuf::from("/etc/key.pem"),
            redirect_http: false,
        });
        // listen has 80 + (auto-added) 443. redirect_http is off, so port 80
        // gets a plain server block (still in main block) — but main block
        // would have both 80 plain and 443 ssl. That's an unusual config,
        // but valid: the renderer should produce one server block listening
        // on both, with TLS settings applying only to 443.
        let out = render(&s);
        assert_eq!(out.matches("server {").count(), 1);
        assert!(out.contains("listen 80;"));
        assert!(out.contains("listen 443 ssl;"));
        assert!(!out.contains("return 301"));
    }
}
