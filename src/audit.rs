use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, SET_COOKIE};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    level: &'static str,
    message: String,
}

pub fn audit_target(host: &str, timeout: Duration, insecure_tls: bool) -> Result<(), String> {
    let host = host.trim().trim_end_matches('/');
    if host.is_empty() || host.contains('/') || host.contains('@') {
        return Err("service audit requires one hostname or IP address, not a CIDR or URL".into());
    }

    let client = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(insecure_tls)
        .build()
        .map_err(|e| format!("could not create HTTP client: {e}"))?;

    println!("\n=== HTTP Service Security Audit: {host} ===");
    for scheme in ["http", "https"] {
        let url = format!("{scheme}://{host}/");
        println!("\n[{scheme.to_uppercase()}] {url}");
        match client.get(&url).send() {
            Ok(response) => print_response_audit(response, scheme),
            Err(error) => println!("  Could not retrieve service: {error}"),
        }
    }

    if insecure_tls {
        println!("\nNote: TLS certificate verification was explicitly disabled for this audit.");
    }
    Ok(())
}

fn print_response_audit(response: Response, scheme: &str) {
    println!("  HTTP status: {}", response.status());
    let findings = analyze_headers(response.headers(), scheme);
    if findings.is_empty() {
        println!("  No issues detected by the configured checks.");
    } else {
        for finding in findings {
            println!("  [{}] {}", finding.level, finding.message);
        }
    }
}

fn analyze_headers(headers: &HeaderMap, scheme: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !headers.contains_key("x-content-type-options") {
        findings.push(Finding {
            level: "LOW",
            message: "X-Content-Type-Options is not set; consider 'nosniff'.".into(),
        });
    } else if headers.get("x-content-type-options").and_then(|v| v.to_str().ok())
        .map(|v| !v.eq_ignore_ascii_case("nosniff")).unwrap_or(true)
    {
        findings.push(Finding {
            level: "INFO",
            message: "X-Content-Type-Options is present but is not 'nosniff'.".into(),
        });
    }

    let has_frame_protection = headers.contains_key("x-frame-options")
        || headers.get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("frame-ancestors"))
            .unwrap_or(false);
    if !has_frame_protection {
        findings.push(Finding {
            level: "LOW",
            message: "No X-Frame-Options or CSP frame-ancestors directive was observed.".into(),
        });
    }

    if let Some(csp) = headers.get("content-security-policy").and_then(|v| v.to_str().ok()) {
        if !csp.to_ascii_lowercase().contains("default-src")
            && !csp.to_ascii_lowercase().contains("script-src")
        {
            findings.push(Finding {
                level: "INFO",
                message: "Content-Security-Policy is present, but no default-src or script-src directive was observed; review policy completeness.".into(),
            });
        }
    } else {
        findings.push(Finding {
            level: "INFO",
            message: "Content-Security-Policy was not observed; assess whether a policy is appropriate for this application.".into(),
        });
    }

    if scheme == "https" && !headers.contains_key("strict-transport-security") {
        findings.push(Finding {
            level: "INFO",
            message: "Strict-Transport-Security was not observed on the HTTPS response.".into(),
        });
    }

    for value in headers.get_all(SET_COOKIE).iter() {
        let Ok(cookie) = value.to_str() else { continue };
        let mut parts = cookie.split(';');
        let name = parts.next().unwrap_or("").split('=').next().unwrap_or("").trim();
        let name_lower = name.to_ascii_lowercase();
        let is_session_cookie = ["sid", "session", "auth", "token"]
            .iter().any(|needle| name_lower.contains(needle));
        if !is_session_cookie {
            continue;
        }

        let attributes = parts.map(|part| part.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        let has_secure = attributes.iter().any(|a| a == "secure");
        let has_httponly = attributes.iter().any(|a| a == "httponly");
        let has_samesite = attributes.iter().any(|a| a.starts_with("samesite="));

        if scheme == "https" && !has_secure {
            findings.push(Finding {
                level: "MEDIUM",
                message: format!("Session-like cookie '{name}' lacks the Secure attribute on HTTPS."),
            });
        }
        if !has_httponly {
            findings.push(Finding {
                level: "LOW",
                message: format!("Session-like cookie '{name}' lacks the HttpOnly attribute."),
            });
        }
        if !has_samesite {
            findings.push(Finding {
                level: "INFO",
                message: format!("Session-like cookie '{name}' has no observed SameSite attribute; review CSRF protections."),
            });
        }
        if scheme == "http" && !has_secure {
            findings.push(Finding {
                level: "MEDIUM",
                message: format!("Session-like cookie '{name}' is set over unencrypted HTTP without Secure; if used for authentication, it may be exposed in transit."),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue};

    use super::analyze_headers;

    #[test]
    fn recognizes_frame_ancestors_as_frame_protection() {
        let mut headers = HeaderMap::new();
        headers.insert("content-security-policy", HeaderValue::from_static("frame-ancestors 'self'"));
        assert!(!analyze_headers(&headers, "https").iter()
            .any(|f| f.message.contains("No X-Frame-Options")));
    }

    #[test]
    fn reports_missing_secure_on_https_session_cookie_without_printing_value() {
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", HeaderValue::from_static("SID=secret-value; HttpOnly"));
        let findings = analyze_headers(&headers, "https");
        assert!(findings.iter().any(|f| f.message.contains("lacks the Secure")));
        assert!(findings.iter().all(|f| !f.message.contains("secret-value")));
    }

    #[test]
    fn does_not_flag_secure_cookie_on_https() {
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", HeaderValue::from_static("session_id=abc; Secure; HttpOnly; SameSite=Lax"));
        let findings = analyze_headers(&headers, "https");
        assert!(!findings.iter().any(|f| f.message.contains("lacks the Secure")));
        assert!(!findings.iter().any(|f| f.message.contains("lacks the HttpOnly")));
    }
}
