use super::{DEFAULT_DURATION_MS, DEFAULT_TOAST_BODY};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ParsedToast {
    pub kind: vapor_forge_features::toast::ToastKind,
    pub style: Option<vapor_forge_features::toast::ToastStyle>,
    pub action: vapor_forge_features::toast::ToastAction,
    pub title: String,
    pub body: String,
    pub duration_ms: u32,
    pub logo: vapor_forge_features::toast::ToastLogo,
}

struct ToastOptions {
    kind: vapor_forge_features::toast::ToastKind,
    style: Option<vapor_forge_features::toast::ToastStyle>,
    title: Option<String>,
    body: Option<String>,
    duration_ms: u32,
    logo: vapor_forge_features::toast::ToastLogo,
    action: vapor_forge_features::toast::ToastAction,
}

pub(crate) fn parse_toast_args(args: &str) -> Result<ParsedToast, String> {
    let tokens = tokenize_toast_args(args)?;
    let mut options = ToastOptions {
        kind: vapor_forge_features::toast::ToastKind::Info,
        style: None,
        title: None,
        body: None,
        duration_ms: DEFAULT_DURATION_MS,
        logo: vapor_forge_features::toast::ToastLogo::Default,
        action: vapor_forge_features::toast::ToastAction::Dismiss,
    };
    let mut body_words = Vec::new();
    let mut index = 0;

    while index < tokens.len() {
        if let Some(parsed_kind) = parse_toast_kind(&tokens[index]) {
            options.kind = parsed_kind;
            index += 1;
            continue;
        }
        if let Some(parsed_style) = parse_toast_style(&tokens[index]) {
            options.style = Some(parsed_style);
            index += 1;
            continue;
        }
        break;
    }

    while index < tokens.len() {
        if token_is_toast_option(&tokens[index]) {
            let (key, value, next_index) = parse_toast_option(&tokens, index)?;
            apply_toast_option(key, value, &mut options)?;
            index = next_index;
        } else {
            body_words.push(tokens[index].as_str());
            index += 1;
        }
    }

    if options.body.is_none() && !body_words.is_empty() {
        options.body = Some(body_words.join(" "));
    }

    Ok(ParsedToast {
        kind: options.kind,
        style: options.style,
        action: options.action,
        title: non_empty(options.title.as_deref().unwrap_or(""), "Vapor Forge").to_owned(),
        body: non_empty(options.body.as_deref().unwrap_or(""), DEFAULT_TOAST_BODY).to_owned(),
        duration_ms: options.duration_ms,
        logo: options.logo,
    })
}

fn token_is_toast_option(token: &str) -> bool {
    token.starts_with("--") || token.contains('=')
}

fn parse_toast_option(tokens: &[String], index: usize) -> Result<(&str, &str, usize), String> {
    let token = tokens[index].as_str();
    if let Some(option) = token.strip_prefix("--") {
        if let Some((key, value)) = option.split_once('=') {
            return Ok((key, value, index + 1));
        }
        let Some(value) = tokens.get(index + 1) else {
            return Err(format!(
                "err missing value for toast option: {}",
                super::command::quote_text(token)
            ));
        };
        return Ok((option, value, index + 2));
    }
    if let Some((key, value)) = token.split_once('=') {
        return Ok((key, value, index + 1));
    }
    Err(format!(
        "err invalid toast option: {}",
        super::command::quote_text(token)
    ))
}

fn apply_toast_option(key: &str, value: &str, options: &mut ToastOptions) -> Result<(), String> {
    match key.trim().to_ascii_lowercase().as_str() {
        "kind" | "type" => {
            options.kind = parse_toast_kind(value).ok_or_else(|| {
                format!(
                    "err invalid toast kind: {}",
                    super::command::quote_text(value)
                )
            })?;
        }
        "style" => {
            options.style = Some(parse_toast_style(value).ok_or_else(|| {
                format!(
                    "err invalid toast style: {}",
                    super::command::quote_text(value)
                )
            })?);
        }
        "title" => options.title = Some(value.to_owned()),
        "body" | "message" | "text" => options.body = Some(value.to_owned()),
        "duration" | "duration_ms" | "ms" => options.duration_ms = parse_duration(value)?,
        "logo" => {
            options.logo = parse_toast_logo(value).ok_or_else(|| {
                format!(
                    "err invalid toast logo: {}",
                    super::command::quote_text(value)
                )
            })?;
        }
        "icon" => options.logo = vapor_forge_features::toast::ToastLogo::Custom(value.to_owned()),
        "steam-url" | "steam_url" => {
            if !value.starts_with("steam://") {
                return Err(format!(
                    "err invalid steam URL: {}",
                    super::command::quote_text(value)
                ));
            }
            options.action =
                vapor_forge_features::toast::ToastAction::OpenSteamUrl(value.to_owned());
        }
        "decky-route" | "decky_route" => {
            if !value.starts_with("/decky/") {
                return Err(format!(
                    "err invalid Decky route: {}",
                    super::command::quote_text(value)
                ));
            }
            options.action =
                vapor_forge_features::toast::ToastAction::OpenDeckyRoute(value.to_owned());
        }
        _ => {
            return Err(format!(
                "err unknown toast option: {}",
                super::command::quote_text(key)
            ));
        }
    }
    Ok(())
}

pub(crate) fn tokenize_toast_args(args: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for ch in args.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(quote_char) = quote {
            if ch == quote_char {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }

    if escaped {
        current.push('\\');
    }
    if quote.is_some() {
        return Err("err unterminated quote in toast command".to_owned());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

pub(crate) fn parse_toast_kind(value: &str) -> Option<vapor_forge_features::toast::ToastKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" | "normal" => Some(vapor_forge_features::toast::ToastKind::Info),
        "warning" | "warn" => Some(vapor_forge_features::toast::ToastKind::Warning),
        "error" | "err" => Some(vapor_forge_features::toast::ToastKind::Error),
        _ => None,
    }
}

fn parse_toast_style(value: &str) -> Option<vapor_forge_features::toast::ToastStyle> {
    match value.trim().to_ascii_lowercase().as_str() {
        "accent" => Some(vapor_forge_features::toast::ToastStyle::Accent),
        "banner" => Some(vapor_forge_features::toast::ToastStyle::Banner),
        _ => None,
    }
}

fn parse_toast_logo(value: &str) -> Option<vapor_forge_features::toast::ToastLogo> {
    match value.trim().to_ascii_lowercase().as_str() {
        "default" => Some(vapor_forge_features::toast::ToastLogo::Default),
        "hidden" => Some(vapor_forge_features::toast::ToastLogo::Hidden),
        _ => None,
    }
}

pub(crate) fn default_toast_style(
    kind: vapor_forge_features::toast::ToastKind,
) -> vapor_forge_features::toast::ToastStyle {
    match kind {
        vapor_forge_features::toast::ToastKind::Info => {
            vapor_forge_features::toast::ToastStyle::Accent
        }
        vapor_forge_features::toast::ToastKind::Warning
        | vapor_forge_features::toast::ToastKind::Error => {
            vapor_forge_features::toast::ToastStyle::Banner
        }
    }
}

pub(crate) fn toast_kind_name(kind: vapor_forge_features::toast::ToastKind) -> &'static str {
    match kind {
        vapor_forge_features::toast::ToastKind::Info => "info",
        vapor_forge_features::toast::ToastKind::Warning => "warning",
        vapor_forge_features::toast::ToastKind::Error => "error",
    }
}

pub(crate) fn toast_style_name(style: vapor_forge_features::toast::ToastStyle) -> &'static str {
    match style {
        vapor_forge_features::toast::ToastStyle::Accent => "accent",
        vapor_forge_features::toast::ToastStyle::Banner => "banner",
    }
}

fn non_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

fn parse_duration(value: &str) -> Result<u32, String> {
    if value.is_empty() {
        return Ok(DEFAULT_DURATION_MS);
    }
    value.parse::<u32>().map_err(|_| {
        format!(
            "err invalid duration_ms: {}",
            super::command::quote_text(value)
        )
    })
}
