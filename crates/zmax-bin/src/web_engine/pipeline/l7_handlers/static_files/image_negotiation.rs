//! L7 — WebP/AVIF görsel içerik müzakeresi.

use std::path::{Path, PathBuf};

pub(crate) fn accept_supports_media_type(accept_lower: &str, media_type: &str) -> bool {
    accept_lower.split(',').any(|item| {
        let mut parts = item.split(';');
        let mime = parts.next().unwrap_or("").trim();
        if mime != media_type {
            return false;
        }
        for param in parts {
            let Some((key, val)) = param.split_once('=') else {
                continue;
            };
            if key.trim() != "q" {
                continue;
            }
            if let Ok(q) = val.trim().parse::<f32>() {
                if q.is_finite() && q <= 0.0 {
                    return false;
                }
            }
        }
        true
    })
}

pub(crate) fn find_safe_negotiated_variant(
    orig_path: &Path,
    orig_parent: &Path,
    canon_parent: &Path,
    target_ext: &str,
) -> Option<PathBuf> {
    let file_name = orig_path.file_name()?;
    let stem = orig_path.file_stem()?;

    let mut append_name = file_name.to_os_string();
    append_name.push(".");
    append_name.push(target_ext);

    let mut replace_name = stem.to_os_string();
    replace_name.push(".");
    replace_name.push(target_ext);

    let candidates = [
        orig_parent.join(append_name),
        orig_parent.join(replace_name),
    ];

    for cand in candidates {
        let Ok(canon_cand) = std::fs::canonicalize(&cand) else {
            continue;
        };
        let is_regular_file = std::fs::metadata(&canon_cand).is_ok_and(|m| m.is_file());
        if is_regular_file && canon_cand.parent() == Some(canon_parent) {
            return Some(canon_cand);
        }
    }
    None
}

/// Tarayıcının `Accept` başlığına göre `.jpg`, `.jpeg` ve `.png` dosyaları için güvenli biçimde `.avif` veya `.webp` varyantını seçer.
pub(crate) fn select_negotiated_image_path(
    orig_path: &Path,
    accept_header: Option<&str>,
    allow_avif: bool,
    allow_webp: bool,
) -> Option<(PathBuf, &'static str)> {
    if !allow_avif && !allow_webp {
        return None;
    }
    let ext = orig_path.extension().and_then(|e| e.to_str())?;
    if !(ext.eq_ignore_ascii_case("jpg")
        || ext.eq_ignore_ascii_case("jpeg")
        || ext.eq_ignore_ascii_case("png"))
    {
        return None;
    }

    let accept = accept_header?.trim();
    if accept.is_empty() {
        return None;
    }
    let accept_lower = accept.to_ascii_lowercase();

    let orig_parent = orig_path.parent()?;
    let parent_for_canon = if orig_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        orig_parent
    };
    let canon_parent = std::fs::canonicalize(parent_for_canon).ok()?;

    if allow_avif && accept_supports_media_type(&accept_lower, "image/avif") {
        if let Some(canon_avif) =
            find_safe_negotiated_variant(orig_path, orig_parent, &canon_parent, "avif")
        {
            return Some((canon_avif, "image/avif"));
        }
    }

    if allow_webp && accept_supports_media_type(&accept_lower, "image/webp") {
        if let Some(canon_webp) =
            find_safe_negotiated_variant(orig_path, orig_parent, &canon_parent, "webp")
        {
            return Some((canon_webp, "image/webp"));
        }
    }

    None
}
