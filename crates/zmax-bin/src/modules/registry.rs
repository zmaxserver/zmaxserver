//! WebAdmin modül kategori anahtarları.

/// WebAdmin arayüzü için standart modül kategori anahtarını üretir.
pub fn module_category_key(name: &str, raw_category: &str) -> &'static str {
    let lower_name = name.to_ascii_lowercase();
    if lower_name.contains("cache") || lower_name.contains("gzip") || lower_name.contains("brotli") || lower_name.contains("pagespeed") || lower_name.contains("redis") {
        return "perf";
    }
    if lower_name.contains("sec") || lower_name.contains("header") || lower_name.contains("crs") || lower_name.contains("coreruleset") || lower_name.contains("ssl") || lower_name.contains("acme") {
        return "sec";
    }
    if lower_name.contains("fastcgi") || lower_name.contains("quic") || lower_name.contains("http") {
        return "proto";
    }
    if lower_name.contains("proxy") || lower_name.contains("realip") || lower_name.contains("geoip") {
        return "net";
    }
    if lower_name.contains("rewrite") || lower_name.contains("autoindex") {
        return "route";
    }
    let cat = raw_category.to_ascii_lowercase();
    if cat.contains("güven") || cat.contains("guven") || cat.contains("sec") {
        "sec"
    } else if cat.contains("perform") || cat.contains("opt") {
        "perf"
    } else if cat.contains("proto") {
        "proto"
    } else if cat.contains("ağ") || cat.contains("ag") || cat.contains("net") {
        "net"
    } else if cat.contains("yön") || cat.contains("yon") || cat.contains("route") {
        "route"
    } else {
        "core"
    }
}
