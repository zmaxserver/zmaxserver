//! L3: gercek istemci IP cozumlemesi (H1 ve ek dinleyici icin tek islev).

use crate::modules_runtime::RealIpPolicy;
use std::net::IpAddr;

/// `mod_realip` politikasi etkinse sahteciliğe dayanıklı gerçek IP'yi, değilse soket IP'sini döndürür.
pub fn resolve_real_ip(
    policy: &RealIpPolicy,
    peer_ip: IpAddr,
    headers: &[(String, String)],
) -> IpAddr {
    if policy.enabled {
        zmax_httpparser::resolve_real_ip(
            peer_ip,
            headers,
            &policy.header_name,
            &policy.trusted_proxies,
            policy.recursive,
        )
    } else {
        peer_ip
    }
}
