"""
IP classification for SSRF protection.

Design decision — two different kinds of "disallowed":

1. ALWAYS blocked, no exception, regardless of any scope rule a user
   configures: loopback, link-local, multicast, unspecified, IETF-reserved,
   and known cloud metadata endpoints. These addresses would target the
   scanning platform itself or its host's cloud control plane — no
   legitimate pentest/bug-bounty/CTF target is ever actually "127.0.0.1"
   or "169.254.169.254" from the platform's point of view, even if a
   DNS record a tester doesn't control points there.

2. RFC1918 private ranges (10/8, 172.16/12, 192.168/16) are NOT
   automatically blocked — internal network pentests are a real,
   legitimate use case where the private range IS the engagement scope,
   and the Lab Environment phase (Juice Shop/DVWA/WebGoat) runs on
   private/loopback-adjacent addresses too. Instead, private ranges are
   only reachable when explicitly covered by a CIDR_INCLUDE scope rule —
   see ScopeEnforcer. A domain that unexpectedly resolves to a private IP
   nobody explicitly scoped in is blocked, which also catches
   DNS-rebinding-style SSRF attempts against the platform's own network.
"""
import ipaddress

# Known cloud-provider instance-metadata endpoints. These sit in the
# link-local range for IPv4 so `is_link_local` already catches
# 169.254.169.254, but they're listed explicitly so the block reason is
# clear in logs/audit trail rather than just "link-local".
_CLOUD_METADATA_IPS = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP / DigitalOcean / Oracle Cloud
        "100.100.100.200",  # Alibaba Cloud
        "fd00:ec2::254",    # AWS IMDSv2, IPv6
    }
)


def classify_always_blocked(ip_str: str) -> str | None:
    """
    Returns a human-readable block reason if this IP must be refused no
    matter what scope rules say, else None. Callers should check this
    BEFORE consulting any CIDR include rule — these categories are never
    overridable by scope configuration.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "not a valid IP address"

    if ip_str in _CLOUD_METADATA_IPS:
        return "cloud instance-metadata endpoint (always blocked, not scope-overridable)"
    if ip.is_loopback:
        return "loopback address — would target the scanning platform itself"
    if ip.is_link_local:
        return "link-local address (this range includes cloud metadata services)"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address (0.0.0.0 / ::)"
    if ip.is_reserved:
        return "IETF-reserved address range"
    return None


def is_private_range(ip_str: str) -> bool:
    """
    True for RFC1918 / unique-local ranges. Note: Python's `is_private`
    also returns True for loopback/link-local — callers must run
    classify_always_blocked() first, since those are handled (and
    rejected) unconditionally there.
    """
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
