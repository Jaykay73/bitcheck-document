import ipaddress
from urllib.parse import urlparse

from app.schemas.document_verification import SourceURLAnalysis

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "claim",
    "reward",
    "payment",
    "grant",
    "free",
    "update",
    "secure",
    "account",
    "bvn",
    "otp",
    "password",
    "wallet",
    "crypto",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "ow.ly",
    "is.gd",
    "buff.ly",
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".work", ".support"}
LOCAL_HOSTS = {"localhost", "0.0.0.0"}


class SourceURLAnalyzer:
    def analyze(self, url: str) -> SourceURLAnalysis:
        flags: list[str] = []
        warnings: list[str] = []
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else None
        domain = (parsed.hostname or "").lower() or None

        valid_url = bool(scheme and domain)
        if not valid_url:
            flags.append("invalid_url_format")
            warnings.append("URL format is invalid or missing a host.")

        uses_https = scheme == "https"
        is_ip = self._is_ip_address(domain)
        private_or_internal = self._is_private_or_internal(domain)
        shortened = domain in SHORTENER_DOMAINS if domain else False
        suspicious_tld = self._has_suspicious_tld(domain)
        punycode = "xn--" in (domain or "")
        excessive_hyphens = (domain or "").count("-") >= 3
        too_many_subdomains = self._too_many_subdomains(domain)
        path_domain_text = f"{domain or ''} {parsed.path.lower()} {parsed.query.lower()}"
        suspicious_keywords = any(keyword in path_domain_text for keyword in SUSPICIOUS_KEYWORDS)

        risk = 0.1 if uses_https and valid_url else 0.25
        if not uses_https:
            flags.append("non_https_url")
            risk += 0.2
        if shortened:
            flags.append("shortened_url")
            risk += 0.4
        if is_ip:
            flags.append("ip_address_host")
            risk += 0.35
        if private_or_internal:
            flags.append("private_or_internal_url")
            risk += 0.6
        if suspicious_keywords:
            flags.append("suspicious_url_keyword")
            risk += 0.2
        if suspicious_tld:
            flags.append("suspicious_tld")
            risk += 0.25
        if punycode:
            flags.append("punycode_domain")
            risk += 0.35
        if excessive_hyphens:
            flags.append("excessive_hyphens")
            risk += 0.2
        if too_many_subdomains:
            flags.append("too_many_subdomains")
            risk += 0.2

        return SourceURLAnalysis(
            checked=True,
            url=url,
            domain=domain,
            scheme=scheme,
            uses_https=uses_https,
            is_shortened_url=shortened,
            is_ip_address=is_ip,
            is_private_or_internal=private_or_internal,
            has_suspicious_keywords=suspicious_keywords,
            suspicious_tld=suspicious_tld,
            punycode_detected=punycode,
            excessive_hyphens=excessive_hyphens,
            too_many_subdomains=too_many_subdomains,
            risk_score=round(min(risk, 1.0), 2),
            flags=flags,
            warnings=warnings,
        )

    def _is_ip_address(self, host: str | None) -> bool:
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    def _is_private_or_internal(self, host: str | None) -> bool:
        if not host:
            return False
        if host in LOCAL_HOSTS or host.endswith(".localhost") or host.endswith(".local"):
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address in ipaddress.ip_network("100.64.0.0/10")
        )

    def _has_suspicious_tld(self, host: str | None) -> bool:
        return any((host or "").endswith(tld) for tld in SUSPICIOUS_TLDS)

    def _too_many_subdomains(self, host: str | None) -> bool:
        if not host or self._is_ip_address(host):
            return False
        return len(host.split(".")) > 4
