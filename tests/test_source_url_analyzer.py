from app.services.source_url_analyzer import SourceURLAnalyzer


def test_https_official_looking_url_returns_low_risk() -> None:
    result = SourceURLAnalyzer().analyze("https://example.edu.ng/certificates/ABC-123")

    assert result.uses_https is True
    assert result.risk_score <= 0.15
    assert result.flags == []


def test_shortened_url_returns_elevated_risk() -> None:
    result = SourceURLAnalyzer().analyze("https://bit.ly/abc123")

    assert result.is_shortened_url is True
    assert result.risk_score >= 0.4
    assert "shortened_url" in result.flags


def test_ip_address_url_returns_elevated_risk() -> None:
    result = SourceURLAnalyzer().analyze("https://8.8.8.8/verify")

    assert result.is_ip_address is True
    assert result.risk_score >= 0.4
    assert "ip_address_host" in result.flags


def test_private_internal_url_is_flagged_unsafe() -> None:
    result = SourceURLAnalyzer().analyze("http://127.0.0.1/verify")

    assert result.is_private_or_internal is True
    assert result.risk_score >= 0.7
    assert "private_or_internal_url" in result.flags


def test_non_https_url_returns_elevated_risk() -> None:
    result = SourceURLAnalyzer().analyze("http://example.edu.ng/certificates/ABC-123")

    assert result.uses_https is False
    assert result.risk_score >= 0.4
    assert "non_https_url" in result.flags


def test_suspicious_keyword_url_returns_elevated_risk() -> None:
    result = SourceURLAnalyzer().analyze("https://example.edu.ng/login/account")

    assert result.has_suspicious_keywords is True
    assert result.risk_score >= 0.3
    assert "suspicious_url_keyword" in result.flags


def test_punycode_url_is_flagged() -> None:
    result = SourceURLAnalyzer().analyze("https://xn--example-9d0b.com/verify")

    assert result.punycode_detected is True
    assert "punycode_domain" in result.flags


def test_suspicious_tld_is_flagged() -> None:
    result = SourceURLAnalyzer().analyze("https://example.xyz/certificate")

    assert result.suspicious_tld is True
    assert "suspicious_tld" in result.flags
