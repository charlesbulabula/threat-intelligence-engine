import ipaddress
import logging
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+[a-zA-Z]{2,}$"
)

HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "sha512": 128,
}

HEX_REGEX = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class NormalizedIOC:
    value: str
    type: str
    canonical_value: str
    is_valid: bool
    error: Optional[str] = None
    hash_algorithm: Optional[str] = None
    extracted_domain: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type,
            "canonical_value": self.canonical_value,
            "is_valid": self.is_valid,
            "error": self.error,
            "hash_algorithm": self.hash_algorithm,
            "extracted_domain": self.extracted_domain,
        }


class IOCNormalizer:
    def normalize(self, raw_ioc: dict) -> NormalizedIOC:
        value = str(raw_ioc.get("value", "")).strip()
        ioc_type = str(raw_ioc.get("type", "")).upper().strip()

        if not value:
            return NormalizedIOC(value="", type=ioc_type, canonical_value="", is_valid=False, error="Empty value")

        if ioc_type == "IP":
            return self._normalize_ip(value)
        elif ioc_type == "DOMAIN":
            return self._normalize_domain(value)
        elif ioc_type == "HASH":
            return self._normalize_hash(value)
        elif ioc_type == "URL":
            return self._normalize_url(value)
        else:
            return NormalizedIOC(
                value=value,
                type=ioc_type,
                canonical_value=value,
                is_valid=False,
                error=f"Unknown IOC type: {ioc_type}",
            )

    def _normalize_ip(self, value: str) -> NormalizedIOC:
        original = value
        cidr = value
        if "/" in value:
            parts = value.split("/", 1)
            if parts[1] in ("32", "128"):
                cidr = parts[0]
            else:
                cidr = value

        try:
            ip_obj = ipaddress.ip_address(cidr.strip())
            canonical = str(ip_obj)
            return NormalizedIOC(
                value=original,
                type="IP",
                canonical_value=canonical,
                is_valid=True,
            )
        except ValueError:
            try:
                net = ipaddress.ip_network(value, strict=False)
                return NormalizedIOC(
                    value=original,
                    type="IP",
                    canonical_value=str(net),
                    is_valid=True,
                )
            except ValueError as exc:
                return NormalizedIOC(
                    value=original,
                    type="IP",
                    canonical_value=original,
                    is_valid=False,
                    error=f"Invalid IP address: {exc}",
                )

    def _normalize_domain(self, value: str) -> NormalizedIOC:
        original = value
        normalized = value.lower().rstrip(".")

        if normalized.startswith("*."):
            normalized = normalized[2:]

        if not normalized or len(normalized) > 253:
            return NormalizedIOC(
                value=original,
                type="DOMAIN",
                canonical_value=normalized,
                is_valid=False,
                error="Domain too long or empty after normalization",
            )

        if not DOMAIN_REGEX.match(normalized):
            return NormalizedIOC(
                value=original,
                type="DOMAIN",
                canonical_value=normalized,
                is_valid=False,
                error=f"Invalid domain format: {normalized}",
            )

        return NormalizedIOC(
            value=original,
            type="DOMAIN",
            canonical_value=normalized,
            is_valid=True,
        )

    def _normalize_hash(self, value: str) -> NormalizedIOC:
        original = value
        normalized = value.lower().strip()

        if not HEX_REGEX.match(normalized):
            return NormalizedIOC(
                value=original,
                type="HASH",
                canonical_value=normalized,
                is_valid=False,
                error="Hash contains non-hex characters",
            )

        length = len(normalized)
        algo = None
        for name, expected_len in HASH_LENGTHS.items():
            if length == expected_len:
                algo = name
                break

        if algo is None:
            return NormalizedIOC(
                value=original,
                type="HASH",
                canonical_value=normalized,
                is_valid=False,
                error=f"Unrecognized hash length: {length}",
            )

        return NormalizedIOC(
            value=original,
            type="HASH",
            canonical_value=normalized,
            is_valid=True,
            hash_algorithm=algo,
        )

    def _normalize_url(self, value: str) -> NormalizedIOC:
        original = value
        try:
            parsed = urllib.parse.urlparse(value)
            if not parsed.scheme:
                parsed = urllib.parse.urlparse(f"http://{value}")

            netloc = parsed.netloc.lower()
            if ":" in netloc:
                netloc = netloc.split(":")[0]

            domain = netloc

            if not domain:
                return NormalizedIOC(
                    value=original,
                    type="URL",
                    canonical_value=value,
                    is_valid=False,
                    error="Could not extract domain from URL",
                )

            canonical = urllib.parse.urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                "",
            ))

            return NormalizedIOC(
                value=original,
                type="URL",
                canonical_value=canonical,
                is_valid=True,
                extracted_domain=domain,
            )
        except Exception as exc:
            return NormalizedIOC(
                value=original,
                type="URL",
                canonical_value=original,
                is_valid=False,
                error=f"URL parse error: {exc}",
            )

# _r 20260618105113-303f7740
