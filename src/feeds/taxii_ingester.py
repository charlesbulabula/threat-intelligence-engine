import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Generator, List, Optional

from taxii2client.v21 import Server, Collection, as_pages

logger = logging.getLogger(__name__)

IPV4_PATTERN = re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]")
DOMAIN_PATTERN = re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]")
MD5_PATTERN = re.compile(r"\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]")
SHA256_PATTERN = re.compile(r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]")
SHA1_PATTERN = re.compile(r"\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]")
URL_PATTERN = re.compile(r"\[url:value\s*=\s*'([^']+)'\]")


@dataclass
class IOC:
    value: str
    type: str
    confidence: int
    valid_until: Optional[datetime]
    labels: List[str] = field(default_factory=list)
    stix_id: Optional[str] = None
    pattern: Optional[str] = None
    description: Optional[str] = None
    source: str = "taxii"

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type,
            "confidence": self.confidence,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "labels": self.labels,
            "stix_id": self.stix_id,
            "source": self.source,
        }


class TAXIIIngester:
    def __init__(
        self,
        server_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
    ):
        self.server_url = server_url
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._server: Optional[Server] = None
        logger.info("TAXIIIngester initialized: server=%s", server_url)

    def _get_server(self) -> Server:
        if self._server is None:
            self._server = Server(
                self.server_url,
                user=self._username,
                password=self._password,
                verify=self._verify_ssl,
            )
        return self._server

    def get_collections(self) -> List[dict]:
        server = self._get_server()
        collections = []
        try:
            for api_root in server.api_roots:
                for collection in api_root.collections:
                    collections.append({
                        "id": collection.id,
                        "title": collection.title,
                        "description": getattr(collection, "description", ""),
                        "api_root": api_root.url,
                        "can_read": collection.can_read,
                        "can_write": collection.can_write,
                    })
        except Exception as exc:
            logger.error("Failed to list TAXII collections: %s", exc)
            raise
        logger.info("Found %d TAXII collections", len(collections))
        return collections

    def _find_collection(self, collection_id: str) -> Optional[Collection]:
        server = self._get_server()
        for api_root in server.api_roots:
            for collection in api_root.collections:
                if collection.id == collection_id:
                    return collection
        return None

    def _extract_ioc_from_pattern(self, pattern: str, indicator: dict) -> Optional[IOC]:
        confidence = indicator.get("confidence", 50)
        labels = indicator.get("labels", [])
        stix_id = indicator.get("id")
        description = indicator.get("description", "")

        valid_until_str = indicator.get("valid_until")
        valid_until = None
        if valid_until_str:
            try:
                valid_until = datetime.fromisoformat(valid_until_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        for regex, ioc_type in [
            (IPV4_PATTERN, "IP"),
            (DOMAIN_PATTERN, "DOMAIN"),
            (MD5_PATTERN, "HASH"),
            (SHA256_PATTERN, "HASH"),
            (SHA1_PATTERN, "HASH"),
            (URL_PATTERN, "URL"),
        ]:
            match = regex.search(pattern)
            if match:
                return IOC(
                    value=match.group(1),
                    type=ioc_type,
                    confidence=confidence,
                    valid_until=valid_until,
                    labels=labels,
                    stix_id=stix_id,
                    pattern=pattern,
                    description=description,
                )

        logger.debug("Could not extract IOC from pattern: %s", pattern[:100])
        return None

    def fetch_indicators(
        self,
        collection_id: str,
        since_dt: Optional[datetime] = None,
    ) -> Generator[IOC, None, None]:
        collection = self._find_collection(collection_id)
        if not collection:
            raise ValueError(f"Collection not found: {collection_id}")

        kwargs = {"type": "indicator"}
        if since_dt:
            kwargs["added_after"] = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        total_fetched = 0
        total_yielded = 0

        try:
            for bundle_page in as_pages(collection.get_objects, per_request=100, **kwargs):
                objects = bundle_page.get("objects", [])
                for obj in objects:
                    if obj.get("type") != "indicator":
                        continue
                    total_fetched += 1
                    pattern = obj.get("pattern", "")
                    if not pattern:
                        continue
                    ioc = self._extract_ioc_from_pattern(pattern, obj)
                    if ioc:
                        total_yielded += 1
                        yield ioc
        except Exception as exc:
            logger.error("Error fetching from collection %s: %s", collection_id, exc)
            raise

        logger.info(
            "TAXII fetch complete: collection=%s fetched=%d yielded=%d",
            collection_id,
            total_fetched,
            total_yielded,
        )

# _r 20260616104912-1f1a6ac9
