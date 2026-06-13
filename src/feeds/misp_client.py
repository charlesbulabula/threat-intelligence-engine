import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pymisp
from pymisp import PyMISP, MISPEvent, MISPAttribute

logger = logging.getLogger(__name__)

ATTR_TYPE_MAP = {
    "ip-src": "IP",
    "ip-dst": "IP",
    "ip-src|port": "IP",
    "ip-dst|port": "IP",
    "domain": "DOMAIN",
    "hostname": "DOMAIN",
    "domain|ip": "DOMAIN",
    "md5": "HASH",
    "sha1": "HASH",
    "sha256": "HASH",
    "sha512": "HASH",
    "url": "URL",
    "link": "URL",
    "email-src": "EMAIL",
    "email-dst": "EMAIL",
}

THREAT_LEVEL_MAP = {
    "1": "HIGH",
    "2": "MEDIUM",
    "3": "LOW",
    "4": "INFO",
}


class MISPClient:
    def __init__(
        self,
        url: str,
        api_key: str,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        self.url = url.rstrip("/")
        self._misp = PyMISP(
            url=self.url,
            key=api_key,
            ssl=verify_ssl,
            timeout=timeout,
        )
        logger.info("MISPClient initialized: url=%s", self.url)

    def fetch_recent(
        self,
        hours: int = 24,
        tags: Optional[List[str]] = None,
        published: bool = True,
        threat_level: Optional[int] = None,
    ) -> List[MISPEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        timestamp = int(cutoff.timestamp())

        search_params: Dict = {
            "timestamp": timestamp,
            "pythonify": True,
        }

        if published:
            search_params["published"] = True

        if tags:
            search_params["tags"] = tags

        if threat_level:
            search_params["threat_level_id"] = threat_level

        try:
            events = self._misp.search(controller="events", **search_params)
            if isinstance(events, dict) and "errors" in events:
                logger.error("MISP search returned errors: %s", events["errors"])
                return []
            logger.info("Fetched %d MISP events (last %d hours)", len(events), hours)
            return events
        except Exception as exc:
            logger.error("Failed to fetch MISP events: %s", exc)
            raise

    def extract_iocs(self, event: MISPEvent) -> List[dict]:
        iocs = []

        event_id = str(event.id) if hasattr(event, "id") else "unknown"
        threat_level_id = str(getattr(event, "threat_level_id", "4"))
        threat_level = THREAT_LEVEL_MAP.get(threat_level_id, "INFO")
        event_uuid = str(getattr(event, "uuid", ""))
        event_date = str(getattr(event, "date", ""))

        attributes: List[MISPAttribute] = []
        if hasattr(event, "attributes"):
            attributes.extend(event.attributes)

        for obj in getattr(event, "Object", []):
            for attr in getattr(obj, "Attribute", []):
                attributes.append(attr)

        for attr in attributes:
            attr_type = str(getattr(attr, "type", ""))
            ioc_type = ATTR_TYPE_MAP.get(attr_type)
            if not ioc_type:
                continue

            value = str(getattr(attr, "value", "")).strip()
            if not value:
                continue

            if "|" in attr_type and "|" in value:
                value = value.split("|")[0].strip()

            comment = str(getattr(attr, "comment", "") or "")
            tags = []
            for tag in getattr(attr, "Tag", []):
                tag_name = getattr(tag, "name", "")
                if tag_name:
                    tags.append(tag_name)

            ioc = {
                "value": value,
                "type": ioc_type,
                "attr_type": attr_type,
                "event_id": event_id,
                "event_uuid": event_uuid,
                "event_date": event_date,
                "threat_level": threat_level,
                "comment": comment,
                "tags": tags,
                "to_ids": bool(getattr(attr, "to_ids", False)),
                "source": "misp",
            }
            iocs.append(ioc)

        logger.debug("Extracted %d IOCs from MISP event %s", len(iocs), event_id)
        return iocs

    def get_event(self, event_id: int) -> Optional[MISPEvent]:
        try:
            event = self._misp.get_event(event_id, pythonify=True)
            return event
        except Exception as exc:
            logger.error("Failed to fetch MISP event %s: %s", event_id, exc)
            return None

    def search_by_value(self, value: str) -> List[dict]:
        try:
            results = self._misp.search(value=value, pythonify=True)
            iocs = []
            for event in results:
                iocs.extend(self.extract_iocs(event))
            return [ioc for ioc in iocs if ioc["value"] == value]
        except Exception as exc:
            logger.error("MISP value search failed for '%s': %s", value, exc)
            return []

# _r 20260613094303-7f6e0371
