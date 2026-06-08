import logging
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger(__name__)


class ConfidenceScorer:
    SOURCE_SCORES = {
        "misp": 85,
        "taxii_cisa": 90,
        "taxii_isac": 85,
        "otx": 70,
        "custom": 50,
        "manual": 60,
        "crowdstrike": 88,
        "recorded_future": 87,
        "virustotal": 75,
        "shodan": 65,
        "unknown": 40,
    }

    MAX_CROSS_SOURCE_BONUS = 20
    CROSS_SOURCE_BONUS_PER_SOURCE = 10
    ANALYST_REVIEWED_BONUS = 15
    AGE_DECAY_PER_WEEK = 5
    MAX_AGE_DECAY = 30

    def score(self, ioc: dict) -> int:
        source = str(ioc.get("source", "unknown")).lower()
        base_score = self.SOURCE_SCORES.get(source, self.SOURCE_SCORES["unknown"])

        created_at = ioc.get("created_at") or ioc.get("first_seen")
        decay = 0
        if created_at:
            decay = self._age_decay(created_at)

        additional_sources: List[str] = ioc.get("additional_sources", [])
        cross_source_bonus = min(
            len(additional_sources) * self.CROSS_SOURCE_BONUS_PER_SOURCE,
            self.MAX_CROSS_SOURCE_BONUS,
        )

        analyst_bonus = self.ANALYST_REVIEWED_BONUS if ioc.get("analyst_reviewed", False) else 0

        raw_score = base_score - decay + cross_source_bonus + analyst_bonus
        final_score = max(0, min(100, raw_score))

        logger.debug(
            "IOC score: value=%s base=%d decay=%d cross_source=%d analyst=%d final=%d",
            ioc.get("value", "?"),
            base_score,
            decay,
            cross_source_bonus,
            analyst_bonus,
            final_score,
        )
        return final_score

    def decay_factor(self, created_at) -> int:
        weeks = self._weeks_elapsed(created_at)
        return min(int(weeks * self.AGE_DECAY_PER_WEEK), self.MAX_AGE_DECAY)

    def _age_decay(self, created_at) -> int:
        try:
            return self.decay_factor(created_at)
        except Exception as exc:
            logger.warning("Could not compute age decay: %s", exc)
            return 0

    def _weeks_elapsed(self, created_at) -> float:
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))

        if isinstance(created_at, datetime):
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = now - created_at
            weeks = delta.total_seconds() / (7 * 24 * 3600)
            return max(0.0, weeks)

        raise ValueError(f"Unsupported created_at type: {type(created_at)}")

    def bulk_score(self, iocs: List[dict]) -> List[dict]:
        results = []
        for ioc in iocs:
            try:
                s = self.score(ioc)
                results.append({**ioc, "confidence_score": s})
            except Exception as exc:
                logger.error("Scoring failed for IOC %s: %s", ioc.get("value"), exc)
                results.append({**ioc, "confidence_score": 0})
        return results

    def get_tier(self, score: int) -> str:
        if score >= 85:
            return "HIGH"
        elif score >= 65:
            return "MEDIUM"
        elif score >= 40:
            return "LOW"
        return "VERY_LOW"

    def adjust_for_context(self, base_score: int, context: dict) -> int:
        adjusted = base_score
        if context.get("seen_in_wild", False):
            adjusted += 5
        if context.get("targeted_industry_match", False):
            adjusted += 8
        if context.get("revoked", False):
            adjusted -= 30
        if context.get("false_positive_count", 0) > 0:
            fp_penalty = min(context["false_positive_count"] * 10, 40)
            adjusted -= fp_penalty
        return max(0, min(100, adjusted))

# _r 20260605152604-0865ef1c
