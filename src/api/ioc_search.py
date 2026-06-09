import hashlib
import json
import logging
from typing import List, Optional

import redis
from elasticsearch import Elasticsearch, NotFoundError
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ioc", tags=["ioc"])

IOC_INDEX = "ioc_index"
CACHE_TTL = 300
MAX_BULK_VALUES = 500


def get_es() -> Elasticsearch:
    from src.dependencies import get_elasticsearch
    return get_elasticsearch()


def get_redis() -> redis.Redis:
    from src.dependencies import get_redis_client
    return get_redis_client()


class IOCMatch(BaseModel):
    value: str
    matched: bool
    confidence: Optional[int] = None
    sources: List[str] = Field(default_factory=list)
    last_seen: Optional[str] = None
    type: Optional[str] = None
    labels: List[str] = Field(default_factory=list)
    threat_level: Optional[str] = None


class BulkCheckRequest(BaseModel):
    values: List[str] = Field(..., min_length=1, max_length=MAX_BULK_VALUES)


class BulkCheckResponse(BaseModel):
    total: int
    matched: int
    results: List[IOCMatch]


def _cache_key(value: str) -> str:
    sha = hashlib.sha256(value.encode()).hexdigest()
    return f"ioc:{sha}"


def _source_from_hit(hit: dict) -> IOCMatch:
    src = hit.get("_source", {})
    return IOCMatch(
        value=src.get("value", ""),
        matched=True,
        confidence=src.get("confidence_score") or src.get("confidence"),
        sources=src.get("sources", [src.get("source")] if src.get("source") else []),
        last_seen=src.get("last_seen") or src.get("updated_at"),
        type=src.get("type"),
        labels=src.get("labels", []),
        threat_level=src.get("threat_level"),
    )


@router.get("/lookup", response_model=IOCMatch)
async def lookup_ioc(
    value: str = Query(..., min_length=1, max_length=512),
    es: Elasticsearch = Depends(get_es),
    redis_client: redis.Redis = Depends(get_redis),
):
    cache_key = _cache_key(value)
    cached = redis_client.get(cache_key)
    if cached:
        try:
            data = json.loads(cached)
            logger.debug("IOC cache hit: %s", value[:64])
            return IOCMatch(**data)
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning("Cache decode error for %s: %s", value, exc)

    try:
        resp = es.search(
            index=IOC_INDEX,
            query={"term": {"value.keyword": value}},
            size=1,
        )
    except Exception as exc:
        logger.error("ES lookup failed for '%s': %s", value, exc)
        raise HTTPException(status_code=503, detail="Search service unavailable")

    hits = resp["hits"]["hits"]
    if not hits:
        result = IOCMatch(value=value, matched=False)
        redis_client.setex(cache_key, CACHE_TTL, result.model_dump_json())
        return result

    result = _source_from_hit(hits[0])
    try:
        redis_client.setex(cache_key, CACHE_TTL, result.model_dump_json())
    except Exception as exc:
        logger.warning("Failed to cache IOC result: %s", exc)

    return result


@router.post("/bulk-check", response_model=BulkCheckResponse)
async def bulk_check(
    request: BulkCheckRequest,
    es: Elasticsearch = Depends(get_es),
    redis_client: redis.Redis = Depends(get_redis),
):
    values = request.values
    results: List[IOCMatch] = []
    uncached_values = []
    cache_map = {}

    pipe = redis_client.pipeline(transaction=False)
    for v in values:
        pipe.get(_cache_key(v))
    cache_hits = pipe.execute()

    for val, hit in zip(values, cache_hits):
        if hit:
            try:
                results.append(IOCMatch(**json.loads(hit)))
                cache_map[val] = True
            except Exception:
                uncached_values.append(val)
        else:
            uncached_values.append(val)

    if uncached_values:
        docs_to_get = [
            {"_index": IOC_INDEX, "_id": hashlib.sha256(v.encode()).hexdigest()}
            for v in uncached_values
        ]

        try:
            es_resp = es.search(
                index=IOC_INDEX,
                query={
                    "terms": {"value.keyword": uncached_values}
                },
                size=len(uncached_values),
            )
            found_values = {hit["_source"]["value"]: hit for hit in es_resp["hits"]["hits"]}
        except Exception as exc:
            logger.error("ES bulk check failed: %s", exc)
            raise HTTPException(status_code=503, detail="Search service unavailable")

        set_pipe = redis_client.pipeline(transaction=False)
        for val in uncached_values:
            if val in found_values:
                match = _source_from_hit(found_values[val])
            else:
                match = IOCMatch(value=val, matched=False)
            results.append(match)
            set_pipe.setex(_cache_key(val), CACHE_TTL, match.model_dump_json())
        set_pipe.execute()

    total_matched = sum(1 for r in results if r.matched)
    return BulkCheckResponse(
        total=len(values),
        matched=total_matched,
        results=results,
    )

# _r 20260609102908-6263dc0e
