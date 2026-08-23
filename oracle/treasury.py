from __future__ import annotations

from datetime import date, datetime, timezone
from xml.etree import ElementTree

import httpx

from custos_protocol.models import Observation
from oracle.cache import TTLCache
from oracle.tenors import TENOR_FIELDS

# Treasury's OData/Atom endpoint for the daily par yield curve. It is intentionally
# isolated here so a Fiscal Data JSON client can replace it without touching the
# scoring engine or gateway.
#
# This must not be pointed back at .../sites/default/files/interest-rates/yield.xml.
# That document is reachable and healthy but serves the legacy QR_BC_CM report, which
# contains zero <entry> elements and dates in DD-MON-YY form. parse_yield_curve finds
# nothing in it and every request fails closed. See ARCHITECTURE.md section 18.
TREASURY_XML_BASE = (
    "https://home.treasury.gov/resource-center/data-chart-center/interest-rates/pages/xml"
)


def yield_curve_url(year: int) -> str:
    """The daily par yield curve feed for one calendar year."""
    return f"{TREASURY_XML_BASE}?data=daily_treasury_yield_curve&field_tdr_date_value={year}"


class UnsupportedTenor(ValueError):
    pass


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_date(value: str) -> date | None:
    value = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None


def parse_yield_curve(xml: str, field_name: str) -> tuple[date, float] | None:
    """Extract the most recent non-empty tenor value from Treasury Atom XML."""
    root = ElementTree.fromstring(xml)
    candidates: list[tuple[date, float]] = []
    for entry in root.iter():
        if _local_name(entry.tag) != "entry":
            continue
        values = {_local_name(node.tag): (node.text or "").strip() for node in entry.iter()}
        raw_date = values.get("NEW_DATE") or values.get("QUOTE_DATE") or values.get("record_date")
        raw_yield = values.get(field_name)
        if not raw_date or not raw_yield or raw_yield.upper() in {"N/A", "NA"}:
            continue
        parsed_date = _parse_date(raw_date)
        try:
            parsed_yield = float(raw_yield)
        except ValueError:
            parsed_yield = -1
        if parsed_date is not None and parsed_yield >= 0:
            candidates.append((parsed_date, parsed_yield))
    return max(candidates, default=None, key=lambda item: item[0])


class TreasuryOracle:
    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        url: str | None = None,
        timeout_seconds: float = 15.0,
        cache_ttl_seconds: int = 60,
    ) -> None:
        self._client = client
        self._url = url
        self._timeout_seconds = timeout_seconds
        self._cache: TTLCache[Observation] = TTLCache(cache_ttl_seconds)

    def _candidate_urls(self) -> list[str]:
        """A pinned URL is used verbatim. Otherwise the live feed is tried for this
        year and then last year: Treasury's year feed answers HTTP 200 with zero
        entries until the year's first business day closes, so a bare current-year
        URL yields nothing every 1 January."""
        if self._url is not None:
            return [self._url]
        this_year = datetime.now(timezone.utc).year
        return [yield_curve_url(this_year), yield_curve_url(this_year - 1)]

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> str | None:
        # One retry only for transport failures. HTTP error responses do not retry.
        for attempt in range(2):
            try:
                response = await client.get(url)
            except httpx.TransportError:
                if attempt:
                    return None
                continue
            return None if response.is_error else response.text
        return None

    async def get_observation(self, tenor: str) -> Observation | None:
        field_name = TENOR_FIELDS.get(tenor)
        if field_name is None:
            raise UnsupportedTenor(tenor)
        cached = self._cache.get(tenor)
        if cached is not None:
            return cached.model_copy(update={"cache_hit": True})

        timeout = httpx.Timeout(self._timeout_seconds, connect=self._timeout_seconds)
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        try:
            parsed = None
            for url in self._candidate_urls():
                body = await self._fetch(client, url)
                if body is None:
                    continue
                parsed = parse_yield_curve(body, field_name)
                if parsed is not None:
                    break
            if parsed is None:
                return None
            record_date, percent = parsed
            observation = Observation(
                source="home.treasury.gov", tenor=tenor,
                observed_yield_bps=int(round(percent * 100)), record_date=record_date,
                fetched_at=datetime.now(timezone.utc), cache_hit=False,
            )
            self._cache.set(tenor, observation)
            return observation
        except (httpx.HTTPError, ElementTree.ParseError):
            return None
        finally:
            if owns_client:
                await client.aclose()
