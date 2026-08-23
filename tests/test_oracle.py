import asyncio
import datetime as _datetime

import httpx

from oracle.treasury import (
    TREASURY_XML_BASE,
    TreasuryOracle,
    parse_yield_curve,
    yield_curve_url,
)


def _feed(*rows: tuple[str, str]) -> str:
    entries = "".join(
        f"<entry><content><d:properties>"
        f"<d:NEW_DATE>{day}T00:00:00</d:NEW_DATE><d:BC_3MONTH>{rate}</d:BC_3MONTH>"
        f"</d:properties></content></entry>"
        for day, rate in rows
    )
    return (
        "<?xml version='1.0'?>"
        "<feed xmlns='http://www.w3.org/2005/Atom' xmlns:d='urn:test'>"
        f"{entries}</feed>"
    )


EMPTY_FEED = _feed()


def test_parse_yield_curve_selects_latest_record():
    xml = _feed(("2026-08-10", "4.01"), ("2026-08-11", "4.02"))
    assert parse_yield_curve(xml, "BC_3MONTH") == (_datetime.date(2026, 8, 11), 4.02)


def test_the_feed_url_targets_the_odata_endpoint_for_a_named_year():
    """The legacy .../interest-rates/yield.xml document carries zero <entry> elements,
    so the parser can never find a record in it. Only the OData/Atom endpoint works."""
    url = yield_curve_url(2026)
    assert url.startswith(TREASURY_XML_BASE)
    assert "data=daily_treasury_yield_curve" in url
    assert "field_tdr_date_value=2026" in url
    assert "sites/default/files" not in url


def test_the_live_feed_is_tried_for_this_year_then_last_year():
    """Treasury's year feed is empty until the year's first business day closes, so a
    bare current-year URL returns nothing every 1 January. Verified against the live
    endpoint: field_tdr_date_value=2027 answers HTTP 200 with zero entries."""
    this_year = _datetime.datetime.now(_datetime.timezone.utc).year
    assert TreasuryOracle()._candidate_urls() == [
        yield_curve_url(this_year),
        yield_curve_url(this_year - 1),
    ]


def test_an_explicitly_supplied_url_is_used_verbatim():
    """Callers pinning a URL get exactly that one, with no year fallback behind it."""
    assert TreasuryOracle(url="https://example.test/feed.xml")._candidate_urls() == [
        "https://example.test/feed.xml"
    ]


def test_an_empty_current_year_feed_falls_back_to_the_previous_year():
    served: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        served.append(str(request.url))
        body = EMPTY_FEED if len(served) == 1 else _feed(("2026-12-31", "3.95"))
        return httpx.Response(200, text=body)

    async def run():
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            return await TreasuryOracle(client=client).get_observation("3M")
        finally:
            await client.aclose()

    observation = asyncio.run(run())

    assert len(served) == 2, "the empty current-year feed must be retried against last year"
    assert observation is not None
    assert observation.observed_yield_bps == 395
    assert observation.record_date == _datetime.date(2026, 12, 31)


def test_a_populated_current_year_feed_costs_exactly_one_request():
    served: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        served.append(str(request.url))
        return httpx.Response(200, text=_feed(("2026-08-21", "3.88")))

    async def run():
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            return await TreasuryOracle(client=client).get_observation("3M")
        finally:
            await client.aclose()

    observation = asyncio.run(run())

    assert served == [yield_curve_url(_datetime.datetime.now(_datetime.timezone.utc).year)]
    assert observation is not None and observation.observed_yield_bps == 388


def test_the_default_timeout_clears_the_measured_feed_latency():
    """Measured against the live OData feed on 2026-08-22: 8.2 s, 9.1 s, 9.5 s cold.
    The former 3.0 s default timed out before the feed could answer, so a correct URL
    alone would still have produced nothing."""
    assert TreasuryOracle()._timeout_seconds >= 12.0
