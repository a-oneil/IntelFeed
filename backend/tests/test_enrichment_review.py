"""What enrichment asks an analyst to look at (``app/enrichment/review.py``):
an IP Shodan newly tags ``scanner``, or that GreyNoise classes benign
mass-scanning noise, is flagged ``needs_review`` once, through the sources'
``apply_record`` hooks. Real database."""

import pytest

from app.enrichment import pipeline
from app.enrichment.base import EnrichmentData
from app.models.observable import Observable


async def _obs(db, value: str, **fields) -> Observable:
    obs = Observable(kind="ipv4", value=value, base_confidence=0.8, current_confidence=0.8, **fields)
    db.add(obs)
    await db.flush()
    return obs


# ── Review flags ─────────────────────────────────────────────────────


def _shodan(tags: str | None) -> EnrichmentData:
    return EnrichmentData(raw_response={}, parsed_data={"found": True, "tags": tags}, ttl_hours=24)


def _greynoise(noise_class: str, noise: bool) -> EnrichmentData:
    return EnrichmentData(
        raw_response={}, parsed_data={"found": True, "noise_class": noise_class, "noise": noise}, ttl_hours=168
    )


async def _apply(db, obs: Observable, source_type: str, data: EnrichmentData) -> None:
    await pipeline.apply_source_result(db, "observable", obs.id, source_type, data)
    await db.refresh(obs)


async def test_a_newly_scanner_tagged_ip_is_flagged_for_review(db_session):
    obs = await _obs(db_session, "198.51.100.20")
    await _apply(db_session, obs, "shodan", _shodan("cloud, scanner"))

    assert obs.needs_review is True
    assert obs.infra_tag == "scanner"
    assert obs.reputation["shodan_tags"] == "cloud, scanner"


async def test_other_shodan_tags_raise_no_flag(db_session):
    obs = await _obs(db_session, "198.51.100.21")
    await _apply(db_session, obs, "shodan", _shodan("vpn, self-signed"))
    assert obs.needs_review is False
    assert obs.infra_tag == "vpn"


async def test_a_cleared_scanner_flag_isnt_raised_again(db_session):
    """Shodan said scanner before; the analyst cleared the flag; the next
    answer saying the same doesn't ask again."""
    obs = await _obs(db_session, "198.51.100.22")
    await _apply(db_session, obs, "shodan", _shodan("scanner"))
    assert obs.needs_review is True
    obs.needs_review = False
    await db_session.flush()

    await _apply(db_session, obs, "shodan", _shodan("scanner"))
    assert obs.needs_review is False

    # Shodan stops saying it, then says it again: that's new, so it asks.
    await _apply(db_session, obs, "shodan", _shodan("vpn"))
    await _apply(db_session, obs, "shodan", _shodan("scanner"))
    assert obs.needs_review is True


async def test_an_ip_tagged_scanner_before_isnt_flagged(db_session):
    obs = await _obs(db_session, "198.51.100.23", reputation={"shodan_tags": "scanner"})
    await _apply(db_session, obs, "shodan", _shodan("scanner, cloud"))
    assert obs.needs_review is False


async def test_greynoise_benign_noise_flags_once(db_session):
    obs = await _obs(db_session, "198.51.100.24")
    await _apply(db_session, obs, "greynoise", _greynoise("benign", True))
    assert (obs.noise_class, obs.needs_review) == ("benign", True)

    obs.needs_review = False
    await db_session.flush()
    await _apply(db_session, obs, "greynoise", _greynoise("benign", True))
    assert obs.needs_review is False


@pytest.mark.parametrize(("noise_class", "noise"), [("malicious", True), ("benign", False), ("unknown", True)])
async def test_greynoise_other_answers_raise_no_flag(db_session, noise_class, noise):
    obs = await _obs(db_session, "198.51.100.25")
    await _apply(db_session, obs, "greynoise", _greynoise(noise_class, noise))
    assert obs.needs_review is False


@pytest.mark.parametrize(
    ("source_type", "data"), [("shodan", _shodan("scanner")), ("greynoise", _greynoise("benign", True))]
)
async def test_a_denied_ip_is_never_flagged(db_session, source_type, data):
    obs = await _obs(db_session, "198.51.100.26", is_denied=True)
    await _apply(db_session, obs, source_type, data)
    assert obs.needs_review is False
