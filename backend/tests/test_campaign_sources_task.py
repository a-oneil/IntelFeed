"""sync_campaign_sources never succeeded in prod: its summary line passed the
stats dict as kwargs to a stdlib logger (TypeError on every run)."""

from app.workers import saved_search_tasks as sst


def test_sync_campaign_sources_logs_the_summary_without_raising(monkeypatch, caplog):
    def fake_run_async(coro):
        coro.close()
        return {"campaigns": 2, "entries_added": 5}

    monkeypatch.setattr(sst, "run_async", fake_run_async)
    with caplog.at_level("INFO", logger="app.workers.saved_search_tasks"):
        sst.sync_campaign_sources()
    assert any("campaign_sources_synced" in r.getMessage() for r in caplog.records)
