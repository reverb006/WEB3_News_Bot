"""
Tests for RadarScheduler lifecycle, job registration, and concurrency locks.
"""

import asyncio
from unittest.mock import patch

import pytest
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.database.db import Database
from app.scheduler import RadarScheduler, run_daemon


async def _get_test_db():
    db = Database(":memory:")
    await db.initialize()
    return db


@pytest.mark.asyncio
class TestRadarScheduler:
    """Test scheduler initialization, job configuration, and lifecycle."""

    async def test_job_registration(self):
        db = await _get_test_db()
        try:
            scheduler = RadarScheduler(db=db)
            scheduler.setup_jobs(run_pipeline_immediately=True)

            jobs = {job.id: job for job in scheduler.scheduler.get_jobs()}

            # Verify all 3 jobs are registered
            assert "pipeline_cycle" in jobs
            assert "daily_digest" in jobs
            assert "initial_startup_pipeline" in jobs

            # Verify trigger types
            assert isinstance(jobs["pipeline_cycle"].trigger, IntervalTrigger)
            assert isinstance(jobs["daily_digest"].trigger, CronTrigger)
        finally:
            await db.close()

    async def test_job_registration_no_initial(self):
        db = await _get_test_db()
        try:
            scheduler = RadarScheduler(db=db)
            scheduler.setup_jobs(run_pipeline_immediately=False)

            jobs = {job.id: job for job in scheduler.scheduler.get_jobs()}
            assert "pipeline_cycle" in jobs
            assert "daily_digest" in jobs
            assert "initial_startup_pipeline" not in jobs
        finally:
            await db.close()

    async def test_scheduler_lifecycle(self):
        db = await _get_test_db()
        try:
            scheduler = RadarScheduler(db=db)
            assert scheduler.is_running is False

            scheduler.start(run_pipeline_immediately=False)
            assert scheduler.is_running is True

            scheduler.shutdown(wait=False)
            assert scheduler.is_running is False
        finally:
            await db.close()

    async def test_pipeline_cycle_lock_prevents_overlap(self):
        db = await _get_test_db()
        try:
            scheduler = RadarScheduler(db=db)

            # Acquire the lock manually to simulate an active running cycle
            await scheduler._cycle_lock.acquire()

            try:
                result = await scheduler.run_pipeline_cycle()
                assert result.get("skipped") is True
            finally:
                scheduler._cycle_lock.release()
        finally:
            await db.close()

    @patch("app.digest.daily.run_daily_digest")
    async def test_run_digest_cycle(self, mock_run_digest):
        mock_run_digest.return_value = ("reports/digest_2026-09-22.md", [42])

        db = await _get_test_db()
        try:
            scheduler = RadarScheduler(db=db)
            res = await scheduler.run_digest_cycle()

            assert res["success"] is True
            assert res["report_path"] == "reports/digest_2026-09-22.md"
            assert res["telegram_message_ids"] == [42]
        finally:
            await db.close()

    async def test_run_daemon_graceful_stop(self, monkeypatch):
        import app.scheduler as sched_mod
        from app.config.settings import Settings

        clean_settings = Settings(
            _env_file=None,
            gemini_api_key="",
            telegram_bot_token="",
            telegram_chat_id="",
            web_port=0,
        )
        monkeypatch.setattr(sched_mod, "get_settings", lambda: clean_settings)

        db = await _get_test_db()
        try:
            stop_event = asyncio.Event()

            # Set stop event after a brief delay
            async def trigger_stop():
                await asyncio.sleep(0.05)
                stop_event.set()

            asyncio.create_task(trigger_stop())
            # Should start daemon and exit cleanly without raising exceptions
            await run_daemon(db=db, run_immediately=False, stop_event=stop_event)
        finally:
            await db.close()
