"""
Scheduler module — autonomous 24/7 background execution using APScheduler.

Orchestrates:
1. Real-time Pipeline Cycle (Every 15 minutes by default):
   - Fetches new articles from all active RSS collectors
   - Classifies unclassified articles using Gemini
   - Computes priority scores & links/merges incidents
   - Dispatches real-time Telegram alerts for critical exploits (priority >= 70)
   - Triggers deep case-study generation for critical incidents (priority >= 80)
2. Daily Digest Cycle (Daily at configured time, default 09:00 UTC):
   - Compiles 24h intelligence summary
   - Generates markdown report in reports/digest_YYYY-MM-DD.md
   - Delivers rich HTML Telegram digest card
3. Graceful lifecycle management and signal handling for daemon operation
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.config.settings import get_settings
from app.database.db import Database

logger = logging.getLogger(__name__)


class RadarScheduler:
    """
    Autonomous pipeline scheduler managing periodic collection, classification,
    incident alerting, and daily digest dispatches.
    """

    def __init__(self, db: Database):
        self.db = db
        self.settings = get_settings()
        self.tz = self.settings.scheduler_timezone or "UTC"
        self._scheduler = AsyncIOScheduler(timezone=self.tz)
        self._is_running = False
        self._cycle_lock = asyncio.Lock()

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def scheduler(self) -> AsyncIOScheduler:
        return self._scheduler

    async def run_pipeline_cycle(self) -> dict:
        """
        Execute a single pipeline cycle: collect -> classify -> alert -> analyze.
        Protected with a lock so concurrent triggers cannot overlap.
        """
        if self._cycle_lock.locked():
            logger.warning("Previous pipeline cycle is still running. Skipping this trigger.")
            return {"skipped": True}

        async with self._cycle_lock:
            start_time = datetime.now(timezone.utc)
            logger.info("=" * 60)
            logger.info(f"Starting scheduled pipeline cycle at {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            logger.info("=" * 60)

            results = {
                "started_at": start_time.isoformat(),
                "collected": {},
                "classified": {},
                "duration_seconds": 0.0,
            }

            # 1. Collection Phase
            try:
                from app.main import collect_all
                logger.info("--- Phase 1: RSS Feed Collection ---")
                collect_summary = await collect_all(self.db)
                results["collected"] = collect_summary
                logger.info(
                    f"Collection finished: {collect_summary['articles_new']} new, "
                    f"{collect_summary['articles_duplicate']} duplicates "
                    f"({collect_summary['sources_succeeded']}/{collect_summary['sources_attempted']} sources OK)"
                )
            except Exception as e:
                logger.error(f"Error during scheduled collection phase: {e}", exc_info=True)
                results["collected"]["error"] = str(e)

            # 2. Classification & Alerting Phase
            try:
                from app.main import classify_all
                logger.info("--- Phase 2: AI Classification & Incident Merging ---")
                classify_summary = await classify_all(self.db, limit=30)
                results["classified"] = classify_summary

                logger.info(
                    f"Classification finished: {classify_summary['classified']} classified, "
                    f"{classify_summary['failed']} failed, "
                    f"{classify_summary.get('alerts_sent', 0)} alerts dispatched"
                )
            except Exception as e:
                logger.error(f"Error during scheduled classification phase: {e}", exc_info=True)
                results["classified"]["error"] = str(e)

            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            results["duration_seconds"] = round(duration, 2)
            logger.info(f"Pipeline cycle completed in {results['duration_seconds']}s")
            return results

    async def run_digest_cycle(self) -> dict:
        """
        Execute the daily digest generation and broadcast job.
        """
        logger.info("=" * 60)
        logger.info("Starting scheduled Daily Digest cycle")
        logger.info("=" * 60)

        results = {"started_at": datetime.now(timezone.utc).isoformat(), "success": False}
        try:
            from app.digest.daily import run_daily_digest
            report_path, telegram_ids = await run_daily_digest(
                db=self.db,
                target_date=None,  # Defaults to latest active date
                send_telegram=True,
                force=False,
            )
            results["success"] = True
            results["report_path"] = str(report_path) if report_path else None
            results["telegram_message_ids"] = telegram_ids
            logger.info(f"Daily Digest completed: report={report_path}, telegram_msgs={len(telegram_ids)}")
        except Exception as e:
            logger.error(f"Error during scheduled daily digest cycle: {e}", exc_info=True)
            results["error"] = str(e)

        return results

    def setup_jobs(self, run_pipeline_immediately: bool = True) -> None:
        """
        Register recurring jobs with the APScheduler instance.
        """
        # 1. Pipeline interval job
        interval_min = max(1, self.settings.rss_collection_interval_minutes)
        pipeline_trigger = IntervalTrigger(
            minutes=interval_min,
            timezone="UTC",
        )
        self._scheduler.add_job(
            self.run_pipeline_cycle,
            trigger=pipeline_trigger,
            id="pipeline_cycle",
            name="Periodic Collection & Classification",
            replace_existing=True,
            max_instances=1,
        )
        logger.info(f"Registered pipeline job: every {interval_min} minutes (UTC)")

        # 2. Daily Digest cron job
        digest_time_str = self.settings.daily_digest_time or "10:00"
        try:
            hour_str, min_str = digest_time_str.split(":")
            digest_hour = int(hour_str)
            digest_min = int(min_str)
        except Exception:
            logger.warning(f"Invalid DAILY_DIGEST_TIME '{digest_time_str}'. Defaulting to 10:00 ({self.tz}).")
            digest_hour, digest_min = 10, 0

        digest_trigger = CronTrigger(
            hour=digest_hour,
            minute=digest_min,
            timezone=self.tz,
        )
        self._scheduler.add_job(
            self.run_digest_cycle,
            trigger=digest_trigger,
            id="daily_digest",
            name="Daily Security Intelligence Digest",
            replace_existing=True,
            max_instances=1,
        )
        logger.info(f"Registered daily digest job: daily at {digest_hour:02d}:{digest_min:02d} ({self.tz})")

        # 3. Optional immediate initial run on startup
        if run_pipeline_immediately:
            self._scheduler.add_job(
                self.run_pipeline_cycle,
                trigger="date",
                run_date=datetime.now(timezone.utc),
                id="initial_startup_pipeline",
                name="Initial Startup Pipeline",
                replace_existing=True,
            )
            logger.info("Registered initial pipeline job to run immediately on startup.")

    def start(self, run_pipeline_immediately: bool = True) -> None:
        """Start the scheduler."""
        if not self._is_running:
            self.setup_jobs(run_pipeline_immediately=run_pipeline_immediately)
            self._scheduler.start()
            self._is_running = True
            logger.info("RadarScheduler started successfully.")

    def shutdown(self, wait: bool = False) -> None:
        """Gracefully shut down the scheduler."""
        if self._is_running:
            self._scheduler.shutdown(wait=wait)
            self._is_running = False
            logger.info("RadarScheduler stopped.")


async def run_daemon(
    db: Database,
    run_immediately: bool = True,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    """
    Run the autonomous daemon loop until interrupted.
    """
    scheduler = RadarScheduler(db=db)
    scheduler.start(run_pipeline_immediately=run_immediately)

    # Initialize interactive Telegram bot listener if credentials configured
    bot = None
    if scheduler.settings.has_telegram:
        try:
            from app.alerts.bot import RadarTelegramBot
            bot = RadarTelegramBot(db=db)
            await bot.start()
        except Exception as e:
            logger.warning(f"Could not start Telegram Bot listener: {e}")

    # Initialize local Web Dashboard
    web_runner = None
    web_host = scheduler.settings.web_host
    web_port = scheduler.settings.web_port
    try:
        from app.web.server import run_web_server
        web_runner = await run_web_server(db=db, host=web_host, port=web_port)
    except Exception as e:
        logger.warning(f"Could not start Web Dashboard on {web_host}:{web_port}: {e}")

    print("\n" + "=" * 65)
    print("  WEB3 SECURITY RADAR -- AUTONOMOUS DAEMON ACTIVE")
    print("=" * 65)
    print(f"  Collection & Alerting cycle: Every {scheduler.settings.rss_collection_interval_minutes} minutes")
    print(f"  Daily Digest schedule:        Daily at {scheduler.settings.daily_digest_time} ({scheduler.settings.scheduler_timezone})")
    print(f"  Database path:               {scheduler.settings.database_full_path}")
    print(f"  Telegram alerts enabled:     {'YES' if scheduler.settings.has_telegram else 'NO'}")
    print(f"  Interactive Bot Commands:    {'ACTIVE (/ask, /poc, /watch, /security, /news)' if bot else 'OFF'}")
    print(f"  Auditor Web Dashboard:       {f'http://{web_host}:{web_port}' if web_runner else 'OFF'}")
    print(f"  Gemini AI enabled:           {'YES' if scheduler.settings.has_gemini else 'NO'}")
    print("\n  Press Ctrl+C to gracefully shut down the daemon.\n")

    if stop_event is None:
        stop_event = asyncio.Event()

    try:
        await stop_event.wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("Shutdown signal received.")
    finally:
        print("\nStopping daemon and cleaning up background tasks...")
        if bot:
            await bot.stop()
        if web_runner:
            await web_runner.cleanup()
        scheduler.shutdown(wait=False)
        print("[OK] Daemon shut down cleanly.")
