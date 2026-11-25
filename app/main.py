"""
Main entry point -- runs the Web3 Security Radar pipeline.

Commands:
    python -m app.main collect     # Fetch new articles from all sources
    python -m app.main classify    # Classify unclassified articles with Gemini
    python -m app.main pipeline    # Run collect + classify in sequence
    python -m app.main status      # Show database stats
    python -m app.main init-db     # Initialize database only

Usage:
    cd News-Feed
    python -m app.main pipeline
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.config.settings import get_settings, PROJECT_ROOT
from app.collectors.rss_collector import RSSCollector
from app.collectors.sources import get_active_sources
from app.database.db import Database


def setup_logging() -> None:
    """
    Configure logging to write to both console and file.

    Log format includes timestamp, level, logger name, and message.
    The log file rotates when you restart (appends, doesn't overwrite).
    """
    settings = get_settings()

    # Ensure log directory exists
    log_path = settings.log_full_path
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Create formatters
    detailed_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

    # File handler (all levels)
    file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
    file_handler.setFormatter(detailed_fmt)
    file_handler.setLevel(logging.DEBUG)

    # Console handler (INFO and above)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_fmt)
    console_handler.setLevel(logging.INFO)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Suppress verbose library warnings (e.g. AFC automatic function calling notice)
    import warnings
    warnings.filterwarnings("ignore", message=".*automatic function calling.*")
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", category=UserWarning, module="google.genai")

    # Quiet noisy libraries
    logging.getLogger("google").setLevel(logging.ERROR)
    logging.getLogger("google.genai").setLevel(logging.ERROR)
    logging.getLogger("google.genai.models").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.ERROR)
    logging.getLogger("httpcore").setLevel(logging.ERROR)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)


# ============================================================
# PHASE 1: Collection
# ============================================================

async def collect_all(db: Database) -> dict:
    """
    Run one full collection cycle across all active RSS sources.

    Returns a summary dict with counts of what happened.
    """
    logger = logging.getLogger("pipeline.collect")
    sources = get_active_sources(collector_type="rss")

    summary = {
        "sources_attempted": 0,
        "sources_succeeded": 0,
        "sources_failed": 0,
        "articles_collected": 0,
        "articles_new": 0,
        "articles_duplicate": 0,
    }

    for source_config in sources:
        summary["sources_attempted"] += 1
        collector = RSSCollector(source_config)

        try:
            # Ensure source exists in database
            source_id = await db.upsert_source(source_config)

            # Collect articles
            articles = await collector.collect()

            if not articles:
                await db.update_source_fetch_status(
                    source_config.name, error="No articles returned"
                )
                summary["sources_failed"] += 1
                continue

            # Store each article (skip duplicates)
            new_count = 0
            dup_count = 0
            for article in articles:
                if await db.article_exists(article.url):
                    dup_count += 1
                    continue

                try:
                    await db.insert_article(article, source_id)
                    new_count += 1
                except Exception as e:
                    logger.warning(f"Failed to insert article {article.url}: {e}")
                    dup_count += 1

            summary["articles_collected"] += len(articles)
            summary["articles_new"] += new_count
            summary["articles_duplicate"] += dup_count
            summary["sources_succeeded"] += 1

            await db.update_source_fetch_status(source_config.name)
            logger.info(
                f"[OK] {source_config.name}: {new_count} new, {dup_count} duplicates"
            )

        except Exception as e:
            summary["sources_failed"] += 1
            logger.error(f"[FAIL] {source_config.name} failed: {e}")
            await db.update_source_fetch_status(source_config.name, error=str(e))

    return summary


# ============================================================
# PHASE 2: Classification
# ============================================================

async def classify_all(db: Database, limit: int = 20) -> dict:
    """
    Classify unclassified articles using Gemini AI.

    Fetches articles without classifications from the DB, sends each
    to Gemini for analysis, then stores the results back.

    Returns a summary dict.
    """
    logger = logging.getLogger("pipeline.classify")

    # Lazy import — only load Gemini code when actually classifying
    from app.ai.classifier import GeminiClassifier
    from app.processing.priority import compute_priority

    settings = get_settings()
    if not settings.has_gemini:
        logger.error("Gemini API key not configured. Set GEMINI_API_KEY in .env")
        return {"error": "No Gemini API key", "classified": 0, "failed": 0, "skipped": 0}

    # Get unclassified articles
    articles = await db.get_unclassified_articles(limit=limit)
    if not articles:
        logger.info("No unclassified articles found")
        return {"classified": 0, "failed": 0, "skipped": 0}

    logger.info(f"Classifying {len(articles)} unclassified articles (limit={limit})")

    # Initialize the classifier
    classifier = GeminiClassifier()

    summary = {"classified": 0, "failed": 0, "skipped": 0}

    for i, article in enumerate(articles, 1):
        title = article["title"]
        logger.info(f"[{i}/{len(articles)}] Classifying: {title[:70]}")

        try:
            # Send to Gemini
            classification = await classifier.classify(
                title=title,
                content=article.get("content", ""),
                source_type=article.get("source_type", "UNKNOWN"),
                source_name=article.get("source_name", ""),
            )

            if classification is None:
                logger.warning(f"  -> Classification returned None, skipping")
                summary["failed"] += 1
                continue

            # Compute priority score
            source_reliability = article.get("reliability_score", 50)
            priority = compute_priority(classification, source_reliability)

            # Store results in database
            raw_json = classifier.get_raw_response(classification)
            await db.update_article_classification(
                article_id=article["id"],
                classification=classification,
                priority_score=priority,
                raw_response=raw_json,
            )

            summary["classified"] += 1

            # Log the result with a readable summary
            cat = classification.category.value
            sev = classification.severity.value
            loss = classification.estimated_loss_usd
            loss_txt = f" | Loss: ${loss:,.0f}" if loss else ""
            proto = f" [{classification.protocol}]" if classification.protocol else ""
            logger.info(
                f"  [OK] {cat} | Priority: {priority}/100 | Severity: {sev}{proto}{loss_txt}"
            )

            # Deduplication & Incident Merging (Phase 4)
            from app.processing.deduplication import IncidentManager
            incident_mgr = IncidentManager()
            incident_id, is_new_incident = await incident_mgr.process_and_link(
                db=db,
                article_id=article["id"],
                title=title,
                classification=classification,
            )

            # Prepare article payload with classification fields
            article_payload = dict(article)
            article_payload.update({
                "summary": classification.summary,
                "category": classification.category.value,
                "severity": classification.severity.value,
                "security_relevance": classification.security_relevance,
                "priority_score": priority,
                "protocol": classification.protocol,
                "attack_type": [at.value for at in classification.attack_type],
                "estimated_loss_usd": classification.estimated_loss_usd,
                "chain": classification.chain,
                "incident_id": incident_id,
            })

            # Append to Dual Knowledge Archive (Phase 6)
            from app.processing.archive import ArchiveManager
            archive_mgr = ArchiveManager()
            archive_mgr.archive_article(article_payload, classification)

            # Check if this qualifies for a real-time Telegram alert
            # Suppress alert if already alerted for this incident or article is > alert_max_age_hours old
            from app.processing.deduplication import is_article_fresh
            max_age_hours = getattr(settings, "alert_max_age_hours", 400)
            is_fresh = is_article_fresh(article.get("published_at"), max_age_hours=max_age_hours)

            should_alert_incident = await incident_mgr.should_dispatch_alert(
                db=db,
                incident_id=incident_id,
                priority_score=priority,
                should_alert=classification.should_alert,
                published_at=article.get("published_at"),
                max_age_hours=max_age_hours,
            )

            # Check for Major Web3 News alert (fresh within max_age_hours and priority >= 20)
            is_major_news = classification.category.value in ("MAJOR_WEB3_NEWS", "PROTOCOL_UPDATE") and priority >= 20
            already_alerted_art = await db.has_alert_been_sent(article["id"])
            should_alert_news = is_major_news and is_fresh and not already_alerted_art

            # Check for VIP Watchlist Match (fresh within max_age_hours)
            watch_text = f"{title} {classification.protocol or ''} {classification.summary or ''}"
            matched_keyword = await db.check_watchlist_match(watch_text)
            should_alert_watchlist = bool(matched_keyword and is_fresh and not already_alerted_art)

            if matched_keyword:
                article_payload["summary"] = f"🎯 [WATCHLIST MATCH: {matched_keyword.upper()}] " + article_payload.get("summary", "")

            if (should_alert_incident or should_alert_news or should_alert_watchlist) and settings.has_telegram:
                from app.alerts.telegram import TelegramAlertManager
                alert_mgr = TelegramAlertManager()
                alert_sent = await alert_mgr.send_article_alert(article_payload, db)
                if alert_sent:
                    if should_alert_watchlist:
                        alert_type_tag = f"VIP Watchlist ({matched_keyword})"
                    elif should_alert_incident:
                        alert_type_tag = "Security Exploit"
                    else:
                        alert_type_tag = "Major Web3 News"
                    logger.info(f"  [ALERT] Real-time Telegram alert delivered! ({alert_type_tag} #{incident_id})")
                    summary["alerts_sent"] = summary.get("alerts_sent", 0) + 1

            # Deep Analysis (Phase 5)
            # If priority >= 80 or CRITICAL exploit, automatically trigger deep auditor analysis & Foundry PoC
            if priority >= 80 or classification.category.value == "CRITICAL_SECURITY":
                from app.ai.analyzer import run_incident_deep_analysis
                logger.info(f"  [ANALYSIS] Critical exploit detected! Generating Deep Auditor Case Study...")
                await asyncio.sleep(4.0)  # Brief breathing window for API rate limits
                # Only notify Telegram if this incident is fresh (< 48h)
                report_path = await run_incident_deep_analysis(
                    incident_id, db, send_telegram=(settings.has_telegram and is_fresh)
                )
                if report_path:
                    logger.info(f"  [SAVED] Deep Case Study saved: {report_path.name}")
                    summary["deep_analyses"] = summary.get("deep_analyses", 0) + 1

                # Auto-generate Foundry PoC test skeleton
                try:
                    from app.ai.poc_generator import generate_foundry_poc
                    poc_path = await generate_foundry_poc(incident_id, db)
                    if poc_path:
                        logger.info(f"  [POC] Foundry PoC test skeleton saved: {poc_path.name}")
                except Exception as e:
                    logger.warning(f"Could not auto-generate Foundry PoC: {e}")

        except Exception as e:
            err_short = str(e).split("\n")[0][:80]
            logger.warning(f"  [SKIP] Could not classify article {article.get('id')}: {err_short}")
            summary["failed"] += 1


    return summary



# ============================================================
# Status Display
# ============================================================

async def show_status(db: Database) -> None:
    """Print database statistics to the console."""
    total = await db.get_article_count()
    stats = await db.get_source_stats()

    # Count classified vs unclassified
    unclassified = await db.get_unclassified_articles(limit=9999)
    classified_count = total - len(unclassified)

    print("\n" + "=" * 65)
    print("  WEB3 SECURITY RADAR -- STATUS")
    print("=" * 65)
    print(f"\n  Total articles:  {total}")
    print(f"  Classified:      {classified_count}")
    print(f"  Unclassified:    {len(unclassified)}")
    print(f"\n  {'Source':<25} {'Type':<20} {'Articles':>8}  Last Fetched")
    print("  " + "-" * 75)

    for s in stats:
        last = s["last_fetched_at"] or "never"
        if len(last) > 19:
            last = last[:19]  # Trim microseconds
        error = f" [!] {s['last_error']}" if s["last_error"] else ""
        print(
            f"  {s['name']:<25} {s['source_type']:<20} {s['article_count']:>8}  {last}{error}"
        )

    # Show classification breakdown if we have classified articles
    if classified_count > 0:
        print(f"\n  --- Classification Breakdown ---")
        cursor = await db.conn.execute(
            """
            SELECT category, COUNT(*) as cnt
            FROM articles
            WHERE classified_at IS NOT NULL
            GROUP BY category
            ORDER BY cnt DESC
            """
        )
        rows = await cursor.fetchall()
        for cat, cnt in rows:
            bar = "#" * min(cnt, 40)
            print(f"  {cat or 'NULL':<25} {cnt:>4}  {bar}")

        # Top priority articles
        print(f"\n  --- Top 10 Priority Articles ---")
        cursor = await db.conn.execute(
            """
            SELECT title, category, severity, priority_score, protocol
            FROM articles
            WHERE classified_at IS NOT NULL
            ORDER BY priority_score DESC
            LIMIT 10
            """
        )
        rows = await cursor.fetchall()
        for title, cat, sev, prio, proto in rows:
            proto_str = f" [{proto}]" if proto else ""
            print(f"  {prio:>3}  {cat:<20} {title[:55]}{proto_str}")

        # Incidents & Deduplication stats
        cursor = await db.conn.execute("SELECT COUNT(*), SUM(article_count > 1) FROM incidents")
        row = await cursor.fetchone()
        total_inc = row[0] or 0
        multi_source_inc = row[1] or 0
        if total_inc > 0:
            print(f"\n  --- Unique Incidents Tracked: {total_inc} ({multi_source_inc} multi-source corroborated) ---")
            cursor = await db.conn.execute(
                """
                SELECT id, title, protocol, article_count, estimated_loss_usd
                FROM incidents
                ORDER BY article_count DESC, id DESC
                LIMIT 5
                """
            )
            rows = await cursor.fetchall()
            for inc_id, inc_title, inc_proto, cnt, inc_loss in rows:
                loss_str = f" (${inc_loss:,.0f})" if inc_loss else ""
                proto_str = f" [{inc_proto}]" if inc_proto else ""
                print(f"  #{inc_id:<3} ({cnt} sources) {inc_title[:50]}{proto_str}{loss_str}")

    print()


# ============================================================
# Main Entry
# ============================================================

async def async_main(command: str, extra_args: list[str] = None) -> None:
    """Main async entry point."""
    settings = get_settings()
    db = Database(settings.database_full_path)

    try:
        await db.initialize()

        if command == "init-db":
            print(f"[OK] Database initialized at {settings.database_full_path}")

        elif command == "collect":
            print(f"\nStarting collection cycle at {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}...\n")
            summary = await collect_all(db)
            print(f"\n{'=' * 50}")
            print(f"  Collection Complete")
            print(f"{'=' * 50}")
            print(f"  Sources: {summary['sources_succeeded']}/{summary['sources_attempted']} succeeded")
            print(f"  Articles: {summary['articles_new']} new, {summary['articles_duplicate']} duplicates")
            if summary["sources_failed"] > 0:
                print(f"  WARNING: {summary['sources_failed']} source(s) failed -- check logs")
            print()

        elif command == "classify":
            limit = 20
            if extra_args:
                if extra_args[0].lower() == "all":
                    limit = 9999
                elif extra_args[0].isdigit():
                    limit = int(extra_args[0])

            print(f"\nStarting classification (limit={limit})...\n")
            summary = await classify_all(db, limit=limit)
            print(f"\n{'=' * 50}")
            print(f"  Classification Complete")
            print(f"{'=' * 50}")
            print(f"  Classified: {summary['classified']}")
            print(f"  Failed:     {summary['failed']}")
            if summary.get("error"):
                print(f"  Error:      {summary['error']}")
            print()

        elif command == "pipeline":
            # Run both collect + classify in sequence
            print(f"\n--- PHASE 1: Collection ---\n")
            collect_summary = await collect_all(db)
            print(f"  => {collect_summary['articles_new']} new articles collected\n")

            print(f"--- PHASE 2: Classification ---\n")
            classify_summary = await classify_all(db, limit=20)
            print(f"  => {classify_summary['classified']} articles classified\n")

            print(f"{'=' * 50}")
            print(f"  Pipeline Complete")
            print(f"{'=' * 50}")
            print(f"  New articles:   {collect_summary['articles_new']}")
            print(f"  Classified:     {classify_summary['classified']}")
            print(f"  Failed:         {classify_summary['failed']}")
            print()

        elif command == "status":
            await show_status(db)

        elif command == "alert-test":
            from app.alerts.telegram import TelegramAlertManager, format_alert_message
            alert_mgr = TelegramAlertManager()
            if not alert_mgr.is_configured:
                print("[!] Telegram is not configured in .env (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID required)")
                return

            print("Sending sample critical security alert to Telegram...")
            sample_article = {
                "id": 999999,
                "title": "Curve Finance Exploited for $60M via Vyper Reentrancy Lock Vulnerability",
                "url": "https://hackmd.io/@vyperlang/curve-reentrancy-postmortem",
                "category": "CRITICAL_SECURITY",
                "severity": "CRITICAL",
                "priority_score": 95,
                "protocol": "Curve Finance",
                "estimated_loss_usd": 60_000_000.0,
                "attack_type": '["REENTRANCY", "COMPILER_BUG"]',
                "chain": '["Ethereum", "Arbitrum"]',
                "summary": "Attacker exploited a malfunction in the @nonreentrant decorator in older Vyper compiler versions (0.2.15, 0.2.16, 0.3.0), allowing reentrancy across multiple Curve liquidity pools.",
                "source_name": "PeckShield & Vyper Team",
            }
            msg = format_alert_message(sample_article)
            msg_id = await alert_mgr.send_message(msg)
            if msg_id:
                print(f"[OK] Test alert sent successfully! (Telegram Message ID: {msg_id})")
                print("Check your Telegram to see the live alert card.")
            else:
                print("[ERROR] Failed to send Telegram alert. Check logs for details.")

        elif command == "dispatch-alerts":
            from app.alerts.telegram import TelegramAlertManager
            alert_mgr = TelegramAlertManager()
            if not alert_mgr.is_configured:
                print("[!] Telegram is not configured in .env")
                return

            min_prio = 70
            if extra_args and extra_args[0].isdigit():
                min_prio = int(extra_args[0])

            print(f"Scanning for unalerted articles with priority >= {min_prio}...")
            res = await alert_mgr.dispatch_pending_alerts(db, min_priority=min_prio)
            print(f"[OK] Alerts dispatch complete: {res['sent']} sent, {res['failed']} failed (out of {res['total_pending']} pending)")

        elif command == "analyze":
            from app.ai.analyzer import run_incident_deep_analysis
            target_inc_id = None
            if extra_args and extra_args[0].isdigit():
                target_inc_id = int(extra_args[0])
            else:
                # Find the latest unanalyzed incident
                cursor = await db.conn.execute(
                    """
                    SELECT id, title, protocol FROM incidents
                    WHERE deep_analysis IS NULL
                    ORDER BY id DESC LIMIT 1
                    """
                )
                row = await cursor.fetchone()
                if row:
                    target_inc_id = row[0]
                    print(f"Targeting Incident #{target_inc_id}: {row[1]}")
                else:
                    print("No unanalyzed incidents found in database.")
                    return

            print(f"Running deep auditor analysis on Incident #{target_inc_id}...")
            report_path = await run_incident_deep_analysis(target_inc_id, db, send_telegram=True)
            if report_path:
                print(f"\n[OK] Deep analysis complete! Report saved to:\n  {report_path}")
                print("Check your Telegram for the Auditor Briefing card.")
            else:
                print("\n[ERROR] Deep analysis failed. Check logs for details.")

        elif command == "poc":
            from app.ai.poc_generator import generate_foundry_poc
            target_inc_id = None
            if extra_args and extra_args[0].isdigit():
                target_inc_id = int(extra_args[0])
            else:
                cursor = await db.conn.execute(
                    "SELECT id, title, protocol FROM incidents WHERE severity IN ('CRITICAL', 'HIGH') ORDER BY id DESC LIMIT 1"
                )
                row = await cursor.fetchone()
                if row:
                    target_inc_id = row[0]
                    print(f"Targeting Incident #{target_inc_id}: {row[1]}")
                else:
                    print("No high/critical incidents found.")
                    return
            print(f"Generating Foundry PoC test for Incident #{target_inc_id}...")
            poc_path = await generate_foundry_poc(target_inc_id, db)
            if poc_path:
                print(f"\n[OK] Foundry PoC test skeleton saved to:\n  {poc_path}")
            else:
                print("\n[ERROR] PoC generation failed.")

        elif command == "ask":
            from app.ai.qa import ask_auditor
            query = " ".join(extra_args)
            if not query.strip():
                print("Usage: python -m app.main ask <your auditor question>")
                return
            print(f"Querying Auditor AI: {query}\n...")
            answer = await ask_auditor(query, db)
            print(f"\n--- AUDITOR ANSWER ---\n{answer}\n")

        elif command == "digest":
            import re
            from app.digest.daily import run_daily_digest
            target_date = None
            force = False
            send_telegram = True

            if extra_args:
                for arg in extra_args:
                    if arg == "--force":
                        force = True
                    elif arg == "--no-telegram":
                        send_telegram = False
                    elif re.match(r"^\d{4}-\d{2}-\d{2}$", arg):
                        target_date = arg

            print(f"Generating Daily Security Digest for date: {target_date or 'latest'} (force={force}, telegram={send_telegram})...")
            report_path, telegram_ids = await run_daily_digest(
                db=db,
                target_date=target_date,
                send_telegram=send_telegram,
                force=force,
            )

            if report_path:
                print(f"\n[OK] Daily Digest generated successfully!")
                print(f"  Markdown report: {report_path}")
                if telegram_ids:
                    print(f"  Telegram: {len(telegram_ids)} message(s) dispatched (IDs: {telegram_ids})")
                else:
                    print("  Telegram: No messages sent (or already sent / disabled).")
            else:
                print(f"\n[INFO] Daily digest was not generated (may have already been sent for this date). Use --force to re-generate.")

        elif command == "backfill-archives":
            from app.processing.archive import ArchiveManager
            archive_mgr = ArchiveManager()
            print("Backfilling and synchronizing dual knowledge archives from database...")
            res = await archive_mgr.backfill_archives(db)
            print("\n[OK] Archive synchronization complete!")
            print(f"  Security Archive: {res['security_count']} incidents -> {res['security_file']}")
            print(f"  News Archive:     {res['news_count']} articles  -> {res['news_file']}")
            print(f"  Total Archived:   {res['total']} items")

        elif command == "backfill-history":
            from app.processing.historical import HistoricalBackfillManager
            mgr = HistoricalBackfillManager(db=db)
            print("Importing 800+ historical Web3 exploits (2020-2026) from curated security archives...")
            res = await mgr.run_backfill()
            print("\n[OK] Historical backfill complete!")
            print(f"  Parsed Incidents:       {res['total_parsed']}")
            print(f"  New Articles Stored:    {res['inserted_articles']}")
            print(f"  New Incidents Created:  {res['inserted_incidents']}")
            print(f"  Total Security Archive: {res['archive_security_count']}")

        elif command == "bot":
            from app.alerts.bot import RadarTelegramBot
            bot = RadarTelegramBot(db=db)
            print("Starting Telegram Bot listener... Press Ctrl+C to stop.")
            await bot.start()
            stop_evt = asyncio.Event()
            try:
                await stop_evt.wait()
            except (asyncio.CancelledError, KeyboardInterrupt):
                pass
            finally:
                await bot.stop()
                print("\n[OK] Bot stopped.")

        elif command == "web":
            from app.web.server import run_web_server
            host = settings.web_host
            port = settings.web_port
            if extra_args and extra_args[0].isdigit():
                port = int(extra_args[0])
            print(f"Starting Web Dashboard at http://{host}:{port}... Press Ctrl+C to stop.")
            runner = await run_web_server(db=db, host=host, port=port)
            stop_evt = asyncio.Event()
            try:
                await stop_evt.wait()
            except (asyncio.CancelledError, KeyboardInterrupt):
                pass
            finally:
                await runner.cleanup()
                print("\n[OK] Web Dashboard stopped.")

        elif command == "daemon":
            from app.scheduler import run_daemon
            skip_initial = False
            if extra_args and "--skip-initial" in extra_args:
                skip_initial = True
            await run_daemon(db=db, run_immediately=not skip_initial)

        else:
            print(f"Unknown command: {command}")
            print(
                "Usage: python -m app.main [collect|classify [N|all]|pipeline|status|"
                "analyze [ID]|poc [ID]|ask <QUERY>|digest [YYYY-MM-DD]|"
                "backfill-archives|backfill-history|bot|web [PORT]|daemon|"
                "alert-test|dispatch-alerts|init-db]"
            )
            sys.exit(1)

    finally:
        await db.close()


def main() -> None:
    """CLI entry point."""
    setup_logging()

    if len(sys.argv) < 2:
        print("Web3 Security Radar v0.2.0")
        print()
        print("Usage: python -m app.main <command> [options]")
        print()
        print("Commands:")
        print("  collect            Fetch new articles from all RSS sources")
        print("  classify [N]       Classify N unclassified articles (default 20, or 'all')")
        print("  pipeline           Run collect + classify in sequence")
        print("  status             Show database statistics + classification breakdown")
        print("  analyze [ID]       Generate deep auditor case study for an incident")
        print("  poc [ID]           Generate runnable Foundry PoC test skeleton")
        print("  ask <QUERY>        Ask Auditor AI technical questions with local DB context")
        print("  digest [DATE]      Generate daily intelligence digest (Markdown + Telegram)")
        print("  backfill-archives  Backfill dual knowledge archives (security & news)")
        print("  backfill-history   Import 800+ historical Web3 exploits (2020-2026)")
        print("  bot                Run interactive Telegram bot command listener")
        print("  web [PORT]         Run local Web Dashboard (default port 8000)")
        print("  daemon             Run autonomous 24/7 scheduler (15-min cycles + daily digest)")
        print("  alert-test         Send a sample critical DeFi exploit alert to Telegram")
        print("  dispatch-alerts    Send pending unalerted critical incidents to Telegram")
        print("  init-db            Initialize the database schema")
        print()
        sys.exit(0)

    command = sys.argv[1].lower()
    extra_args = sys.argv[2:]
    asyncio.run(async_main(command, extra_args))


if __name__ == "__main__":
    main()

