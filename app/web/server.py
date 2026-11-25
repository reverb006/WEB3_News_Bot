"""
Web Dashboard Server — High-performance async local dashboard for Web3 Security Radar.

Powered by aiohttp.web, providing:
- Real-time threat metrics & cumulative loss tracking
- Interactive Incident Explorer with severity filters
- In-browser Auditor Deep Analysis & Foundry PoC viewer
- Live VIP Watchlist manager
- Interactive In-Browser Auditor AI Q&A
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from aiohttp import web

from app.config.settings import get_settings
from app.database.db import Database
from app.processing.archive import SECURITY_ARCHIVE_PATH, NEWS_ARCHIVE_PATH

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = ROOT_DIR / "reports"
POCS_DIR = ROOT_DIR / "pocs"
HTML_PATH = Path(__file__).resolve().parent / "index.html"
DB_KEY = web.AppKey("db", Database)


def create_web_app(db: Database) -> web.Application:
    """Create and configure the aiohttp web application."""
    app = web.Application()
    app[DB_KEY] = db

    # Routes
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/stats", handle_api_stats)
    app.router.add_get("/api/incidents", handle_api_incidents)
    app.router.add_get("/api/incident/{id}", handle_api_incident_detail)
    app.router.add_get("/api/watchlist", handle_api_get_watchlist)
    app.router.add_post("/api/watchlist", handle_api_add_watchlist)
    app.router.add_delete("/api/watchlist/{keyword}", handle_api_delete_watchlist)
    app.router.add_post("/api/ask", handle_api_ask)
    app.router.add_get("/api/archive/{type}", handle_api_archive)

    return app


async def handle_index(request: web.Request) -> web.Response:
    """Serve the single-page dashboard HTML."""
    if not HTML_PATH.exists():
        return web.Response(text="Dashboard HTML template not found.", status=404)
    content = HTML_PATH.read_text(encoding="utf-8")
    return web.Response(text=content, content_type="text/html")


async def handle_api_stats(request: web.Request) -> web.Response:
    """Return pipeline and threat statistics."""
    db: Database = request.app[DB_KEY]

    total = await db.get_article_count()
    unclass = len(await db.get_unclassified_articles(limit=9999))
    classified = total - unclass

    # Incidents stats
    cursor = await db.conn.execute("SELECT COUNT(*), COALESCE(SUM(estimated_loss_usd), 0) FROM incidents")
    row = await cursor.fetchone()
    inc_count = row[0] if row else 0
    total_loss = row[1] if row else 0.0

    # Category breakdown
    cursor = await db.conn.execute(
        """
        SELECT category, COUNT(*) FROM articles
        WHERE classified_at IS NOT NULL
        GROUP BY category ORDER BY COUNT(*) DESC
        """
    )
    categories = dict(await cursor.fetchall())

    # Severity breakdown
    cursor = await db.conn.execute(
        """
        SELECT severity, COUNT(*) FROM incidents
        GROUP BY severity ORDER BY COUNT(*) DESC
        """
    )
    severities = dict(await cursor.fetchall())

    # Watchlist count
    keywords = await db.get_watchlist_keywords()

    # Source stats
    sources = await db.get_source_stats()

    return web.json_response({
        "total_articles": total,
        "classified": classified,
        "unclassified": unclass,
        "incidents_count": inc_count,
        "total_loss_usd": total_loss,
        "categories": categories,
        "severities": severities,
        "watchlist_count": len(keywords),
        "sources": sources,
    })


async def handle_api_incidents(request: web.Request) -> web.Response:
    """Return paginated and sorted list of incidents with filters."""
    db: Database = request.app[DB_KEY]

    # Query params
    sort_by = request.query.get("sort_by", "date").lower()
    sort_order = request.query.get("sort_order", "desc").lower()
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"

    severity = request.query.get("severity", "ALL").upper()
    search = request.query.get("search", "").strip()

    limit_param = request.query.get("limit", "50").lower()
    if limit_param in ("all", "0", "-1"):
        limit = None
    else:
        try:
            limit = max(1, int(limit_param))
        except ValueError:
            limit = 50

    try:
        page = max(1, int(request.query.get("page", "1")))
    except ValueError:
        page = 1

    # Build SQL WHERE conditions
    where_clauses = []
    params = []

    if severity != "ALL":
        where_clauses.append("i.severity = ?")
        params.append(severity)

    if search:
        search_pat = f"%{search}%"
        where_clauses.append(
            "(i.title LIKE ? OR i.protocol LIKE ? OR i.attack_type LIKE ? OR a.published_at LIKE ? OR i.first_seen_at LIKE ? OR a.url LIKE ?)"
        )
        params.extend([search_pat, search_pat, search_pat, search_pat, search_pat, search_pat])

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Count total matching
    count_sql = f"""
        SELECT COUNT(DISTINCT i.id)
        FROM incidents i
        LEFT JOIN articles a ON a.incident_id = i.id
        {where_sql}
    """
    cursor = await db.conn.execute(count_sql, tuple(params))
    total_count = (await cursor.fetchone())[0]

    # Determine ORDER BY
    if sort_by == "severity":
        order_sql = f"""
            CASE i.severity 
                WHEN 'CRITICAL' THEN 1 
                WHEN 'HIGH' THEN 2 
                WHEN 'MEDIUM' THEN 3 
                WHEN 'LOW' THEN 4 
                ELSE 5 
            END {sort_order.upper()}, COALESCE(i.estimated_loss_usd, 0) DESC
        """
    elif sort_by == "loss":
        order_sql = f"COALESCE(i.estimated_loss_usd, 0) {sort_order.upper()}, event_date DESC"
    elif sort_by == "id":
        order_sql = f"i.id {sort_order.upper()}"
    else:  # default "date"
        order_sql = f"event_date {sort_order.upper()}, i.id DESC"

    # Pagination logic
    pagination_sql = ""
    query_params = list(params)
    if limit is not None:
        offset = (page - 1) * limit
        pagination_sql = f"LIMIT {limit} OFFSET {offset}"
        total_pages = max(1, (total_count + limit - 1) // limit)
    else:
        total_pages = 1

    data_sql = f"""
        SELECT i.id, i.title, i.protocol, i.chain, i.attack_type, i.estimated_loss_usd,
               i.severity, i.status, i.article_count, 
               COALESCE(MIN(a.published_at), i.first_seen_at) as event_date,
               i.first_seen_at, i.last_updated_at,
               (i.deep_analysis IS NOT NULL) as has_analysis,
               MIN(a.url) as primary_url
        FROM incidents i
        LEFT JOIN articles a ON a.incident_id = i.id
        {where_sql}
        GROUP BY i.id
        ORDER BY {order_sql}
        {pagination_sql}
    """
    cursor = await db.conn.execute(data_sql, tuple(query_params))
    columns = [desc[0] for desc in cursor.description]
    rows = await cursor.fetchall()
    incidents = [dict(zip(columns, r)) for r in rows]

    # Check for Foundry PoCs on disk
    for inc in incidents:
        inc_id = inc["id"]
        proto = "".join(c for c in (inc.get("protocol") or "incident").lower() if c.isalnum() or c == "_")
        poc_file = POCS_DIR / f"PoC_Incident_{inc_id}_{proto}.t.sol"
        inc["has_poc"] = poc_file.exists()
        # Formatted event date YYYY-MM-DD
        raw_date = inc.get("event_date") or inc.get("first_seen_at") or ""
        inc["date_formatted"] = raw_date[:10] if len(raw_date) >= 10 else raw_date

    return web.json_response({
        "incidents": incidents,
        "total_count": total_count,
        "page": page,
        "limit": limit if limit is not None else total_count,
        "total_pages": total_pages,
    })


async def handle_api_incident_detail(request: web.Request) -> web.Response:
    """Return complete incident detail including report and PoC code."""
    db: Database = request.app[DB_KEY]
    try:
        inc_id = int(request.match_info["id"])
    except ValueError:
        return web.json_response({"error": "Invalid incident ID"}, status=400)

    inc = await db.get_incident(inc_id)
    if not inc:
        return web.json_response({"error": "Incident not found"}, status=404)

    articles = await db.get_incident_articles(inc_id)

    # Read markdown case study if exists
    proto = "".join(c for c in (inc.get("protocol") or "incident").lower() if c.isalnum() or c == "_")
    report_file = REPORTS_DIR / f"incident_{inc_id}_{proto}.md"
    report_text = report_file.read_text(encoding="utf-8") if report_file.exists() else None

    # Read Foundry PoC if exists
    poc_file = POCS_DIR / f"PoC_Incident_{inc_id}_{proto}.t.sol"
    poc_code = poc_file.read_text(encoding="utf-8") if poc_file.exists() else None

    primary_url = articles[0].get("url") if articles else None

    return web.json_response({
        "incident": inc,
        "articles": articles,
        "report_markdown": report_text,
        "poc_solidity": poc_code,
        "primary_url": primary_url,
    })


async def handle_api_get_watchlist(request: web.Request) -> web.Response:
    """Get active watchlist keywords."""
    db: Database = request.app[DB_KEY]
    keywords = await db.get_watchlist_keywords()
    return web.json_response({"keywords": keywords})


async def handle_api_add_watchlist(request: web.Request) -> web.Response:
    """Add keyword to watchlist."""
    db: Database = request.app[DB_KEY]
    try:
        data = await request.json()
        keyword = data.get("keyword", "").strip()
        if not keyword:
            return web.json_response({"error": "Keyword cannot be empty"}, status=400)
        success = await db.add_watchlist_keyword(keyword)
        return web.json_response({"success": success, "keyword": keyword})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)


async def handle_api_delete_watchlist(request: web.Request) -> web.Response:
    """Delete keyword from watchlist."""
    db: Database = request.app[DB_KEY]
    keyword = request.match_info["keyword"]
    success = await db.remove_watchlist_keyword(keyword)
    return web.json_response({"success": success, "keyword": keyword})


async def handle_api_ask(request: web.Request) -> web.Response:
    """Answer technical auditor question in the web UI."""
    db: Database = request.app[DB_KEY]
    try:
        data = await request.json()
        question = data.get("question", "").strip()
        if not question:
            return web.json_response({"error": "Question cannot be empty"}, status=400)

        from app.ai.qa import ask_auditor
        answer = await ask_auditor(question, db)
        return web.json_response({"answer": answer})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_api_archive(request: web.Request) -> web.Response:
    """Return raw text of security or news archive."""
    archive_type = request.match_info["type"].lower()
    if archive_type == "security":
        path = SECURITY_ARCHIVE_PATH
    elif archive_type == "news":
        path = NEWS_ARCHIVE_PATH
    else:
        return web.json_response({"error": "Unknown archive type"}, status=400)

    if not path.exists():
        return web.json_response({"error": "Archive file does not exist yet."}, status=404)

    return web.Response(text=path.read_text(encoding="utf-8"), content_type="text/markdown")


async def run_web_server(db: Database, host: str = "127.0.0.1", port: int = 8000) -> web.AppRunner:
    """Start the aiohttp web server runner."""
    app = create_web_app(db)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info(f"[OK] Web Dashboard active at http://{host}:{port}")
    return runner
