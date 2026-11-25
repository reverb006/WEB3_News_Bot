"""
Unit tests for the Web Dashboard server and API routes.
"""

from __future__ import annotations

import pytest
from aiohttp.test_utils import TestClient, TestServer

from app.database.db import Database
from app.web.server import create_web_app


@pytest.mark.asyncio
async def test_web_dashboard_routes():
    db = Database(":memory:")
    await db.initialize()

    # Seed 1 test incident
    inc_id = await db.create_incident(
        title="Web Test Incident",
        protocol="TestProtocol",
        chain=["Ethereum"],
        attack_type=["REENTRANCY"],
        estimated_loss_usd=1_000_000.0,
        severity="HIGH",
        status="active",
    )

    app = create_web_app(db)
    client = TestClient(TestServer(app))
    await client.start_server()

    # 1. Main HTML
    resp_home = await client.get("/")
    assert resp_home.status == 200
    text_home = await resp_home.text()
    assert "WEB3 SECURITY RADAR" in text_home

    # 2. Stats API
    resp_stats = await client.get("/api/stats")
    assert resp_stats.status == 200
    data_stats = await resp_stats.json()
    assert data_stats["incidents_count"] == 1
    assert data_stats["total_loss_usd"] == 1_000_000.0

    # 3. Incidents API (with pagination & sorting)
    resp_inc = await client.get("/api/incidents?sort_by=loss&sort_order=desc&limit=25&page=1")
    assert resp_inc.status == 200
    data_inc = await resp_inc.json()
    assert len(data_inc["incidents"]) == 1
    assert data_inc["total_count"] == 1
    assert data_inc["page"] == 1
    assert data_inc["total_pages"] == 1
    assert data_inc["incidents"][0]["protocol"] == "TestProtocol"
    assert "date_formatted" in data_inc["incidents"][0]

    # 4. Incident Detail API
    resp_detail = await client.get(f"/api/incident/{inc_id}")
    assert resp_detail.status == 200
    data_detail = await resp_detail.json()
    assert data_detail["incident"]["id"] == inc_id

    # 5. Watchlist API (Add, List, Delete)
    resp_add = await client.post("/api/watchlist", json={"keyword": "flash loan"})
    assert resp_add.status == 200
    data_add = await resp_add.json()
    assert data_add["success"] is True

    resp_list = await client.get("/api/watchlist")
    assert resp_list.status == 200
    data_list = await resp_list.json()
    assert "flash loan" in data_list["keywords"]

    resp_del = await client.delete("/api/watchlist/flash%20loan")
    assert resp_del.status == 200
    data_del = await resp_del.json()
    assert data_del["success"] is True

    await client.close()
    await db.close()
