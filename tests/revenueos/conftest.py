from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aicos.container import Container
from revenueos.email import Brand, OutboxMailer
from revenueos.service import RevenueOS

# Monday 2026-11-02 14:00 UTC == 09:00 America/New_York (inside send window)
MONDAY = datetime(2026, 11, 2, 14, 0, tzinfo=UTC)


@pytest.fixture
def brand() -> Brand:
    return Brand(
        company_name="Northwind Growth",
        physical_address="100 Main St, Suite 4, Austin, TX 78701",
        from_name="Dana Reyes",
        from_email="dana@northwind.example",
        reply_to="dana@northwind.example",
        phone="(512) 555-0100",
        booking_url="https://cal.example/dana",
        report_url="https://northwind.example/report",
        unsubscribe_base_url="https://api.northwind.example/u",
    )


@pytest.fixture
def mailer() -> OutboxMailer:
    return OutboxMailer()


@pytest.fixture
def rev(container: Container, mailer: OutboxMailer) -> RevenueOS:
    return RevenueOS(
        approvals=container.approvals,
        policy=container.policy,
        audit=container.audit,
        bus=container.bus,
        mailer=mailer,
        unsubscribe_key=b"u" * 32,
    )
