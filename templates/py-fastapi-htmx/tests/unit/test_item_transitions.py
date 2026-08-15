"""The item lifecycle state machine.

These rules are the reason the webhooks and audit domains can trust their
events: if an illegal or duplicate transition could slip through, partners would
receive webhooks — and the trail would record facts — for state changes that
never really happened.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import ItemStatusChanged
from app.core.exceptions import ValidationError
from app.domains.auth.models import User
from app.domains.items.models import Item, ItemStatus
from app.domains.items.service import change_status, selectable_statuses

LEGAL = [
    (ItemStatus.DRAFT, ItemStatus.ACTIVE),
    (ItemStatus.DRAFT, ItemStatus.ARCHIVED),
    (ItemStatus.ACTIVE, ItemStatus.ARCHIVED),
]

ILLEGAL = [
    (ItemStatus.ACTIVE, ItemStatus.DRAFT),
    (ItemStatus.ARCHIVED, ItemStatus.DRAFT),
    (ItemStatus.ARCHIVED, ItemStatus.ACTIVE),
]


async def _item_in(session: AsyncSession, owner: User, status: ItemStatus) -> Item:
    """Insert an item directly in ``status``, bypassing the transition rules."""
    row = Item(name="Test item", owner_id=owner.id, status=status)
    session.add(row)
    await session.flush()
    return row


@pytest.mark.parametrize(("start", "target"), LEGAL)
async def test_legal_transition_is_applied(
    db_session: AsyncSession,
    member_user: User,
    start: ItemStatus,
    target: ItemStatus,
) -> None:
    item = await _item_in(db_session, member_user, start)
    updated, events = await change_status(db_session, item.id, target, member_user)

    assert updated.status == target
    assert len(events) == 1


@pytest.mark.parametrize(("start", "target"), ILLEGAL)
async def test_illegal_transition_is_refused(
    db_session: AsyncSession,
    member_user: User,
    start: ItemStatus,
    target: ItemStatus,
) -> None:
    item = await _item_in(db_session, member_user, start)

    with pytest.raises(ValidationError):
        await change_status(db_session, item.id, target, member_user)


async def test_setting_the_current_status_is_a_no_op(
    db_session: AsyncSession,
    member_user: User,
) -> None:
    # A double-clicked Save button, or a retried request, must not fire a second
    # round of downstream work.
    item = await _item_in(db_session, member_user, ItemStatus.ACTIVE)
    _, events = await change_status(db_session, item.id, ItemStatus.ACTIVE, member_user)
    assert events == []


async def test_archiving_records_the_time_and_emits_one_event(
    db_session: AsyncSession,
    member_user: User,
) -> None:
    item = await _item_in(db_session, member_user, ItemStatus.ACTIVE)
    updated, events = await change_status(db_session, item.id, ItemStatus.ARCHIVED, member_user)

    assert updated.archived_at is not None
    assert len(events) == 1

    event = events[0]
    assert isinstance(event, ItemStatusChanged)
    assert event.item_id == item.id
    assert event.owner_id == member_user.id
    assert event.previous_status == "active"
    assert event.new_status == "archived"
    # The actor is the viewer that made the change, which is what lets the audit
    # trail answer "who did this?" without the service knowing about requests.
    assert event.actor_id == member_user.id


async def test_activating_does_not_set_archived_at(
    db_session: AsyncSession,
    member_user: User,
) -> None:
    item = await _item_in(db_session, member_user, ItemStatus.DRAFT)
    updated, _ = await change_status(db_session, item.id, ItemStatus.ACTIVE, member_user)
    assert updated.archived_at is None


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        (
            ItemStatus.DRAFT,
            [ItemStatus.DRAFT, ItemStatus.ACTIVE, ItemStatus.ARCHIVED],
        ),
        (ItemStatus.ACTIVE, [ItemStatus.ACTIVE, ItemStatus.ARCHIVED]),
        (ItemStatus.ARCHIVED, [ItemStatus.ARCHIVED]),
    ],
)
def test_selectable_statuses_matches_the_transition_table(
    current: ItemStatus,
    expected: list[ItemStatus],
) -> None:
    # The dropdown is generated from this, so a mismatch would let the UI offer
    # a move the server then rejects.
    assert selectable_statuses(current) == expected


def test_archived_is_the_only_terminal_status() -> None:
    assert ItemStatus.ARCHIVED.is_terminal
    assert not ItemStatus.DRAFT.is_terminal
    assert not ItemStatus.ACTIVE.is_terminal


def test_status_values_are_the_lowercase_wire_format() -> None:
    # These strings appear in URLs, webhook payloads and the Gherkin features,
    # so renaming one is a breaking change rather than a refactor.
    assert [status.value for status in ItemStatus] == ["draft", "active", "archived"]
