"""Shared Pydantic base classes.

Two bases, chosen by direction of travel:

* :class:`InputSchema` — anything parsed from a client. ``extra="forbid"`` is
  the mass-assignment defence: a payload carrying ``{"role": "admin"}`` for a
  model that does not declare ``role`` is rejected outright rather than
  silently ignored (or, worse, splatted onto an ORM object).
* :class:`OutputSchema` — anything serialised back out. Reads attributes off
  ORM instances, so responses are an explicit allow-list of fields.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class InputSchema(BaseModel):
    """Base for request payloads."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


class StrictInputSchema(InputSchema):
    """Input base for JSON APIs, where types should not be coerced.

    Not used for HTML form bodies: those arrive as strings and legitimately
    need coercion.
    """

    model_config = ConfigDict(strict=True)


class OutputSchema(BaseModel):
    """Base for responses."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")


class Page[T](OutputSchema):
    """A single page of results."""

    items: list[T]
    total: int
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total
