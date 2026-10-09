"""Normalized output models for the discovery stage (katana, gau, waybackurls, ffuf)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class CrawledURL(BaseModel):
    url: str
    method: str = "GET"
    source: str = "katana"
    status_code: Optional[int] = None
    content_type: Optional[str] = None


class HistoricalURL(BaseModel):
    url: str
    source: str  # "gau" or "waybackurls"
    status_code: Optional[int] = None


class DiscoveredPath(BaseModel):
    """A path found via active content/directory discovery (ffuf)."""

    url: str
    status_code: int
    content_length: Optional[int] = None
    words: Optional[int] = None
    lines: Optional[int] = None


class Parameter(BaseModel):
    name: str
    example_url: str
    source: str = "url_analysis"


class DiscoveryResult(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    target: str
    crawled_urls: list[CrawledURL] = Field(default_factory=list)
    historical_urls: list[HistoricalURL] = Field(default_factory=list)
    discovered_paths: list[DiscoveredPath] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    skipped_out_of_scope: list[str] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)
