"""Normalized output models for the reconnaissance stage (subfinder, dnsx, httpx, naabu)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Subdomain(BaseModel):
    hostname: str
    source_tool: str


class DNSRecord(BaseModel):
    hostname: str
    record_type: str  # A, AAAA, CNAME, MX, NS, TXT...
    value: str


class HTTPService(BaseModel):
    url: str
    hostname: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: list[str] = Field(default_factory=list)
    content_length: Optional[int] = None
    webserver: Optional[str] = None


class OpenPort(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"


class ReconResult(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    target: str
    subdomains: list[Subdomain] = Field(default_factory=list)
    dns_records: list[DNSRecord] = Field(default_factory=list)
    http_services: list[HTTPService] = Field(default_factory=list)
    open_ports: list[OpenPort] = Field(default_factory=list)
    skipped_out_of_scope: list[str] = Field(
        default_factory=list, description="Hosts/IPs discovered but denied by the Scope Engine"
    )
    tool_errors: list[str] = Field(default_factory=list)
