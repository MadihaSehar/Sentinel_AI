"""
SentinelAI - Phase 6: Response Intelligence Engine
Storage service.

Persists NormalizedRequest/Response pairs and ResponseComparison /
SecurityIndicator results via SQLAlchemy, and implements response
deduplication (Section 30: "Avoid scanning the same endpoint repeatedly" /
"deduplication") by body_hash.

This module is transport/DB-session agnostic: callers pass in a live
SQLAlchemy Session (sync here for simplicity; swap for AsyncSession in the
real FastAPI app without changing the public interface).
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.similarity import body_hash
from app.models.response_intel import (
    RequestRecord,
    ResponseComparisonRecord,
    ResponseRecord,
    SecurityIndicatorRecord,
)
from app.schemas.response_intel import (
    AnalyzedExchange,
    NormalizedRequest,
    NormalizedResponse,
)


class ResponseStore:
    def __init__(self, session: Session):
        self.session = session

    # -- writes -----------------------------------------------------------

    def save_request(self, req: NormalizedRequest) -> RequestRecord:
        record = RequestRecord(
            id=req.id,
            assessment_id=req.assessment_id,
            tool_run_id=req.tool_run_id,
            method=req.method.value,
            url=req.url,
            path=req.path,
            query_params=req.query_params,
            body_params=req.body_params,
            headers=req.headers,
            cookies=req.cookies,
            raw_body=req.raw_body,
        )
        self.session.add(record)
        return record

    def save_response(self, resp: NormalizedResponse) -> ResponseRecord:
        if not resp.body_hash:
            resp.body_hash = body_hash(resp.body)
        record = ResponseRecord(
            id=resp.id,
            request_id=resp.request_id,
            status_code=resp.status_code,
            headers=resp.headers,
            cookies=resp.cookies,
            content_type=resp.content_type,
            body=resp.body,
            body_hash=resp.body_hash,
            size_bytes=resp.size_bytes or len(resp.body or ""),
            elapsed_ms=resp.elapsed_ms,
            redirect_chain=resp.redirect_chain,
            auth_state=resp.auth_state.value,
        )
        self.session.add(record)
        return record

    def save_analyzed_exchange(
        self, assessment_id: UUID, exchange: AnalyzedExchange
    ) -> None:
        """Persist request, response, comparison (if any), and all
        security indicators derived for this exchange, atomically."""
        self.save_request(exchange.request)
        self.save_response(exchange.response)

        if exchange.comparison is not None:
            c = exchange.comparison
            self.session.add(
                ResponseComparisonRecord(
                    assessment_id=assessment_id,
                    baseline_response_id=c.baseline_response_id,
                    test_response_id=c.test_response_id,
                    status_code_match=c.status_code_match,
                    status_code_delta=c.status_code_delta,
                    length_delta=c.length_delta,
                    length_ratio=c.length_ratio,
                    text_similarity=c.text_similarity,
                    structural_similarity=c.structural_similarity,
                    timing_delta_ms=c.timing_delta_ms,
                    timing_significant=c.timing_significant,
                    header_diff=c.header_diff,
                    dom_diff=c.dom_diff.model_dump() if c.dom_diff else {},
                    error_signature_match=c.error_signature_match,
                )
            )

        for indicator in exchange.security_indicators:
            self.session.add(
                SecurityIndicatorRecord(
                    assessment_id=assessment_id,
                    response_id=exchange.response.id,
                    kind=indicator.kind,
                    description=indicator.description,
                    confidence_hint=indicator.confidence_hint,
                    evidence_refs=indicator.evidence_refs,
                )
            )

        self.session.commit()

    # -- dedup / reads ------------------------------------------------------

    def find_duplicate_response(
        self, assessment_id: UUID, candidate_hash: str
    ) -> ResponseRecord | None:
        """Return an existing response with the same body_hash for this
        assessment, if one exists -- used to skip redundant deep analysis
        of byte-identical pages (Section 30)."""
        stmt = (
            select(ResponseRecord)
            .join(RequestRecord, RequestRecord.id == ResponseRecord.request_id)
            .where(
                RequestRecord.assessment_id == assessment_id,
                ResponseRecord.body_hash == candidate_hash,
            )
            .limit(1)
        )
        return self.session.scalars(stmt).first()

    def get_response(self, response_id: UUID) -> ResponseRecord | None:
        return self.session.get(ResponseRecord, response_id)

    def get_indicators_for_response(
        self, response_id: UUID
    ) -> list[SecurityIndicatorRecord]:
        stmt = select(SecurityIndicatorRecord).where(
            SecurityIndicatorRecord.response_id == response_id
        )
        return list(self.session.scalars(stmt).all())
