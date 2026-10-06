import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.future import select
from app.models.models import AIFeedbackRecord, Incident, Alert
from app.services.suppression_service import SuppressionService

class FeedbackService:
    """
    RLHF Active Learning Feedback Loop:
    - Ingests SOC Analyst verdicts (True/False Positive, Over-containment, Misclassified).
    - Automatically spawns dynamic suppression rules on False Positive verdicts.
    - Generates Few-Shot In-Context learning prompts for the AI Triage Engine.
    """

    @classmethod
    async def record_feedback(
        cls,
        incident_id: int,
        verdict: str,
        analyst_notes: str,
        reason_category: Optional[str] = None,
        corrected_severity: Optional[str] = None,
        auto_suppress_hours: Optional[int] = 24,
        created_by: str = "SOC Analyst",
        db=None
    ) -> Optional[AIFeedbackRecord]:
        if not incident_id or not verdict or not db:
            return None

        # Fetch incident details
        res = await db.execute(select(Incident).where(Incident.id == incident_id))
        inc = res.scalars().first()
        if not inc:
            return None

        clean_verdict = verdict.strip().lower()

        feedback = AIFeedbackRecord(
            incident_id=incident_id,
            analyst_verdict=clean_verdict,
            reason_category=reason_category or "general",
            analyst_notes=analyst_notes,
            original_summary=inc.summary,
            original_severity=inc.severity,
            corrected_severity=corrected_severity or inc.severity,
            created_by=created_by,
            created_at=datetime.datetime.utcnow()
        )
        db.add(feedback)

        # Update Incident metadata based on analyst verdict
        if clean_verdict == "false_positive":
            inc.status = "closed"
            inc.false_positive_score = 1.0
            inc.confidence_score = 0.1

            # Auto-create suppression rule if requested and incident has IOCs
            if auto_suppress_hours and auto_suppress_hours > 0:
                alt_res = await db.execute(select(Alert).where(Alert.incident_id == incident_id))
                first_alt = alt_res.scalars().first()
                if first_alt and first_alt.source_ip:
                    await SuppressionService.create_suppression_rule(
                        entity_type="ip",
                        entity_value=first_alt.source_ip,
                        reason=f"Auto-suppressed from False Positive verdict on {inc.incident_number}: {analyst_notes}",
                        duration_hours=auto_suppress_hours,
                        created_by=created_by,
                        db=db
                    )
        elif clean_verdict == "true_positive":
            inc.false_positive_score = 0.0
            inc.confidence_score = 1.0

        await db.commit()
        await db.refresh(feedback)
        return feedback

    @classmethod
    async def get_few_shot_prompt_context(
        cls,
        alert_dict: Dict[str, Any],
        limit: int = 3,
        db=None
    ) -> str:
        """
        Builds a Few-Shot In-Context Learning prompt snippet from past analyst feedback
        to guide LLM triage and prevent recurring misclassifications.
        """
        if not db:
            return ""

        stmt = select(AIFeedbackRecord).order_by(AIFeedbackRecord.created_at.desc()).limit(limit)
        res = await db.execute(stmt)
        records = res.scalars().all()

        if not records:
            return ""

        context_lines = [
            "### SOC ANALYST HISTORICAL FEEDBACK & RLHF LESSONS LEARNED (FEW-SHOT EXAMPLES):",
            "Review past SOC analyst verdicts on similar historical alerts to ensure accuracy:"
        ]

        for r in records:
            v_upper = r.analyst_verdict.upper()
            cat = r.reason_category or "Unspecified"
            notes = r.analyst_notes or "No notes provided"
            context_lines.append(
                f"- [VERDICT: {v_upper}] Category: '{cat}' | Analyst Correction: \"{notes}\""
            )

        context_lines.append(
            "CRITICAL INSTRUCTION: If the current alert exhibits similar characteristics to any of the above "
            "FALSE_POSITIVE examples, lower the false positive risk and confidence score accordingly.\n"
        )

        return "\n".join(context_lines)

    @classmethod
    async def list_feedbacks(cls, limit: int = 50, db=None) -> List[AIFeedbackRecord]:
        if not db:
            return []
        res = await db.execute(
            select(AIFeedbackRecord).order_by(AIFeedbackRecord.created_at.desc()).limit(limit)
        )
        return res.scalars().all()
