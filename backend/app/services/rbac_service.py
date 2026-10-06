import datetime
from typing import Dict, Any, Tuple, Optional

class RBACService:
    """
    Enterprise RBAC & Dual-Custody 4-Eyes Principle Service:
    - Enforces 4-tier role hierarchy (Tier-1 Analyst, Tier-2 Responder, Tier-3 Commander, SOC Admin).
    - Requires independent two-person sign-off (Dual-Custody) for destructive / high-impact actions.
    - Strictly prevents self-approval on high-impact actions.
    """

    ROLE_TIER1_ANALYST = "tier1_analyst"
    ROLE_TIER2_RESPONDER = "tier2_responder"
    ROLE_TIER3_COMMANDER = "tier3_commander"
    ROLE_SOC_ADMIN = "soc_admin"

    CRITICAL_ACTION_TYPES = {
        "isolate_endpoint",
        "isolate_wazuh_agent",
        "revoke_user_sessions",
        "disable_user_account",
        "kill_process"
    }

    CRITICAL_TARGET_PATTERNS = ["SRV-DC", "PROD", "FINANCE", "10.0.0.1"]

    @classmethod
    def is_dual_custody_required(
        cls,
        action_type: str,
        risk_level: str = "medium",
        target: str = "",
        parameters: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Determines whether an action warrants Dual-Custody (4-Eyes principle) approval.
        """
        clean_action = str(action_type or "").strip().lower()
        clean_risk = str(risk_level or "").strip().lower()
        clean_target = str(target or "").upper()

        if clean_risk == "critical":
            return True

        if clean_action in cls.CRITICAL_ACTION_TYPES:
            return True

        for pat in cls.CRITICAL_TARGET_PATTERNS:
            if pat in clean_target:
                return True

        return False

    @classmethod
    def check_approver_permission(
        cls,
        approver_role: str,
        action_type: str,
        risk_level: str = "medium",
        is_second_signature: bool = False
    ) -> Tuple[bool, str]:
        """
        Verifies whether the approver's role is authorized to sign off.
        """
        role = str(approver_role or "").strip().lower()

        if role == cls.ROLE_TIER1_ANALYST:
            return False, "Tier-1 Analyst has read/triage rights only and cannot approve containment actions."

        if is_second_signature:
            if role not in [cls.ROLE_TIER3_COMMANDER, cls.ROLE_SOC_ADMIN]:
                return False, "Dual-Custody second signature requires Tier-3 Commander or SOC Admin privilege."
            return True, "Authorized as Tier-3 / Admin counter-signer."

        if role in [cls.ROLE_TIER2_RESPONDER, cls.ROLE_TIER3_COMMANDER, cls.ROLE_SOC_ADMIN]:
            return True, "Authorized as primary signer."

        return False, f"Unknown or unauthorized role: '{approver_role}'"

    @classmethod
    def evaluate_dual_custody(
        cls,
        approval,
        approver: str,
        approver_role: str,
        decision: str
    ) -> Dict[str, Any]:
        """
        Evaluates the dual-custody state transition, enforcing the 4-eyes rule and anti-self-approval.
        """
        decision_clean = decision.strip().lower()

        # Reject immediately terminates workflow regardless of single/dual custody
        if decision_clean == "reject":
            return {
                "allowed": True,
                "is_final": True,
                "status": "rejected",
                "message": f"Action rejected by {approver} ({approver_role})."
            }

        if not approval.requires_dual_custody:
            # Single-custody action
            allowed, reason = cls.check_approver_permission(approver_role, approval.action_type, approval.risk_level)
            if not allowed:
                return {"allowed": False, "reason": reason}
            return {
                "allowed": True,
                "is_final": True,
                "status": "approved",
                "message": f"Single-custody approval granted by {approver}."
            }

        # Dual-Custody Flow
        now = datetime.datetime.utcnow()

        # Case 1: First signature
        if not approval.first_approver:
            allowed, reason = cls.check_approver_permission(
                approver_role, approval.action_type, approval.risk_level, is_second_signature=False
            )
            if not allowed:
                return {"allowed": False, "reason": reason}

            approval.first_approver = approver
            approval.first_approver_role = approver_role
            approval.first_approved_at = now
            approval.dual_custody_status = "awaiting_second_approval"

            return {
                "allowed": True,
                "is_final": False,
                "status": "pending",
                "dual_custody_status": "awaiting_second_approval",
                "message": (
                    f"First signature recorded by {approver} ({approver_role}). "
                    "Action is locked awaiting second signature from an independent Tier-3 Commander (4-Eyes Principle)."
                )
            }

        # Case 2: Second signature
        # Rule: Anti-Self-Approval check
        if approval.first_approver.strip().lower() == approver.strip().lower():
            return {
                "allowed": False,
                "reason": (
                    f"Self-approval prohibited! Approver '{approver}' cannot sign off on their own proposal. "
                    "A separate Tier-3 Commander must provide the second signature."
                )
            }

        allowed, reason = cls.check_approver_permission(
            approver_role, approval.action_type, approval.risk_level, is_second_signature=True
        )
        if not allowed:
            return {"allowed": False, "reason": reason}

        approval.second_approver = approver
        approval.second_approver_role = approver_role
        approval.second_approved_at = now
        approval.dual_custody_status = "fully_approved"

        return {
            "allowed": True,
            "is_final": True,
            "status": "approved",
            "dual_custody_status": "fully_approved",
            "message": (
                f"Dual-custody verification complete! Approved by primary signer '{approval.first_approver}' "
                f"and counter-signed by Tier-3 Commander '{approver}'."
            )
        }
