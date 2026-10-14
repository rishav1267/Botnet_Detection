"""
Role-Based Access Control (RBAC) Enforcement Middleware & Guards
Enforces role hierarchies (admin, analyst, read_only) across all protected operations.
"""

from typing import Dict, Any, Tuple, Optional, List
from backend.middleware.auth import verify_jwt_token, check_permission, check_role, canonical_role
from backend.utils.response import api_error


class RBACGuard:
    """Provides authorization verification helpers for API controllers."""

    @staticmethod
    def extract_claims(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, Any]]:
        """Extract and verify JWT claims from headers."""
        if not headers:
            return None
        auth_hdr = headers.get("Authorization", headers.get("authorization", ""))
        return verify_jwt_token(auth_hdr)

    @staticmethod
    def require_authentication(headers: Optional[Dict[str, str]]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Tuple[int, Dict[str, Any]]]]:
        """
        Ensure caller has a valid, unexpired, non-revoked session token.
        Returns: (is_authorized, claims, error_response_tuple)
        """
        claims = RBACGuard.extract_claims(headers)
        if not claims:
            return False, None, (401, api_error(
                "Authentication required. Please provide a valid Bearer token in the Authorization header.",
                status_code=401,
                error_code="UNAUTHORIZED"
            ))
        return True, claims, None

    @staticmethod
    def require_role(
        headers: Optional[Dict[str, str]],
        allowed_roles: List[str]
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Tuple[int, Dict[str, Any]]]]:
        """
        Ensure caller belongs to one of the specified roles (e.g. ['admin', 'analyst']).
        """
        is_authed, claims, err = RBACGuard.require_authentication(headers)
        if not is_authed:
            return False, None, err

        if not check_role(claims, allowed_roles):
            user_role = canonical_role(claims.get("role", "read_only"))
            allowed_str = ", ".join(allowed_roles)
            return False, claims, (403, api_error(
                f"Access denied. Operation requires role in [{allowed_str}], but current role is '{user_role}'.",
                status_code=403,
                error_code="FORBIDDEN"
            ))

        return True, claims, None

    @staticmethod
    def require_permission(
        headers: Optional[Dict[str, str]],
        permission: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Tuple[int, Dict[str, Any]]]]:
        """
        Ensure caller has the specific functional permission.
        """
        is_authed, claims, err = RBACGuard.require_authentication(headers)
        if not is_authed:
            return False, None, err

        if not check_permission(claims, permission):
            return False, claims, (403, api_error(
                f"Access denied. Missing required permission: '{permission}'.",
                status_code=403,
                error_code="FORBIDDEN"
            ))

        return True, claims, None


# Singleton instance
rbac_guard = RBACGuard()
