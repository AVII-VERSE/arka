"""
Custom ARKA Application Exceptions.
"""

from typing import Any

from fastapi import HTTPException, status


class ARKAException(HTTPException):
    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: str = "ARKA_ERROR",
        extra: dict[str, Any] | None = None,
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.error_code = error_code
        self.extra = extra or {}


class TenantNotFoundException(ARKAException):
    def __init__(self, tenant_id: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{tenant_id}' not found.",
            error_code="TENANT_NOT_FOUND",
        )


class TenantAccessDeniedException(ARKAException):
    def __init__(self, tenant_id: str):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied to tenant '{tenant_id}'. Cross-tenant access forbidden.",
            error_code="TENANT_ACCESS_DENIED",
        )


class AuthenticationFailedException(ARKAException):
    def __init__(self, detail: str = "Invalid credentials or authentication token."):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code="AUTH_FAILED",
        )


class InsufficientPermissionsException(ARKAException):
    def __init__(self, required_role: str):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{required_role}' or higher is required to execute this operation.",
            error_code="INSUFFICIENT_PERMISSIONS",
        )


class RateLimitExceededException(ARKAException):
    def __init__(self, retry_after_seconds: int = 60):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please throttle your requests.",
            error_code="RATE_LIMIT_EXCEEDED",
            extra={"retry_after_seconds": retry_after_seconds},
        )
