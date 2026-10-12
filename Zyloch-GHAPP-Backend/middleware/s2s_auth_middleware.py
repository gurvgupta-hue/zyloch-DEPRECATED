"""Reject unauthenticated internal scan API requests."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from config.s2s_auth import path_requires_s2s_auth, verify_s2s_credential


class S2SAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        if not path_requires_s2s_auth(path, request.method):
            return await call_next(request)

        if not verify_s2s_credential(request):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        return await call_next(request)
