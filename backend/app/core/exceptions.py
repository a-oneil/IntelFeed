from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


class AppError(Exception):
    """Application-level error with code and details."""

    def __init__(self, code: str, message: str, status_code: int = 400, details: list | None = None):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or []


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}},
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {"field": ".".join(str(loc) for loc in err["loc"][1:]), "message": err["msg"], "code": err["type"]}
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=400,
        content={"error": {"code": "validation_error", "message": "Request validation failed", "details": details}},
    )


async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    code_map = {401: "unauthorized", 403: "forbidden", 404: "not_found", 429: "rate_limited"}
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": code_map.get(exc.status_code, "error"), "message": exc.detail, "details": []}},
    )
