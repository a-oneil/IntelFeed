"""Tool execution endpoint.

Exposes endpoints to execute any registered tool by name and list
available tools. Used by the IntelFeed CLI to interact with the platform.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.user import User
from app.tools import ADMIN_TOOLS, TOOL_DEFINITIONS, execute_tool

router = APIRouter()


class ToolExecuteRequest(BaseModel):
    tool_name: str
    args: dict = {}

    model_config = ConfigDict(
        json_schema_extra={"example": {"tool_name": "search_entries", "args": {"query": "LockBit", "limit": 5}}}
    )


class ToolExecuteResponse(BaseModel):
    result: str


@router.post("/execute", response_model=ToolExecuteResponse)
async def execute_tool_endpoint(
    request: ToolExecuteRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute an agent tool by name and return the JSON result.

    Tools whose API equivalents are admin-gated require an admin caller —
    the registry must not be a side door around the API layer's gates.
    """
    if request.tool_name in ADMIN_TOOLS and user.role != "admin":
        raise AppError(
            code="forbidden",
            message=f"Tool '{request.tool_name}' requires admin access",
            status_code=403,
        )
    result = await execute_tool(request.tool_name, request.args, db, user.id)
    return ToolExecuteResponse(result=result)


@router.get("/tools")
async def list_tools(user: User = Depends(get_current_user)):
    """Return all registered tool definitions (name, description, schema)."""
    return TOOL_DEFINITIONS
