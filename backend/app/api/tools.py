"""Tool execution endpoint.

Exposes endpoints to execute any registered tool by name and list
available tools. Used by the IntelFeed CLI to interact with the platform.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import AGENT_SCOPE_PROPOSE, ToolCaller, get_tool_caller
from app.database import get_db
from app.tools import ADMIN_TOOLS, MUTATING_TOOLS, TOOL_DEFINITIONS, execute_tool
from app.tools.gate import auto_approve_tools, check_call, needs_confirmation, stage_tool_call, staged_reply

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
    caller: ToolCaller = Depends(get_tool_caller),
    db: AsyncSession = Depends(get_db),
):
    """Execute an agent tool by name and return the JSON result.

    Tools whose API equivalents are admin-gated require an admin caller —
    the registry must not be a side door around the API layer's gates. An
    agent token (an AI run acting for a user) runs read tools; a ``read`` one
    is refused anything that changes data, and a ``propose`` one gets that
    change staged for the user's click in the copilot instead of run (the
    same gate the in-process providers use, app.tools.gate). Neither may pass
    a confirmation token: those stand for the user's yes, not a model's.
    """
    user = caller.user
    name = request.tool_name
    if caller.is_agent:
        refusal = check_call(name, request.args, role=user.role, offered=None)
        if refusal:
            raise AppError(code="forbidden", message=refusal, status_code=403)
        if needs_confirmation(name):
            if caller.agent_scope == AGENT_SCOPE_PROPOSE:
                if name not in auto_approve_tools():
                    action_id = await stage_tool_call(
                        user_id=user.id,
                        conversation_id=caller.conversation_id,
                        tool_name=name,
                        args=request.args,
                        db=db,
                    )
                    return ToolExecuteResponse(result=staged_reply(action_id, name))
            elif name in MUTATING_TOOLS:
                # A read token keeps the storing reads (extractions) it always had.
                raise AppError(
                    code="forbidden",
                    message=f"Tool '{name}' changes data; this credential is read-only",
                    status_code=403,
                )
    if name in ADMIN_TOOLS and user.role != "admin":
        raise AppError(
            code="forbidden",
            message=f"Tool '{name}' requires admin access",
            status_code=403,
        )
    result = await execute_tool(name, request.args, db, user.id)
    return ToolExecuteResponse(result=result)


@router.get("/tools")
async def list_tools(caller: ToolCaller = Depends(get_tool_caller)):
    """Return all registered tool definitions (name, description, schema)."""
    return TOOL_DEFINITIONS
