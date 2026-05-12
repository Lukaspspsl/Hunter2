"""Hunter 2 LLM stack — client, prompts, tool caller, ReAct engine."""

from .client import LLMClient, LLMUnavailable
from .prompts import build_system_prompt, tool_registry_for_prompt
from .tool_caller import ToolCaller, ToolCallResult, ToolHandler
from .react_engine import ReActEngine, EscalationRequest

__all__ = [
    "LLMClient",
    "LLMUnavailable",
    "build_system_prompt",
    "tool_registry_for_prompt",
    "ToolCaller",
    "ToolCallResult",
    "ToolHandler",
    "ReActEngine",
    "EscalationRequest",
]
