"""Configuration for mac_forensics-mcp.

External tool paths can be configured via environment variables.
Falls back to sensible defaults if not set.
"""

import os
from pathlib import Path


def _get_tool_path(env_var: str, default: str) -> str:
    """Get tool path from environment variable or default.

    Args:
        env_var: Environment variable name
        default: Default path if env var not set

    Returns:
        Path to the tool
    """
    return os.environ.get(env_var, default)


# External tool paths - configurable via environment variables
# These defaults assume tools are installed in /opt/macOS/

FSEPARSER_PATH = _get_tool_path(
    "MAC_FORENSICS_FSEPARSER_PATH",
    "/opt/macOS/FSEventsParser/FSEParser_V4.1.py"
)

SPOTLIGHT_PARSER_PATH = _get_tool_path(
    "MAC_FORENSICS_SPOTLIGHT_PARSER_PATH",
    "/opt/macOS/spotlight_parser/spotlight_parser.py"
)

UNIFIEDLOG_ITERATOR_PATH = _get_tool_path(
    "MAC_FORENSICS_UNIFIEDLOG_ITERATOR_PATH",
    "/opt/macOS/unifiedlog_iterator"
)


def get_config() -> dict:
    """Get current configuration as dictionary."""
    return {
        "fseparser_path": FSEPARSER_PATH,
        "spotlight_parser_path": SPOTLIGHT_PARSER_PATH,
        "unifiedlog_iterator_path": UNIFIEDLOG_ITERATOR_PATH,
    }


def validate_tools() -> dict:
    """Validate that external tools exist.

    Returns:
        Dict with tool names and their availability status
    """
    tools = {
        "fseparser": Path(FSEPARSER_PATH).exists(),
        "spotlight_parser": Path(SPOTLIGHT_PARSER_PATH).exists(),
        "unifiedlog_iterator": Path(UNIFIEDLOG_ITERATOR_PATH).exists(),
    }
    return tools
