import asyncio
import os
import re
from enum import StrEnum
from typing import Any, Literal, Optional

import httpx
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import ToolAnnotations

# Initialize FastMCP server
mcp = FastMCP("Kaspersky OpenTIP")

# Regex pattern for valid hash types (md5, sha1, sha256) and ips
hash_pattern = re.compile(r'^(0x)?(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$')
ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# Constants
OPENTIP_API_BASE = "https://opentip.kaspersky.com/api/v1/"
OPENTIP_API_KEY = os.getenv("OPENTIP_API_KEY")
OPENTIP_API_TIMEOUT = float(os.getenv("OPENTIP_API_TIMEOUT", 30.0))

if OPENTIP_API_KEY is None:
    raise KeyError("Please, set OPENTIP_API_KEY evnironment variable.")

RequestType = Literal["get", "post"]


class Endpoints(StrEnum):
    search_hash = "search/hash"
    search_ip = "search/ip"
    search_domain = "search/domain"
    search_url = "search/url"
    analyze_file = "scan/file"
    get_analysis_results = "getresult/file"


async def opentip_request(
    endpoint: str,
    request_type: RequestType = "get",
    params: Optional[dict[str, Any]] = None,
    content: Optional[bytes] = None,
    headers: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Make a request to the OpenTIP API with proper error handling."""
    headers = headers or {}
    headers = {
        "user-agent": "opentip-mcp-client",
        "x-api-key": OPENTIP_API_KEY,
        **headers
    }

    async with httpx.AsyncClient() as client:
        try:
            url = f"{OPENTIP_API_BASE}{endpoint}"
            if request_type == "get":
                response = await client.get(
                    url, headers=headers, params=params, timeout=OPENTIP_API_TIMEOUT
                )
            elif request_type == "post":
                response = await client.post(
                    url, headers=headers, params=params, content=content, timeout=OPENTIP_API_TIMEOUT
                )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                return {"result": "error", "error_message": "Invalid parameters. Please check your input and try again."}
            elif e.response.status_code == 401:
                return {"result": "error", "error_message": "Authentication failed. Please ensure that you have provided the correct credentials and try again."}
            elif e.response.status_code == 403:
                return {"result": "error", "error_message": "Quota or request limit exceeded. Check your quota and limits and try again."}
            else:
                return {"result": "error", "error_message": str(e)}
        except Exception as e:  # noqa
            return {"result": "error", "error_message": str(e)}


@mcp.tool(
    description="Get threat intelligence information about a file by hash (md5, sha1, sha256)",
    annotations=ToolAnnotations(
        title="Investigate a file by hash",
        readOnlyHint=True,
        openWorldHint=True,
    ),
)
async def search_hash(file_hash: str) -> dict[str, Any] | None:
    """Get threat intelligence information about a file by hash (md5, sha1, sha256)

    Args:
        file_hash: hash that you want to investigate
    """

    if not hash_pattern.match(file_hash):
        return {"result": "error", "error_message": "Invalid hash format. Please provide a valid md5, sha1, or sha256 hash."}

    params = {"request": file_hash}
    return await opentip_request(Endpoints.search_hash, "get", params)


@mcp.tool(
    description="Get threat intelligence data about a web domain",
    annotations=ToolAnnotations(
        title="Investigate a domain",
        readOnlyHint=True,
        openWorldHint=True,
    ),
)
async def search_domain(domain: str) -> dict[str, Any] | None:
    """Get threat intelligence data about a web domain

    Args:
        domain: domain that you want to investigate
    """
    params = {"request": domain}
    return await opentip_request(Endpoints.search_domain, "get", params)


@mcp.tool(
    description="Get threat intelligence data about an IP address",
    annotations=ToolAnnotations(
        title="Investigate an IP",
        readOnlyHint=True,
        openWorldHint=True,
    ),
)
async def search_ip(ip: str) -> dict[str, Any] | None:
    """Get threat intelligence data about an IP address

    Args:
        ip: IPv4 address that you want to investigate
    """

    if not ip_pattern.match(ip):
        return {"result": "error", "error_message": "Invalid IP address format. Please provide a valid IPv4 address."}

    params = {"request": ip}
    return await opentip_request(Endpoints.search_ip, "get", params)


@mcp.tool(
    description="Get threat intelligence data about a URL",
    annotations=ToolAnnotations(
        title="Investigate a URL",
        readOnlyHint=True,
        openWorldHint=True,
    ),
)
async def search_url(url: str) -> dict[str, Any] | None:
    """Get threat intelligence data about a URL

    Args:
        url: the web address that you want to investigate
    """
    params = {"request": url}
    return await opentip_request(Endpoints.search_url, "get", params)


@mcp.tool(
    description="Get full analysis results for a file that was submitted via the web portal.",
    annotations=ToolAnnotations(
        title="Get full analysis results for a file",
        readOnlyHint=True,
        openWorldHint=True,
    ),
)
async def get_full_analysis_result(file_hash: str) -> dict[str, Any] | None:
    """Get full analysis results for a file that was submitted via the web portal.

    Args:
        file_hash: The hash of the file that you want to get analysis results for.
    """
    params = {"request": file_hash}
    return await opentip_request(Endpoints.get_analysis_results, "post", params)


@mcp.tool(
    description="Submit a file for basic analysis using the OpenTIP API.",
    annotations=ToolAnnotations(
        title="Analyze a file by uploading it",
        readOnlyHint=False,
        openWorldHint=True,
    ),
)
async def analyze_file(filename: str, full_file_path: str) -> dict[str, Any] | None:
    """Submit a file for basic analysis using the OpenTIP API.

    Args:
        filename: The name of the file to analyze.
        full_file_path: The full path to the file on the local system.
    """
    params = {"filename": filename}
    headers = {
        "Content-Type": "application/octet-stream",
    }
    try:
        with open(full_file_path, "rb") as f:
            file_data = f.read()
        return await opentip_request(
            endpoint=Endpoints.analyze_file,
            request_type="post",
            params=params,
            content=file_data,
            headers=headers,
        )
    except Exception as e:  # noqa
        return {"result": "error", "error_message": str(e)}


if __name__ == "__main__":
    mcp.run(transport="stdio")
