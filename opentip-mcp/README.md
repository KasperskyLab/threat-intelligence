# Kaspersky OpenTIP Model Context Protocol Server

This server gives access to [Kaspersky OpenTIP API](https://opentip.kaspersky.com/Help/Doc_data/WorkingWithAPI.htm) to agentic applications that support [Model Context Protocol (MCP)](http://modelcontextprotocol.io/), such as Claude or Cline.

## Installation

First, install uv:

```
# windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

You can also install uv from [Github](https://github.com/astral-sh/uv/releases).

Second, clone this repo.

Finally, configure your client. For Claude:

```
{
    "mcpServers": {
        "Kaspersky OpenTIP": {
            "command": "uv",
            "args": [
                "--directory",
                "C:/path/to/repo/opentip-mcp",
                "run",
                "opentip.py"
            ],
            "env": {
              "OPENTIP_API_KEY": "YOUR_API_KEY"
            }
        }
    }
}
```

For Cline (on Windows):
```
{
  "mcpServers": {
    "KasperskyOpenTIP": {
      "command": "cmd",
      "args": [
        "/c",
        "uv",
        "--directory",
        "C:/path/to/repo/opentip-mcp",
        "run",
        "opentip.py"
      ],
      "env": {
        "OPENTIP_API_KEY": "YOUR_API_KEY"
      }
    }
  }
}
```

Note the env key in the JSON above: you need to set the value to your actual OpenTIP API key. Alternatively, you can remove this section and set `OPENTIP_API_KEY` environment variable directly.

## License

Copyright © 2025 AO Kaspersky Lab

Licensed under the Apache 2.0 License. See the LICENSE.txt file for details.
