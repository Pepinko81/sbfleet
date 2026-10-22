"""Exercise the actual stdio transport and installed command entry point."""

import asyncio
import json
import sys
from importlib.resources import files

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from sbfleet import registry as reg
from sbfleet.fleet import FleetSnapshot


def test_schema_packaged_and_stable():
    schema = json.loads(files("sbfleet").joinpath("fleet.schema.json").read_text())
    assert schema == FleetSnapshot.model_json_schema()
    assert schema["additionalProperties"] is False


def test_stdio_initialize_and_all_tools(tmp_path):
    root = reg.ensure_root(tmp_path / "fleet")
    before = sorted(str(p.relative_to(root)) for p in root.rglob("*"))

    async def exercise():
        parameters = StdioServerParameters(
            command=sys.executable, args=["-m", "sbfleet.cli", "--home", str(root), "mcp"]
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as client:
                initialization = await client.initialize()
                assert initialization.serverInfo.name == "sbfleet"
                tools = await client.list_tools()
                assert len(tools.tools) == 8
                for tool in tools.tools:
                    args = {"slug": "missing"} if "slug" in tool.inputSchema["properties"] else {}
                    if tool.name in {"schema_diff", "migration_plan"}:
                        args = {"source": "missing", "target": "missing"}
                        response = await client.call_tool(tool.name, args)
                        assert not response.isError
                        payload = response.structuredContent
                        if tool.name == "migration_plan":
                            payload = payload["diff"]
                        assert payload["error"] == "NOT_FOUND"
                        continue
                    response = await client.call_tool(tool.name, args)
                    assert not response.isError
                    assert response.structuredContent["schema_version"] == "sbfleet.fleet.v1"
                    if args:
                        assert response.structuredContent["error"] == "NOT_FOUND"
                response = await client.call_tool("remove", {"slug": "missing"})
                assert response.isError

    asyncio.run(exercise())
    assert sorted(str(p.relative_to(root)) for p in root.rglob("*")) == before
