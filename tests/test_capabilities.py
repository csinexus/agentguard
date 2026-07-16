from core import capabilities
from core.models import Capability, ToolDeclaration


def test_infers_read_capability_from_verb():
    tool = ToolDeclaration(name="get_profile", description="Get the user's profile information.")
    caps, reasons = capabilities.infer_capabilities(tool)
    assert Capability.READ in caps
    assert any("get" in r for r in reasons[Capability.READ.value])


def test_infers_delete_and_financial():
    tool = ToolDeclaration(
        name="refund_order",
        description="Delete a pending order and issue a refund.",
        input_schema={"properties": {"amount": {"type": "number"}}},
    )
    caps, _ = capabilities.infer_capabilities(tool)
    assert Capability.DELETE in caps
    assert Capability.FINANCIAL in caps


def test_name_implies_readonly():
    assert capabilities.name_implies_readonly(ToolDeclaration(name="get_user", description=""))
    assert not capabilities.name_implies_readonly(ToolDeclaration(name="update_user", description=""))


def test_schema_has_write_params():
    tool = ToolDeclaration(name="get_user", description="", input_schema={"properties": {"content": {"type": "string"}}})
    assert capabilities.schema_has_write_params(tool)
    tool2 = ToolDeclaration(name="get_user", description="", input_schema={"properties": {"id": {"type": "string"}}})
    assert not capabilities.schema_has_write_params(tool2)


def test_capability_override_replaces_inference():
    tool = ToolDeclaration(name="mystery_tool", description="Does something opaque.")
    capabilities.tag_tool(tool, overrides={"mystery_tool": ["execute"]})
    assert tool.inferred_capabilities == [Capability.EXECUTE]
