"""Isolated regression tests exposing OmniBuf Python audit findings (PY-1 through PY-12)."""

from __future__ import annotations

import dataclasses
import enum
import signal
import subprocess
import sys
import textwrap
from collections.abc import Sequence
from typing import Any

import pytest
from google.protobuf import descriptor_pb2
from google.protobuf.compiler import plugin_pb2

import omnibuf
from omnibuf import (
    WIRE_SINT,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Encoder,
    OmniBufDecodeError,
    OmniBufEncodeError,
    OmniBufError,
    Uint32,
    omnibuf_field,
    omnibuf_message,
    opaque_get_uint32,
    read_field0_schema_meta,
    validate_message,
)
from omnibuf import wire as omnibuf_wire
from omnibuf.conformance import AnnotatedLocation, AnnotatedPeerUpdate, TreeNode
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb
from omnibuf.plugin import generate_code
from omnibuf.wire import encode_tag, encode_varint, encode_zigzag32


# ---------------------------------------------------------------------------
# PY-1a: Cyclic Object Graph SIGSEGV
# ---------------------------------------------------------------------------
def test_py1a_cyclic_object_graph_does_not_sigsegv() -> None:
    """Marshaling a cyclic TreeNode graph must raise OmniBufEncodeError/RecursionError, not SIGSEGV."""
    code = textwrap.dedent(
        """
        import sys
        import omnibuf
        from omnibuf.conformance import TreeNode

        n = TreeNode(id=1, name="cycle")
        n.primary = n
        try:
            omnibuf.marshal(n)
        except (omnibuf.OmniBufError, RecursionError):
            sys.exit(0)
        sys.exit(2)
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode != -signal.SIGSEGV, (
        f"Child process crashed with SIGSEGV (returncode={proc.returncode}): {proc.stderr}"
    )
    assert proc.returncode == 0, (
        f"Expected clean OmniBufError/RecursionError (exit 0), got returncode={proc.returncode}: "
        f"{proc.stderr}"
    )


# ---------------------------------------------------------------------------
# PY-1b: Acyclic Depth > 32 Encode Bypass
# ---------------------------------------------------------------------------
def test_py1b_acyclic_depth_above_32_rejected_on_marshal() -> None:
    """Marshaling an acyclic message chain deeper than MAX_NESTING_DEPTH (32) must raise OmniBufError."""
    node = TreeNode(id=35, name="leaf")
    for depth_id in range(34, 0, -1):
        node = TreeNode(id=depth_id, name=f"d{depth_id}", primary=node)

    with pytest.raises(OmniBufError):
        omnibuf.marshal(node)


# ---------------------------------------------------------------------------
# PY-3: Sub-Message Array OOM Amplification Budget
# ---------------------------------------------------------------------------
def test_py3_submsg_array_unmarshal_enforces_max_elements_budget() -> None:
    """unmarshal must support and enforce a max_elements budget against 1-byte empty submsg amplification."""
    enc = Encoder()
    enc.begin_array(5, WIRE_SUB_MSG, 5_000)
    enc.write_raw(b"\x01" * 5_000)  # 5,000 empty 0-byte sub-messages in ~5 KB
    enc.end_array()
    pkt = enc.finish()

    assert len(pkt) < 5_100
    validate_message(pkt)

    with pytest.raises(OmniBufDecodeError):
        omnibuf.unmarshal(pkt, TreeNode, max_elements=100)


# ---------------------------------------------------------------------------
# PY-4a: protoc-gen-omnibuf-py field named `field` shadows `dataclasses.field`
# ---------------------------------------------------------------------------
def test_py4a_plugin_codegen_field_name_does_not_shadow_dataclass_field() -> None:
    """A proto field named `field` followed by a repeated field must not shadow `dataclasses.field`."""
    req = plugin_pb2.CodeGeneratorRequest()
    fdp = req.proto_file.add()
    fdp.name = "shadow_field.proto"
    fdp.package = "audit.py4a"
    fdp.syntax = "proto3"

    msg = fdp.message_type.add()
    msg.name = "ShadowFieldMsg"

    f1 = msg.field.add()
    f1.name = "field"
    f1.number = 1
    f1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f1.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f2 = msg.field.add()
    f2.name = "items"
    f2.number = 2
    f2.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
    f2.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    req.file_to_generate.append("shadow_field.proto")
    resp = generate_code(req)
    assert not resp.error, f"Generator returned error: {resp.error}"
    assert len(resp.file) == 1

    ns: dict[str, Any] = {}
    exec(resp.file[0].content, ns)  # noqa: S102
    cls = ns["ShadowFieldMsg"]
    inst = cls(field="ok", items=["a", "b"])
    raw = omnibuf.marshal(inst)
    decoded = omnibuf.unmarshal(raw, cls)
    assert decoded.field == "ok"
    assert decoded.items == ["a", "b"]


# ---------------------------------------------------------------------------
# PY-4b: protoc-gen-omnibuf-py colliding `from` / `from_` & `marshal_omnibuf`
# ---------------------------------------------------------------------------
def test_py4b_plugin_codegen_keyword_suffix_collision() -> None:
    """Fields `from` and `from_` must not map to the same `from_` dataclass attribute."""
    req = plugin_pb2.CodeGeneratorRequest()
    fdp = req.proto_file.add()
    fdp.name = "collisions.proto"
    fdp.package = "audit.py4b"
    fdp.syntax = "proto3"

    msg = fdp.message_type.add()
    msg.name = "KeywordCollisionMsg"

    for num, fname in ((1, "from"), (2, "from_")):
        fd = msg.field.add()
        fd.name = fname
        fd.number = num
        fd.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
        fd.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    req.file_to_generate.append("collisions.proto")
    resp = generate_code(req)
    assert not resp.error, f"Generator returned error: {resp.error}"
    assert len(resp.file) == 1

    ns: dict[str, Any] = {}
    exec(resp.file[0].content, ns)  # noqa: S102
    cls = ns["KeywordCollisionMsg"]

    dc_fields = dataclasses.fields(cls)
    assert len(dc_fields) == 2, (
        f"Expected 2 distinct dataclass fields for ('from', 'from_'), "
        f"got {[f.name for f in dc_fields]}"
    )


def test_py4b_plugin_codegen_marshal_omnibuf_field_collision() -> None:
    """A proto field named `marshal_omnibuf` must not clobber the generated marshal_omnibuf method."""
    req = plugin_pb2.CodeGeneratorRequest()
    fdp = req.proto_file.add()
    fdp.name = "method_collision.proto"
    fdp.package = "audit.py4b"
    fdp.syntax = "proto3"

    msg = fdp.message_type.add()
    msg.name = "MethodCollisionMsg"

    fd = msg.field.add()
    fd.name = "marshal_omnibuf"
    fd.number = 1
    fd.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    req.file_to_generate.append("method_collision.proto")
    resp = generate_code(req)
    assert not resp.error, f"Generator returned error: {resp.error}"
    assert len(resp.file) == 1

    ns: dict[str, Any] = {}
    exec(resp.file[0].content, ns)  # noqa: S102
    cls = ns["MethodCollisionMsg"]

    inst = cls()
    expected_wire = encode_tag(1, omnibuf_wire.WIRE_STRING) + encode_varint(0)
    assert omnibuf.marshal(inst) == expected_wire
    assert inst.marshal_omnibuf() == expected_wire
    assert omnibuf.unmarshal(inst.marshal_omnibuf(), cls) == inst


# ---------------------------------------------------------------------------
# PY-4c: protoc-gen-omnibuf-py hyphenated proto filename invalid import syntax
# ---------------------------------------------------------------------------
def test_py4c_plugin_codegen_hyphenated_proto_import_valid_syntax() -> None:
    """Importing `api-types.proto` from `svc.proto` must generate syntactically valid Python."""
    req = plugin_pb2.CodeGeneratorRequest()

    f_dep = req.proto_file.add()
    f_dep.name = "api-types.proto"
    f_dep.package = "audit.py4c"
    f_dep.syntax = "proto3"
    m_dep = f_dep.message_type.add()
    m_dep.name = "ApiToken"
    fd_tok = m_dep.field.add()
    fd_tok.name = "token"
    fd_tok.number = 1
    fd_tok.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd_tok.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f_svc = req.proto_file.add()
    f_svc.name = "svc.proto"
    f_svc.package = "audit.py4c"
    f_svc.syntax = "proto3"
    f_svc.dependency.append("api-types.proto")
    m_svc = f_svc.message_type.add()
    m_svc.name = "SvcRequest"
    fd_ref = m_svc.field.add()
    fd_ref.name = "auth"
    fd_ref.number = 1
    fd_ref.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd_ref.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    fd_ref.type_name = ".audit.py4c.ApiToken"

    req.file_to_generate.extend(["api-types.proto", "svc.proto"])
    resp = generate_code(req)
    assert not resp.error, f"Generator returned error: {resp.error}"

    by_name = {f.name: f.content for f in resp.file}
    svc_file = next(name for name in by_name if name.startswith("svc"))
    compile(by_name[svc_file], svc_file, "exec")


# ---------------------------------------------------------------------------
# PY-5: 17..32 Level Non-Cyclic Schema Hierarchy Crash
# ---------------------------------------------------------------------------
def test_py5_non_cyclic_18_level_schema_hierarchy_marshals() -> None:
    """18 distinct non-cyclic @omnibuf_message levels (< MAX_NESTING_DEPTH=32) must marshal cleanly."""
    classes: list[type[Any]] = []

    @omnibuf_message("Py5Level18")
    class Py5Level18:
        leaf_val: Uint32 = omnibuf_field(1, default=0)

    classes.append(Py5Level18)
    child_cls: type[Any] = Py5Level18

    for lvl in range(17, 0, -1):
        cls_name = f"Py5Level{lvl}"
        raw_cls = type(
            cls_name,
            (),
            {
                "__annotations__": {"child": child_cls | None},
                "child": omnibuf_field(1, default=None),
            },
        )
        decorated: type[Any] = omnibuf_message(cls_name)(raw_cls)
        classes.append(decorated)
        child_cls = decorated

    inst: Any = Py5Level18(leaf_val=777)
    for wrapper_cls in classes[1:]:
        inst = wrapper_cls(child=inst)

    raw = omnibuf.marshal(inst, self_describing=False)
    decoded = omnibuf.unmarshal(raw, classes[-1])
    cur = decoded
    for _ in range(17):
        assert cur.child is not None
        cur = cur.child
    assert cur.leaf_val == 777


# ---------------------------------------------------------------------------
# PY-6a: `bool` Subclassing `int` Silently Coerced into Integer Fields
# ---------------------------------------------------------------------------
def test_py6a_bool_rejected_for_int_fields() -> None:
    """Passing `True` to a uint32/int field or Opaque setter must raise TypeError/OmniBufEncodeError."""
    bad_dc = AnnotatedPeerUpdate(asn=True)
    with pytest.raises((TypeError, OmniBufEncodeError)):
        omnibuf.marshal(bad_dc)

    op = peer_omnibuf_pb.OpaquePeerUpdate(b"")
    with pytest.raises((TypeError, OmniBufEncodeError)):
        op.set_asn(True)


# ---------------------------------------------------------------------------
# PY-6b: `"false"` Truthiness Coercion into `bool` Fields
# ---------------------------------------------------------------------------
def test_py6b_string_false_rejected_for_bool_fields() -> None:
    """Passing non-bool `'false'` to a bool field or Encoder.write_bool must raise, not encode True."""
    bad_dc = AnnotatedPeerUpdate(active="false")  # type: ignore[arg-type]
    with pytest.raises((TypeError, OmniBufEncodeError)):
        omnibuf.marshal(bad_dc)

    enc = Encoder()
    with pytest.raises((TypeError, OmniBufEncodeError)):
        enc.write_bool(1, "false")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# PY-7: OpaqueView Clearing Inactive oneof Branch Deletes Active Wire Branch
# ---------------------------------------------------------------------------
def test_py7_opaque_clearing_inactive_oneof_branch_preserves_active_wire_branch() -> None:
    """Calling op.set_branch_a(None) when branch_b is active on the wire must not delete branch_b."""
    req = plugin_pb2.CodeGeneratorRequest()
    fdp = req.proto_file.add()
    fdp.name = "oneof_bug.proto"
    fdp.package = "audit.py7"
    fdp.syntax = "proto3"

    msg = fdp.message_type.add()
    msg.name = "OneofEnvelope"
    oneof = msg.oneof_decl.add()
    oneof.name = "payload"

    fa = msg.field.add()
    fa.name = "branch_a"
    fa.number = 1
    fa.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fa.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    fa.oneof_index = 0

    fb = msg.field.add()
    fb.name = "branch_b"
    fb.number = 2
    fb.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fb.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    fb.oneof_index = 0

    req.file_to_generate.append("oneof_bug.proto")
    resp = generate_code(req)
    assert not resp.error
    ns: dict[str, Any] = {}
    exec(resp.file[0].content, ns)  # noqa: S102

    msg_cls = ns["OneofEnvelope"]
    opaque_cls = ns["OpaqueOneofEnvelope"]

    wire_bytes = omnibuf.marshal(msg_cls(branch_b="hello"))
    op = opaque_cls(wire_bytes)
    assert op.get_branch_b() == "hello"

    # Clearing the already-inactive sibling branch_a must NOT wipe active branch_b!
    op.set_branch_a(None)
    spliced = op.marshal()
    decoded = omnibuf.unmarshal(spliced, msg_cls)
    assert decoded.branch_b == "hello"


# ---------------------------------------------------------------------------
# PY-10a: `read_field0_schema_meta` Swallowing Corrupt Field #0
# ---------------------------------------------------------------------------
def test_py10a_read_field0_schema_meta_raises_on_corrupt_field0() -> None:
    """read_field0_schema_meta must raise OmniBufDecodeError on corrupt Field #0 instead of None."""
    corrupt_field0 = bytes([0x19, 0x05, 0x21, 0x02])
    pkt = corrupt_field0 + encode_tag(65536, WIRE_UINT) + encode_varint(42)

    with pytest.raises(OmniBufDecodeError):
        validate_message(pkt)

    with pytest.raises(OmniBufDecodeError):
        read_field0_schema_meta(pkt)


# ---------------------------------------------------------------------------
# PY-10b: `wire.locate_field_offset` & High-Field Lookup Skipping Corrupt Field #0
# ---------------------------------------------------------------------------
def test_py10b_locate_field_offset_rejects_corrupt_field0() -> None:
    """locate_field_offset and opaque_get_uint32 (#65536) must reject packets with corrupt Field #0."""
    corrupt_field0 = bytes([0x19, 0x05, 0x21, 0x02])
    pkt = corrupt_field0 + encode_tag(65536, WIRE_UINT) + encode_varint(42)

    assert omnibuf_wire.locate_field_offset(pkt, 65536) == (-1, 0)
    with pytest.raises(OmniBufDecodeError):
        opaque_get_uint32(pkt, 65536, default=0)


# ---------------------------------------------------------------------------
# PY-11a: `@omnibuf_message` Silently Dropping Fields Without `omnibuf_field`
# ---------------------------------------------------------------------------
def test_py11a_dataclass_missing_omnibuf_field_rejected() -> None:
    """An @omnibuf_message field missing omnibuf_field(...) must raise instead of silent data loss."""
    with pytest.raises((TypeError, ValueError, OmniBufEncodeError)):

        @omnibuf_message
        class AccidentalUnnumberedField:
            id: Uint32 = omnibuf_field(1, default=0)
            forgotten_field: str = "important"

        omnibuf.marshal(AccidentalUnnumberedField(id=7, forgotten_field="lost"))


# ---------------------------------------------------------------------------
# PY-11b: `@omnibuf_message(slots=False)` Sub-Message Without Explicit Default
# ---------------------------------------------------------------------------
def test_py11b_dataclass_slots_false_submsg_without_default_unmarshals() -> None:
    """@omnibuf_message(slots=False) with a non-optional sub-message field must unmarshal cleanly."""

    @omnibuf_message(slots=False)
    class SlotsFalseEnvelope:
        loc: AnnotatedLocation = omnibuf_field(1)

    pkt = omnibuf.marshal(SlotsFalseEnvelope(loc=AnnotatedLocation(city="Zurich")))
    decoded = omnibuf.unmarshal(pkt, SlotsFalseEnvelope)
    assert decoded.loc.city == "Zurich"


# ---------------------------------------------------------------------------
# PY-11c: `@omnibuf_message` IntEnum Rejecting Unknown Open Enum Wire Values
# ---------------------------------------------------------------------------
class _Py11Status(enum.IntEnum):
    UNKNOWN = 0
    READY = 1


@omnibuf_message
class _Py11EnumHolder:
    status: _Py11Status = omnibuf_field(1, default=_Py11Status.UNKNOWN)


def test_py11c_dataclass_open_int_enum_unknown_wire_value() -> None:
    """Unknown wire enum integers (e.g. 99) must decode cleanly with open-enum semantics."""
    pkt = encode_tag(1, WIRE_SINT) + encode_varint(encode_zigzag32(99))
    decoded = omnibuf.unmarshal(pkt, _Py11EnumHolder)
    assert int(decoded.status) == 99


# ---------------------------------------------------------------------------
# PY-12: `Encoder` Unchecked Container Element Counts
# ---------------------------------------------------------------------------
def test_py12_encoder_rejects_mismatched_array_element_count() -> None:
    """Encoder.end_array() / finish() must raise OmniBufEncodeError when fewer elements were written."""
    enc = Encoder()
    enc.begin_array(1, WIRE_UINT, 5)
    with pytest.raises(OmniBufEncodeError):
        enc.end_array()
        enc.finish()


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 1 - Fast-slot list[Uint32] >= 2^29 (9-byte varints)
# ---------------------------------------------------------------------------
@omnibuf_message
class _FastSlotU32List:
    vals: list[Uint32] = omnibuf_field(1, default_factory=list)


def test_audit_f1_fast_slot_uint32_list_large_values() -> None:
    """Encoding list[Uint32] with values >= 2^29 (9-byte Prefix-Varints) must not overflow buffer."""
    big = [0x2000_0000, 0xFFFF_FFFF, 0x3FFF_FFFF, 0x8000_0000] * 64
    pkt = omnibuf.marshal(_FastSlotU32List(vals=big))
    validate_message(pkt)
    decoded = omnibuf.unmarshal(pkt, _FastSlotU32List)
    assert decoded.vals == big


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 2 - Cyclic SubMsg with omitempty=True
# ---------------------------------------------------------------------------
@omnibuf_message
class _CyclicOmitEmpty:
    child: _CyclicOmitEmpty | None = omnibuf_field(1, default=None, omitempty=True)


def test_audit_f2_is_value_empty_depth_limit_on_cycle() -> None:
    """Cyclic SubMsg with omitempty=True must raise OmniBufEncodeError instead of stack overflow."""
    node = _CyclicOmitEmpty()
    node.child = node
    with pytest.raises(OmniBufEncodeError):
        omnibuf.marshal(node)


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 3 - Standalone opaque_get_* propagate decode errors
# ---------------------------------------------------------------------------
def test_audit_f3_standalone_opaque_getters_propagate_errors() -> None:
    """Standalone opaque_get_* helpers must raise OmniBufDecodeError on wire corruption / bad UTF-8."""
    # Legitimately absent returns default / None / empty view
    empty = b""
    assert opaque_get_uint32(empty, 1, 7) == 7
    assert omnibuf.opaque_get_string(empty, 1, "fallback") == "fallback"
    assert omnibuf.opaque_get_bytes(empty, 1, b"def") == b"def"
    assert bytes(omnibuf.opaque_get_bytes_view(empty, 1)) == b""
    assert omnibuf.opaque_get_submsg_slice(empty, 1) is None

    # Invalid Field #0 wire type (WIRE_UINT instead of WIRE_SUB_MSG)
    bad_f0 = encode_varint((0 << 4) | WIRE_UINT) + encode_varint(1)
    with pytest.raises(OmniBufDecodeError):
        opaque_get_uint32(bad_f0, 1, 7)
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_string(bad_f0, 1, "fallback")
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_bytes(bad_f0, 1, b"def")
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_bytes_view(bad_f0, 1)
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_submsg_slice(bad_f0, 1)

    # Truncated field payload
    truncated = encode_tag(1, WIRE_UINT) + b"\x00"  # 9-byte varint header with 0 trailing bytes
    with pytest.raises(OmniBufDecodeError):
        opaque_get_uint32(truncated, 1, 7)

    # Invalid UTF-8 in WireString field
    bad_utf8 = encode_tag(1, omnibuf_wire.WIRE_STRING) + encode_varint(2) + b"\xff\xfe"
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque_get_string(bad_utf8, 1, "fallback")


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 4 - Empty unknown WireSubMsg inside Field #0 at depth limit
# ---------------------------------------------------------------------------
def test_audit_f4_field0_unknown_empty_submsg_depth_limit() -> None:
    """Empty unknown WireSubMsg inside Field #0 exceeding MAX_NESTING_DEPTH must be rejected."""
    # Build 32 nested empty submessages inside unknown field #99 of Field #0 (depth 1 + 32 = 33 > 32)
    payload = b""
    for _ in range(omnibuf_wire.MAX_NESTING_DEPTH):
        payload = encode_tag(99, WIRE_SUB_MSG) + encode_varint(len(payload)) + payload
    pkt = encode_tag(0, WIRE_SUB_MSG) + encode_varint(len(payload)) + payload
    with pytest.raises(OmniBufDecodeError):
        validate_message(pkt)


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 5 - Python validate_message fallback & splice UTF-8 check
# ---------------------------------------------------------------------------
def test_audit_f5_python_validate_message_and_splice_check_utf8() -> None:
    """Python validate_message fallback and splice_fields_encode must reject invalid UTF-8."""
    bad_utf8 = encode_tag(1, omnibuf_wire.WIRE_STRING) + encode_varint(2) + b"\xff\xfe"
    with pytest.raises(OmniBufDecodeError):
        validate_message(bad_utf8, depth=0, limit_depth=16)
    with pytest.raises(OmniBufDecodeError):
        validate_message(bad_utf8, depth=1, limit_depth=omnibuf_wire.MAX_NESTING_DEPTH)
    with pytest.raises(OmniBufDecodeError):
        omnibuf.opaque.splice_dirty_fields(None, bad_utf8, {2}, lambda _out, _f: None)


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 6 - Depth-limit check for None default-empty list in fast-slot encode
# ---------------------------------------------------------------------------
@omnibuf_message
class _DepthLeafList:
    items: list[Uint32] = omnibuf_field(1, default_factory=list)


@omnibuf_message
class _DepthChain:
    nxt: _DepthChain | None = omnibuf_field(1, default=None)
    leaf: _DepthLeafList | None = omnibuf_field(2, default=None)


def test_audit_f6_fast_slot_none_empty_list_respects_depth_limit() -> None:
    """Fast-slot encoder must enforce MAX_NESTING_DEPTH for None default-empty list fields."""
    leaf = _DepthLeafList(items=None)  # type: ignore[arg-type]
    cur = _DepthChain(leaf=leaf)
    # leaf sits at depth = MAX_NESTING_DEPTH, so its array field is at MAX_NESTING_DEPTH + 1
    for _ in range(omnibuf_wire.MAX_NESTING_DEPTH - 1):
        cur = _DepthChain(nxt=cur)
    with pytest.raises(OmniBufEncodeError):
        omnibuf.marshal(cur)


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 7 - Non-byte memoryview (itemsize > 1) in Encoder / protobuf_codec
# ---------------------------------------------------------------------------
def test_audit_f7_non_byte_memoryview_encoder() -> None:
    """Encoder must use byte length (nbytes) for non-byte memoryviews (itemsize > 1)."""
    import array

    arr = array.array("I", [0x11223344, 0x55667788])
    mv = memoryview(arr)
    expected = arr.tobytes()
    assert len(mv) == 2
    assert mv.nbytes == 8

    enc = Encoder()
    enc.write_bytes(1, mv)
    enc.write_extended(2, 0x07, mv)
    enc.begin_array(3, omnibuf_wire.WIRE_BYTES, 1)
    enc.write_elem_bytes(mv)
    enc.end_array()
    pkt = enc.finish()

    validate_message(pkt)
    assert omnibuf.opaque_get_bytes(pkt, 1) == expected
    assert omnibuf.opaque_get_scalar_array(pkt, 3, omnibuf_wire.WIRE_BYTES, "bytes") == [expected]


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 8 - Hostile non-list PySequence with huge __len__
# ---------------------------------------------------------------------------
class _HugeFakeSeq(Sequence[int]):
    def __len__(self) -> int:
        return 10**12

    def __getitem__(self, idx: int | slice) -> Any:
        raise ValueError("hostile sequence")


def test_audit_f8_hostile_sequence_huge_len_does_not_abort() -> None:
    """Encoding a non-list sequence with huge __len__ must raise cleanly without Rust OOM abort."""
    holder = _FastSlotU32List(vals=_HugeFakeSeq())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="hostile sequence"):
        omnibuf.marshal(holder)


# ---------------------------------------------------------------------------
# Audit 2026-11: Finding 9 - 0-D memoryview, splice_fields linear perf, gpb seen.add
# ---------------------------------------------------------------------------
def test_audit_f9a_zero_dim_memoryview_safe() -> None:
    """0-D memoryview backed by bytes must not OOB-read strides in ByteSliceOwner."""
    # Single-byte packet: field #1 = true ((1 << 4) | WIRE_BOOL_TRUE = 0x13 -> varint 0x27)
    raw_bool = encode_tag(1, omnibuf_wire.WIRE_BOOL_TRUE)
    assert len(raw_bool) == 1
    mv0 = memoryview(raw_bool).cast("B", shape=())
    assert mv0.ndim == 0
    view = omnibuf.OpaqueView(mv0)
    assert view._get_bool(1) is True


def test_audit_f9b_splice_fields_many_replacements() -> None:
    """splice_fields with many replacements must produce exact expected wire output."""
    enc = Encoder()
    for i in range(1, 201):
        enc.write_uint32(i, i)
    src = enc.finish()
    reps = [
        omnibuf.SpliceField(i, encode_tag(i, WIRE_UINT) + encode_varint(i * 10))
        for i in range(1, 201)
    ]
    out = omnibuf.splice_fields(None, src, reps)
    validate_message(out)
    assert opaque_get_uint32(out, 1) == 10
    assert opaque_get_uint32(out, 200) == 2000


def test_audit_f9c_gpb_mismatched_wire_type_before_repeated_clears_reused_dst() -> None:
    """Mismatched wire type on a repeated field must not mark it seen before a valid occurrence."""
    from omnibuf.protobuf_codec import unmarshal_proto

    # FileDescriptorProto has repeated string dependency = 3
    dst = descriptor_pb2.FileDescriptorProto(dependency=["stale"])
    # Wire packet: field #3 with mismatched WIRE_UINT, then field #3 with valid WIRE_ARRAY of strings
    enc = Encoder()
    enc.write_uint32(3, 999)
    enc.write_string_array(3, ["fresh"])
    pkt = enc.finish()

    unmarshal_proto(pkt, dst)
    assert list(dst.dependency) == ["fresh"]
