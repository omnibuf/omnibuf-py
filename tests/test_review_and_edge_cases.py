"""Regression tests for memory safety, oneofs, enums, threading, Field #0, and lazy imports."""

from __future__ import annotations

import enum
import math
import subprocess
import sys
import threading
import types
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from google.protobuf import descriptor_pb2
from google.protobuf.compiler import plugin_pb2

from omnibuf import (
    WIRE_ARRAY,
    WIRE_BOOL_FALSE,
    WIRE_FIXED32,
    WIRE_FIXED64,
    WIRE_MAP,
    WIRE_STRING,
    WIRE_SUB_MSG,
    WIRE_UINT,
    Encoder,
    Float32,
    Float64,
    OmniBufDecodeError,
    OmniBufEncodeError,
    SchemaMeta,
    SpliceField,
    Uint32,
    decode_blind,
    decode_blind_json,
    decode_schema_meta,
    encode_field0_schema_meta,
    marshal,
    omnibuf_field,
    omnibuf_message,
    splice_fields,
    unmarshal,
)
from omnibuf.conformance import TreeNode
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb
from omnibuf.gen.omnibuf.conformance import conformance_omnibuf_pb
from omnibuf.opaque import splice_dirty_fields
from omnibuf.plugin import generate_code
from omnibuf.wire import (
    MAX_FIELD_NUMBER,
    encode_tag,
    encode_varint,
    validate_message,
    validate_value,
)

# ============================================================================
# 1. Mutable Buffer (bytearray / memoryview) UAF Safety
# ============================================================================


def test_mutable_bytearray_snapshot_during_python_reentry() -> None:
    target_buf = bytearray()

    @omnibuf_message
    class EvilChild:
        label: str = omnibuf_field(1, default="")

        def __init__(self, label: str = "") -> None:
            # Mutating the input bytearray mid-decode must not corrupt or UAF the Rust decoder
            target_buf.clear()
            target_buf.extend(b"\xff" * 64)
            self.label = label

    @omnibuf_message
    class EvilParent:
        child: EvilChild | None = omnibuf_field(1, default=None)
        tail: Uint32 = omnibuf_field(2, default=0)

    enc = Encoder()
    enc.begin_submsg(1)
    enc.write_string(1, "safe-payload")
    enc.end_submsg()
    enc.write_uint32(2, 4242)
    valid_bytes = enc.finish()

    target_buf[:] = valid_bytes
    decoded = unmarshal(target_buf, EvilParent)
    assert decoded.child is not None
    assert decoded.child.label == "safe-payload"
    assert decoded.tail == 4242

    # Also verify memoryview over bytearray works cleanly across Opaque, splice, and blind decode
    raw_peer = peer_omnibuf_pb.marshal_peer_update(
        peer_omnibuf_pb.PeerUpdate(
            asn=64512,
            router_id="rtr1",
            location=peer_omnibuf_pb.Location(city="Frankfurt"),
            sequence=10,
        )
    )
    mut_peer = bytearray(raw_peer)
    mv_peer = memoryview(mut_peer)
    op = peer_omnibuf_pb.OpaquePeerUpdate(mv_peer)
    mut_peer[0] ^= (
        0xFF  # Mutating original bytearray after OpaqueView init must not affect snapshot
    )
    loc = op.get_location()
    assert loc is not None and loc.city == "Frankfurt"
    op.set_sequence(11)
    spliced = op.marshal()
    assert peer_omnibuf_pb.unmarshal_peer_update(spliced).sequence == 11

    mut_blind = bytearray(valid_bytes)
    validate_message(memoryview(mut_blind))
    assert decode_blind(memoryview(mut_blind)) == {
        "field_1": {"field_1": "safe-payload"},
        "field_2": 4242,
    }


# ============================================================================
# 2. List & Dict Mutation During Custom Element Callbacks
# ============================================================================


def test_list_and_dict_mutation_during_element_dunder_callbacks() -> None:
    @omnibuf_message
    class ContainerMsg:
        nums: list[Uint32] = omnibuf_field(1, default_factory=list)
        scores: dict[str, Uint32] = omnibuf_field(2, default_factory=dict)

    nums_list: list[Any] = []
    scores_dict: dict[str, Any] = {}

    class MutatingListInt:
        def __init__(self, val: int) -> None:
            self._val = val

        def __index__(self) -> int:
            nums_list.clear()
            return self._val

    class MutatingDictInt:
        def __init__(self, val: int) -> None:
            self._val = val

        def __index__(self) -> int:
            scores_dict.clear()
            return self._val

    nums_list.extend([MutatingListInt(10), MutatingListInt(20), MutatingListInt(30)])
    scores_dict["a"] = MutatingDictInt(100)
    scores_dict["b"] = MutatingDictInt(200)

    msg = ContainerMsg(nums=nums_list, scores=scores_dict)
    raw = marshal(msg, deterministic=True)
    restored = unmarshal(raw, ContainerMsg)
    assert restored.nums == [10, 20, 30]
    assert restored.scores == {"a": 100, "b": 200}


def test_submsg_list_mutation_during_property_access() -> None:
    children_list: list[Any] = []

    class MutatingSubInt:
        def __init__(self, val: int) -> None:
            self._val = val

        def __index__(self) -> int:
            children_list.clear()
            return self._val

    @omnibuf_message
    class LeafItem:
        val: Uint32 = omnibuf_field(1, default=0)

    @omnibuf_message
    class BagMsg:
        items: list[LeafItem] = omnibuf_field(1, default_factory=list)

    children_list.extend([LeafItem(val=MutatingSubInt(77)), LeafItem(val=MutatingSubInt(88))])  # type: ignore[arg-type]
    raw = marshal(BagMsg(items=children_list))
    restored = unmarshal(raw, BagMsg)
    assert [it.val for it in restored.items] == [77, 88]


# ============================================================================
# 3 & 4. protoc-gen-omnibuf-py Real Oneof, Explicit Presence, & Root Imports
# ============================================================================


def test_plugin_real_oneof_and_explicit_presence_zero_values() -> None:
    req = plugin_pb2.CodeGeneratorRequest()
    f = req.proto_file.add()
    f.name = "oneof_test.proto"
    f.package = "testpkg"
    f.syntax = "proto3"

    sub = f.message_type.add()
    sub.name = "SubPayload"
    sub_f = sub.field.add()
    sub_f.name = "code"
    sub_f.number = 1
    sub_f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    sub_f.type = descriptor_pb2.FieldDescriptorProto.TYPE_UINT32

    m = f.message_type.add()
    m.name = "Envelope"
    oo_real = m.oneof_decl.add()
    oo_real.name = "choice"
    oo_synth_u = m.oneof_decl.add()
    oo_synth_u.name = "_opt_zero"
    oo_synth_b = m.oneof_decl.add()
    oo_synth_b.name = "_opt_flag"
    oo_synth_s = m.oneof_decl.add()
    oo_synth_s.name = "_opt_str"

    # Real oneof fields (index 0)
    f1 = m.field.add()
    f1.name = "choice_num"
    f1.number = 1
    f1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f1.type = descriptor_pb2.FieldDescriptorProto.TYPE_UINT32
    f1.oneof_index = 0

    f2 = m.field.add()
    f2.name = "choice_text"
    f2.number = 2
    f2.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f2.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    f2.oneof_index = 0

    f3 = m.field.add()
    f3.name = "choice_sub"
    f3.number = 3
    f3.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f3.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    f3.type_name = ".testpkg.SubPayload"
    f3.oneof_index = 0

    # Proto3 optional scalar fields (synthetic oneofs 1, 2, 3)
    f4 = m.field.add()
    f4.name = "opt_zero"
    f4.number = 4
    f4.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f4.type = descriptor_pb2.FieldDescriptorProto.TYPE_UINT32
    f4.oneof_index = 1
    f4.proto3_optional = True

    f5 = m.field.add()
    f5.name = "opt_flag"
    f5.number = 5
    f5.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f5.type = descriptor_pb2.FieldDescriptorProto.TYPE_BOOL
    f5.oneof_index = 2
    f5.proto3_optional = True

    f6 = m.field.add()
    f6.name = "opt_str"
    f6.number = 6
    f6.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    f6.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    f6.oneof_index = 3
    f6.proto3_optional = True

    req.file_to_generate.append("oneof_test.proto")
    resp = generate_code(req)
    assert not resp.error
    code_str = resp.file[0].content

    mod: Any = types.ModuleType("_dyn_oneof_omnibuf_pb")
    sys.modules["_dyn_oneof_omnibuf_pb"] = mod
    try:
        exec(compile(code_str, "_dyn_oneof_omnibuf_pb.py", "exec"), mod.__dict__)
    finally:
        sys.modules.pop("_dyn_oneof_omnibuf_pb", None)

    # 1. Absent optional fields return None on both eager unmarshal and Opaque
    empty_env = mod.Envelope()
    empty_wire = empty_env.marshal_omnibuf()
    op_empty = mod.OpaqueEnvelope(empty_wire)
    op_empty.validate()
    assert op_empty.which_choice() is None
    assert op_empty.has_opt_zero() is False
    assert op_empty.get_opt_zero() is None
    assert op_empty.has_opt_flag() is False
    assert op_empty.get_opt_flag() is None
    assert op_empty.has_opt_str() is False
    assert op_empty.get_opt_str() is None

    # 2. Explicit zero values (0, False, "") preserve presence on both eager and Opaque
    zero_env = mod.Envelope(choice_num=0, opt_zero=0, opt_flag=False, opt_str="")
    assert zero_env.which_choice() == "choice_num"
    zero_wire = zero_env.marshal_omnibuf()
    dec_zero = mod.unmarshal_envelope(zero_wire)
    assert dec_zero.choice_num == 0
    assert dec_zero.opt_zero == 0
    assert dec_zero.opt_flag is False
    assert dec_zero.opt_str == ""

    op_zero = mod.OpaqueEnvelope(zero_wire)
    assert op_zero.which_choice() == "choice_num"
    assert op_zero.has_choice_num() is True
    assert op_zero.get_choice_num() == 0
    assert op_zero.has_opt_zero() is True
    assert op_zero.get_opt_zero() == 0
    assert op_zero.has_opt_flag() is True
    assert op_zero.get_opt_flag() is False
    assert op_zero.has_opt_str() is True
    assert op_zero.get_opt_str() == ""

    # 3. Multiple oneof branches set simultaneously on dataclass fail marshal
    bad_env = mod.Envelope(choice_num=5, choice_text="both")
    with pytest.raises(OmniBufEncodeError):
        bad_env.marshal_omnibuf()

    # 4. Concatenated wire packet with choice_num followed by choice_text="" -> last wins!
    w1 = mod.Envelope(choice_num=99).marshal_omnibuf()
    w2 = mod.Envelope(choice_text="").marshal_omnibuf()
    concat_wire = w1 + w2
    dec_concat = mod.unmarshal_envelope(concat_wire)
    assert dec_concat.choice_num is None
    assert dec_concat.choice_text == ""
    assert dec_concat.which_choice() == "choice_text"

    op_concat = mod.OpaqueEnvelope(concat_wire)
    assert op_concat.which_choice() == "choice_text"
    assert op_concat.get_choice_num() is None
    assert op_concat.get_choice_text() == ""

    # 5. Opaque set_<oneof_member> clears sibling wire fields on marshal
    op_concat.set_choice_sub(mod.SubPayload(code=7))
    assert op_concat.which_choice() == "choice_sub"
    assert op_concat.get_choice_text() is None
    spliced_oo = op_concat.marshal()
    dec_spliced = mod.unmarshal_envelope(spliced_oo)
    assert dec_spliced.which_choice() == "choice_sub"
    assert dec_spliced.choice_num is None
    assert dec_spliced.choice_text is None
    assert dec_spliced.choice_sub == mod.SubPayload(code=7)


def test_plugin_root_level_relative_imports_and_group_extension_rejection() -> None:
    req = plugin_pb2.CodeGeneratorRequest()
    f_bar = req.proto_file.add()
    f_bar.name = "bar.proto"
    f_bar.syntax = "proto3"
    m_bar = f_bar.message_type.add()
    m_bar.name = "Bar"

    f_leaf = req.proto_file.add()
    f_leaf.name = "sub/leaf.proto"
    f_leaf.syntax = "proto3"
    m_leaf = f_leaf.message_type.add()
    m_leaf.name = "Leaf"

    f_root = req.proto_file.add()
    f_root.name = "root.proto"
    f_root.syntax = "proto3"
    f_root.dependency.extend(["bar.proto", "sub/leaf.proto"])
    m_root = f_root.message_type.add()
    m_root.name = "Root"
    fd1 = m_root.field.add()
    fd1.name = "b"
    fd1.number = 1
    fd1.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd1.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    fd1.type_name = ".Bar"
    fd2 = m_root.field.add()
    fd2.name = "l"
    fd2.number = 2
    fd2.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd2.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    fd2.type_name = ".Leaf"

    req.file_to_generate.append("root.proto")
    resp = generate_code(req)
    assert not resp.error
    content = resp.file[0].content
    assert "from . import bar_omnibuf_pb as _imp_0" in content
    assert "from .sub import leaf_omnibuf_pb as _imp_1" in content

    # Reject TYPE_GROUP (10) cleanly via CodeGeneratorResponse.error
    req_grp = plugin_pb2.CodeGeneratorRequest()
    fg = req_grp.proto_file.add()
    fg.name = "grp.proto"
    fg.syntax = "proto2"
    mg = fg.message_type.add()
    mg.name = "HasGroup"
    fdg = mg.field.add()
    fdg.name = "g"
    fdg.number = 1
    fdg.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fdg.type = descriptor_pb2.FieldDescriptorProto.TYPE_GROUP
    req_grp.file_to_generate.append("grp.proto")
    resp_grp = generate_code(req_grp)
    assert "group" in resp_grp.error.lower()

    # Reject proto2 extension ranges cleanly
    req_ext = plugin_pb2.CodeGeneratorRequest()
    fe = req_ext.proto_file.add()
    fe.name = "ext.proto"
    fe.syntax = "proto2"
    me = fe.message_type.add()
    me.name = "Extendable"
    er = me.extension_range.add()
    er.start = 100
    er.end = 200
    req_ext.file_to_generate.append("ext.proto")
    resp_ext = generate_code(req_ext)
    assert "extension" in resp_ext.error


# ============================================================================
# 5. Fixed-Width WireArray Exact Length & Unknown WireString Skip Parity
# ============================================================================


def test_fixed_width_wire_array_rejects_trailing_bytes_and_unknown_string_skips_by_length() -> None:
    for elem_wt, elem_bytes in (
        (WIRE_BOOL_FALSE, b"\x01"),
        (WIRE_FIXED32, b"\x01\x02\x03\x04"),
        (WIRE_FIXED64, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
    ):
        # Claim count=1 (varint 0x03) plus 1 extra trailing byte
        body = bytes([elem_wt, 0x03]) + elem_bytes + b"\x00"
        pkt = encode_tag(99, WIRE_ARRAY) + encode_varint(len(body)) + body
        with pytest.raises(OmniBufDecodeError):
            validate_message(pkt)
        with pytest.raises(OmniBufDecodeError):
            peer_omnibuf_pb.unmarshal_peer_update(pkt)

    # Spec §7: Unreferenced unknown WIRE_STRING skips by byte length in schema-aware decode,
    # whereas schema-less decode_blind validates UTF-8 on every string field!
    tag_bytes = encode_tag(99, WIRE_STRING)
    unknown_bad_utf8 = tag_bytes + encode_varint(2) + b"\xff\xfe"
    assert validate_value(memoryview(unknown_bad_utf8), len(tag_bytes), WIRE_STRING, 0) == len(
        unknown_bad_utf8
    )
    dec_peer = peer_omnibuf_pb.unmarshal_peer_update(unknown_bad_utf8)
    assert dec_peer.asn == 0
    with pytest.raises(OmniBufDecodeError):
        decode_blind(unknown_bad_utf8)


# ============================================================================
# 6 & 7. Thread-Safe Codec Compilation & Namespace Precedence
# ============================================================================


def test_multithreaded_first_use_dataclass_codec_compilation() -> None:
    @omnibuf_message
    class ConcurrentLeaf:
        x: Uint32 = omnibuf_field(1, default=0)

    @omnibuf_message
    class ConcurrentNode:
        id: Uint32 = omnibuf_field(1, default=0)
        leaf: ConcurrentLeaf = omnibuf_field(2, default_factory=ConcurrentLeaf)
        children: list[ConcurrentNode] = omnibuf_field(3, default_factory=list)

    barrier = threading.Barrier(8)

    def worker(idx: int) -> int:
        barrier.wait()
        node = ConcurrentNode(
            id=idx,
            leaf=ConcurrentLeaf(x=idx * 10),
            children=[ConcurrentNode(id=idx + 100)],
        )
        raw = marshal(node)
        out = unmarshal(raw, ConcurrentNode)
        return out.leaf.x + out.children[0].id

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(1, 9)))
    assert results == [i * 10 + (i + 100) for i in range(1, 9)]


def test_registered_types_do_not_shadow_module_local_classes() -> None:
    mod_a = types.ModuleType("_pkg_a_test")
    mod_b = types.ModuleType("_pkg_b_test")
    sys.modules["_pkg_a_test"] = mod_a
    sys.modules["_pkg_b_test"] = mod_b
    try:
        exec(
            "from omnibuf import Uint32, omnibuf_field, omnibuf_message\n"
            "@omnibuf_message\n"
            "class CollisionChild:\n"
            "    a_only: Uint32 = omnibuf_field(1, default=11)\n",
            mod_a.__dict__,
        )
        exec(
            "from __future__ import annotations\n"
            "from omnibuf import omnibuf_field, omnibuf_message\n"
            "class CollisionChild:\n"
            "    pass\n"
            "# Replace with module-local @omnibuf_message of the same name\n"
            "@omnibuf_message\n"
            "class CollisionChild:\n"  # noqa: F811
            "    b_text: str = omnibuf_field(2, default='from_b')\n"
            "@omnibuf_message\n"
            "class HolderB:\n"
            "    child: CollisionChild = omnibuf_field(1, default_factory=CollisionChild)\n",
            mod_b.__dict__,
        )
        holder_cls = mod_b.__dict__["HolderB"]
        child_b_cls = mod_b.__dict__["CollisionChild"]
        inst = holder_cls(child=child_b_cls(b_text="local-wins"))
        raw = marshal(inst)
        decoded = unmarshal(raw, holder_cls)
        assert isinstance(decoded.child, child_b_cls)
        assert decoded.child.b_text == "local-wins"
    finally:
        sys.modules.pop("_pkg_a_test", None)
        sys.modules.pop("_pkg_b_test", None)


# ============================================================================
# 8. Opaque Error Propagation, splice_dirty_fields Validation, & Fast Scalars
# ============================================================================


def test_opaque_error_propagation_and_splice_validation() -> None:
    # Truncated submessage length on field 9 (Location)
    corrupt_pkt = encode_tag(9, WIRE_SUB_MSG) + encode_varint(50) + b"\x01\x02"
    op_bad = peer_omnibuf_pb.OpaquePeerUpdate(corrupt_pkt)
    with pytest.raises(OmniBufDecodeError):
        op_bad.validate()
    with pytest.raises(OmniBufDecodeError):
        op_bad.get_location()
    with pytest.raises(OmniBufDecodeError):
        op_bad.opaque_location()
    op_bad.set_sequence(5)
    with pytest.raises(OmniBufDecodeError):
        op_bad.marshal()

    # splice_dirty_fields validation on bool, negative bitmask, bit 0, and out-of-range
    valid_pkt = peer_omnibuf_pb.PeerUpdate(sequence=1).marshal_omnibuf()
    bad_inputs: list[Any] = [True, False, -1, -99, 1, {0}, {MAX_FIELD_NUMBER + 1}, {True}]
    for bad_dirty in bad_inputs:
        with pytest.raises(OmniBufEncodeError):
            splice_dirty_fields(None, valid_pkt, bad_dirty, lambda _b, _f: None)
    with pytest.raises(OmniBufEncodeError):
        splice_fields(b"", valid_pkt, [SpliceField(field_num=True, encoded_field=b"")])


def test_opaque_generalized_fast_scalar_setters() -> None:
    base = conformance_omnibuf_pb.TestAllTypes(f6_string="init").marshal_omnibuf()
    op = conformance_omnibuf_pb.OpaqueTestAllTypes(base)
    op.set_f1_uint32(101)
    b1 = op.marshal()
    op2 = conformance_omnibuf_pb.OpaqueTestAllTypes(b1)
    op2.set_f3_sint32(-42)
    b2 = op2.marshal()
    op3 = conformance_omnibuf_pb.OpaqueTestAllTypes(b2)
    op3.set_f4_sint64(-9_000_000_000)
    b3 = op3.marshal()
    op4 = conformance_omnibuf_pb.OpaqueTestAllTypes(b3)
    op4.set_f5_bool(True)
    b4 = op4.marshal()
    op5 = conformance_omnibuf_pb.OpaqueTestAllTypes(b4)
    op5.set_f6_string("updated-fast")
    b5 = op5.marshal()
    op6 = conformance_omnibuf_pb.OpaqueTestAllTypes(b5)
    op6.set_f13_float32(1.5)
    b6 = op6.marshal()
    op7 = conformance_omnibuf_pb.OpaqueTestAllTypes(b6)
    op7.set_f14_float64(-2.25)
    b7 = op7.marshal()
    op8 = conformance_omnibuf_pb.OpaqueTestAllTypes(b7)
    op8.set_f15_fixed32(0xDEAD_BEEF)
    b8 = op8.marshal()
    op9 = conformance_omnibuf_pb.OpaqueTestAllTypes(b8)
    op9.set_f16_fixed64(0xCAFE_BABE_1234_5678)
    final_bytes = op9.marshal()

    res = conformance_omnibuf_pb.unmarshal_test_all_types(final_bytes)
    assert res.f1_uint32 == 101
    assert res.f3_sint32 == -42
    assert res.f4_sint64 == -9_000_000_000
    assert res.f5_bool is True
    assert res.f6_string == "updated-fast"
    assert res.f13_float32 == 1.5
    assert res.f14_float64 == -2.25
    assert res.f15_fixed32 == 0xDEAD_BEEF
    assert res.f16_fixed64 == 0xCAFE_BABE_1234_5678


# ============================================================================
# 10. SchemaMeta Duplicate Map Keys, Inner "" Clearing, & -0.0 / Inf Blind JSON
# ============================================================================


def test_schema_meta_duplicate_map_key_overwrites_while_separate_blocks_merge() -> None:
    child_first = Encoder()
    child_first.write_string(1, "First")
    child_first.begin_map(2, WIRE_UINT, WIRE_STRING, 1)
    child_first.write_varint(1)
    child_first.write_varint(3)
    child_first.write_raw(b"old")
    child_first.end_map()
    b_first = child_first.finish()

    child_second = Encoder()
    child_second.write_string(1, "Second")
    child_second.begin_map(2, WIRE_UINT, WIRE_STRING, 1)
    child_second.write_varint(2)
    child_second.write_varint(3)
    child_second.write_raw(b"new")
    child_second.end_map()
    b_second = child_second.finish()

    # Single WireMap on field 3 with duplicate key 1: second entry MUST overwrite first (not merge)
    dup_map_body = bytearray()
    dup_map_body.append(WIRE_UINT)
    dup_map_body.append(WIRE_SUB_MSG)
    dup_map_body.extend(encode_varint(2))  # 2 entries, both key=1
    dup_map_body.extend(encode_varint(1))
    dup_map_body.extend(encode_varint(len(b_first)))
    dup_map_body.extend(b_first)
    dup_map_body.extend(encode_varint(1))
    dup_map_body.extend(encode_varint(len(b_second)))
    dup_map_body.extend(b_second)

    meta_wire = encode_tag(3, WIRE_MAP) + encode_varint(len(dup_map_body)) + bytes(dup_map_body)
    parsed_single = decode_schema_meta(meta_wire)
    assert parsed_single.children[1].type_name == "Second"
    assert parsed_single.children[1].fields == {2: "new"}

    # Separate Field #0 blocks: recursive merge keeps field 1 ("old") AND field 2 ("new")
    m1 = SchemaMeta(
        type_name="Root", children={1: SchemaMeta(type_name="First", fields={1: "old"})}
    )
    m2 = SchemaMeta(
        type_name="Root", children={1: SchemaMeta(type_name="Second", fields={2: "new"})}
    )
    enc_pkt = Encoder()
    enc_pkt.write_raw(encode_field0_schema_meta(m1))
    enc_pkt.write_raw(encode_field0_schema_meta(m2))
    enc_pkt.begin_submsg(1)
    enc_pkt.write_uint32(1, 10)
    enc_pkt.write_uint32(2, 20)
    enc_pkt.end_submsg()
    assert decode_blind(enc_pkt.finish()) == {"field_1": {"old": 10, "new": 20}}


def test_inner_empty_field0_name_clears_inherited_name_and_blind_json_neg_zero() -> None:
    outer_meta = SchemaMeta(
        type_name="Outer",
        fields={1: "sub"},
        children={1: SchemaMeta(type_name="Sub", fields={1: "inherited_x"})},
    )
    inner_clear = SchemaMeta(type_name="Sub", fields={1: ""})

    enc = Encoder()
    enc.write_raw(encode_field0_schema_meta(outer_meta))
    enc.begin_submsg(1)
    enc.write_raw(encode_field0_schema_meta(inner_clear))
    enc.write_uint32(1, 55)
    enc.end_submsg()
    assert decode_blind(enc.finish()) == {"sub": {"field_1": 55}}

    # Verify -0.0 preserved in decode_blind_json for both allow_nan=False and allow_nan=True
    enc_nz = Encoder()
    enc_nz.write_float32(1, -0.0)
    enc_nz.write_float64(2, -0.0)
    nz_pkt = enc_nz.finish()
    assert decode_blind_json(nz_pkt, allow_nan=False) == '{"field_1":-0.0,"field_2":-0.0}'
    assert decode_blind_json(nz_pkt, allow_nan=True) == '{"field_1":-0.0,"field_2":-0.0}'


# ============================================================================
# 11. @omnibuf_message Enums, NonePolicy, Optional Containers, -0.0, BytesAsStr
# ============================================================================


def test_dataclass_enums_and_invalid_enum_decode_error() -> None:
    class RoleInt(enum.IntEnum):
        UNKNOWN = 0
        PRIMARY = 1
        STANDBY = -2

    class PlainStatus(enum.Enum):
        IDLE = 0
        ACTIVE = 5

    @omnibuf_message
    class NodeState:
        role: RoleInt = omnibuf_field(1, default=RoleInt.UNKNOWN)
        status: PlainStatus = omnibuf_field(2, default=PlainStatus.IDLE)
        history: list[RoleInt] = omnibuf_field(3, default_factory=list)
        by_peer: dict[str, PlainStatus] = omnibuf_field(4, default_factory=dict)

    state = NodeState(
        role=RoleInt.STANDBY,
        status=PlainStatus.ACTIVE,
        history=[RoleInt.PRIMARY, RoleInt.STANDBY],
        by_peer={"p1": PlainStatus.ACTIVE},
    )
    raw = marshal(state, deterministic=True)
    decoded = unmarshal(raw, NodeState)
    assert decoded == state
    assert isinstance(decoded.role, RoleInt)
    assert isinstance(decoded.status, PlainStatus)

    # Unknown closed enum value on wire raises OmniBufDecodeError (not bare ValueError)
    enc_bad = Encoder()
    enc_bad.write_sint32(2, 999)
    with pytest.raises(OmniBufDecodeError):
        unmarshal(enc_bad.finish(), NodeState)


def test_none_policy_class_name_and_optional_container_elements_rejected() -> None:
    class NonePolicy:
        pass

    # NonePolicy contains "None" in its name, so it must NOT receive an implicit default=None
    @omnibuf_message
    class BadMissingDefault:
        policy: NonePolicy = omnibuf_field(1)

    with pytest.raises(TypeError):
        BadMissingDefault()  # type: ignore[call-arg]

    @omnibuf_message
    class GoodOptionalPolicy:
        policy: NonePolicy | None = omnibuf_field(1)

    assert GoodOptionalPolicy().policy is None  # type: ignore[call-arg]

    @omnibuf_message
    class BadOptList:
        items: list[int | None] = omnibuf_field(1, default_factory=list)

    with pytest.raises(OmniBufEncodeError):
        marshal(BadOptList())

    @omnibuf_message
    class BadOptMapVal:
        mapping: dict[str, int | None] = omnibuf_field(1, default_factory=dict)

    with pytest.raises(OmniBufEncodeError):
        marshal(BadOptMapVal())


def test_bytes_as_str_encode_error_and_neg_zero_omitempty_and_deep_recursive_field0() -> None:
    @omnibuf_message
    class RawLabel:
        text: bytes = omnibuf_field(1, wire="string", default=b"")

    with pytest.raises(OmniBufEncodeError):
        marshal(RawLabel(text=b"\xff\xfe"))

    @omnibuf_message
    class SignedZeroMsg:
        f32: Float32 = omnibuf_field(1, default=0.0, omitempty=True)
        f64: Float64 = omnibuf_field(2, default=0.0, omitempty=True)

    # +0.0 is omitted when omitempty=True, whereas -0.0 is emitted and preserves sign bit!
    assert marshal(SignedZeroMsg(f32=0.0, f64=0.0)) == b""
    neg_raw = marshal(SignedZeroMsg(f32=-0.0, f64=-0.0))
    assert len(neg_raw) > 0
    neg_dec = unmarshal(neg_raw, SignedZeroMsg)
    assert math.copysign(1.0, neg_dec.f32) == -1.0
    assert math.copysign(1.0, neg_dec.f64) == -1.0

    # Deep recursive TreeNode self_describing=True populates SchemaMeta down active levels
    deep = TreeNode(
        id=1,
        name="L1",
        primary=TreeNode(
            id=2,
            name="L2",
            primary=TreeNode(
                id=3,
                name="L3",
                children=[TreeNode(id=4, name="L4")],
            ),
        ),
    )
    sd = marshal(deep, self_describing=True)
    blind = decode_blind(sd)
    assert blind["name"] == "L1"
    assert blind["primary"]["name"] == "L2"
    assert blind["primary"]["primary"]["name"] == "L3"
    assert blind["primary"]["primary"]["children"][0]["name"] == "L4"


# ============================================================================
# 12. Lazy google.protobuf Import Verification
# ============================================================================


def test_omnibuf_works_without_google_protobuf_installed() -> None:
    script = """
import sys
sys.modules["google.protobuf"] = None
sys.modules["google.protobuf.message"] = None
sys.modules["google.protobuf.descriptor"] = None

import omnibuf
from omnibuf import Uint32, omnibuf_field, omnibuf_message
from omnibuf.gen.omnibuf.bench import peer_omnibuf_pb, peer_pb

@omnibuf_message
class Ping:
    seq: Uint32 = omnibuf_field(1, default=0)
    msg: str = omnibuf_field(2, default="")

raw = omnibuf.marshal(Ping(seq=7, msg="ok"), self_describing=True)
assert omnibuf.unmarshal(raw, Ping) == Ping(seq=7, msg="ok")
assert omnibuf.decode_blind(raw) == {"seq": 7, "msg": "ok"}

pb = peer_pb.PeerUpdate(asn=64512, router_id="r1", sequence=99)
pb_wire = omnibuf.marshal(pb)
assert omnibuf.unmarshal(pb_wire, peer_pb.PeerUpdate).sequence == 99
assert peer_omnibuf_pb.OpaquePeerUpdate(pb_wire).get_sequence() == 99
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
