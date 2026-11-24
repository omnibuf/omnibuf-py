"""Unit tests for the protoc-gen-omnibuf-py code generator plugin."""

from __future__ import annotations

import dataclasses
import sys
import types
from typing import Any

import pytest
from google.protobuf import descriptor_pb2
from google.protobuf.compiler import plugin_pb2

import omnibuf
from omnibuf import OmniBufEncodeError
from omnibuf import wire as omnibuf_wire
from omnibuf.plugin import generate_code
from omnibuf.wire import encode_tag, encode_varint


def test_plugin_generates_relative_cross_file_imports() -> None:
    req = plugin_pb2.CodeGeneratorRequest()
    f_common = req.proto_file.add()
    f_common.name = "acme/common/types.proto"
    f_common.package = "acme.common"
    f_common.syntax = "proto3"
    m_tag = f_common.message_type.add()
    m_tag.name = "Tag"
    fd_k = m_tag.field.add()
    fd_k.name = "key"
    fd_k.number = 1
    fd_k.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd_k.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

    f_svc = req.proto_file.add()
    f_svc.name = "acme/service/item.proto"
    f_svc.package = "acme.service"
    f_svc.syntax = "proto3"
    f_svc.dependency.append("acme/common/types.proto")
    m_item = f_svc.message_type.add()
    m_item.name = "Item"
    fd_t = m_item.field.add()
    fd_t.name = "tag"
    fd_t.number = 1
    fd_t.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd_t.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    fd_t.type_name = ".acme.common.Tag"

    req.file_to_generate.extend(["acme/common/types.proto", "acme/service/item.proto"])
    resp = generate_code(req)
    assert not resp.error
    by_name = {f.name: f.content for f in resp.file}
    assert (
        "from ..common import types_omnibuf_pb as _imp_0"
        in by_name["acme/service/item_omnibuf_pb.py"]
    )


def test_plugin_field_named_field_does_not_shadow_dataclass_field() -> None:
    """A proto field named `field` followed by a repeated field must not shadow `dataclasses.field`."""
    req = plugin_pb2.CodeGeneratorRequest()
    fdp = req.proto_file.add()
    fdp.name = "shadow_field.proto"
    fdp.package = "test.codegen"
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


def test_plugin_keyword_suffix_collision() -> None:
    """Fields `from` and `from_` must not map to the same `from_` dataclass attribute."""
    req = plugin_pb2.CodeGeneratorRequest()
    fdp = req.proto_file.add()
    fdp.name = "collisions.proto"
    fdp.package = "test.codegen"
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


def test_plugin_marshal_omnibuf_field_collision() -> None:
    """A proto field named `marshal_omnibuf` must not clobber the generated marshal_omnibuf method."""
    req = plugin_pb2.CodeGeneratorRequest()
    fdp = req.proto_file.add()
    fdp.name = "method_collision.proto"
    fdp.package = "test.codegen"
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


def test_plugin_hyphenated_proto_import_valid_syntax() -> None:
    """Importing `api-types.proto` from `svc.proto` must generate syntactically valid Python."""
    req = plugin_pb2.CodeGeneratorRequest()

    f_dep = req.proto_file.add()
    f_dep.name = "api-types.proto"
    f_dep.package = "test.codegen"
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
    f_svc.package = "test.codegen"
    f_svc.syntax = "proto3"
    f_svc.dependency.append("api-types.proto")
    m_svc = f_svc.message_type.add()
    m_svc.name = "SvcRequest"
    fd_ref = m_svc.field.add()
    fd_ref.name = "auth"
    fd_ref.number = 1
    fd_ref.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    fd_ref.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    fd_ref.type_name = ".test.codegen.ApiToken"

    req.file_to_generate.extend(["api-types.proto", "svc.proto"])
    resp = generate_code(req)
    assert not resp.error, f"Generator returned error: {resp.error}"

    by_name = {f.name: f.content for f in resp.file}
    svc_file = next(name for name in by_name if name.startswith("svc"))
    compile(by_name[svc_file], svc_file, "exec")


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
