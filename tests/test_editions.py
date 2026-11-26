"""End-to-end and unit tests for Protobuf Editions 2023, 2024, and 2026."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import types
from pathlib import Path
from typing import Any, cast

import protobuf as pbpy
import pytest
from google.protobuf import descriptor_pb2 as d
from google.protobuf.compiler import plugin_pb2

import omnibuf
from omnibuf import OmniBufDecodeError, OmniBufEncodeError, decode_blind
from omnibuf.editions import EDITION_2023, EDITION_2024, EDITION_2026
from omnibuf.plugin import generate_code
from omnibuf.protobuf_codec import marshal_proto, unmarshal_proto

_PROTOC = shutil.which("protoc")
_PROTOC_GEN_PY = Path(sys.executable).resolve().parent / "protoc-gen-py"


def _require_protoc() -> str:
    if _PROTOC is None:
        pytest.skip("protoc not installed in PATH")
    return _PROTOC


def _load_py_module(path: Path, mod_name: str) -> Any:
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _compile_protos(
    tmp_path: Path,
    files: dict[str, str],
    targets: list[str],
    *,
    tag: str,
    with_pbpy: bool = True,
) -> tuple[d.FileDescriptorSet, dict[str, Any], dict[str, Any]]:
    """Compile real .proto files with protoc into FDS, google.protobuf (_pb2), and protobuf-py (_pb)."""
    protoc = _require_protoc()
    proto_dir = tmp_path / f"src_{tag}"
    gpb_dir = tmp_path / f"gpb_{tag}"
    pbpy_dir = tmp_path / f"pbpy_{tag}"
    proto_dir.mkdir(parents=True, exist_ok=True)
    gpb_dir.mkdir(parents=True, exist_ok=True)
    pbpy_dir.mkdir(parents=True, exist_ok=True)

    for rel, content in files.items():
        fp = proto_dir / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")

    all_rels = list(files.keys())
    all_paths = [str(proto_dir / rel) for rel in all_rels]
    fds_path = tmp_path / f"{tag}.fds"
    res_gpb = subprocess.run(
        [
            protoc,
            f"-I{proto_dir}",
            f"--descriptor_set_out={fds_path}",
            "--include_imports",
            f"--python_out={gpb_dir}",
            *all_paths,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert res_gpb.returncode == 0, f"protoc failed ({tag}):\n{res_gpb.stderr}"
    fds = d.FileDescriptorSet()
    fds.ParseFromString(fds_path.read_bytes())

    gpb_mods: dict[str, Any] = {}
    pbpy_mods: dict[str, Any] = {}

    if with_pbpy and _PROTOC_GEN_PY.is_file():
        res_pbpy = subprocess.run(
            [
                protoc,
                f"-I{proto_dir}",
                f"--plugin=protoc-gen-py={_PROTOC_GEN_PY}",
                f"--py_out={pbpy_dir}",
                *all_paths,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert res_pbpy.returncode == 0, f"protoc-gen-py failed ({tag}):\n{res_pbpy.stderr}"

    # Import generated modules in dependency order so cross-file imports resolve cleanly.
    sys.path.insert(0, str(gpb_dir))
    try:
        for rel in targets:
            stem = rel.removesuffix(".proto").replace("/", "_")
            pb2_path = gpb_dir / f"{rel.removesuffix('.proto')}_pb2.py"
            gpb_mods[rel] = _load_py_module(pb2_path, f"_ed_{tag}_{stem}_pb2")
    finally:
        sys.path.remove(str(gpb_dir))

    if with_pbpy and _PROTOC_GEN_PY.is_file():
        sys.path.insert(0, str(pbpy_dir))
        try:
            for rel in targets:
                stem = rel.removesuffix(".proto").replace("/", "_")
                pb_path = pbpy_dir / f"{rel.removesuffix('.proto')}_pb.py"
                pbpy_mods[rel] = _load_py_module(pb_path, f"_ed_{tag}_{stem}_pb")
        finally:
            sys.path.remove(str(pbpy_dir))

    return fds, gpb_mods, pbpy_mods


def _generate_plugin_module(
    fds: d.FileDescriptorSet,
    targets: list[str],
    *,
    tag: str,
) -> tuple[plugin_pb2.CodeGeneratorResponse, dict[str, Any]]:
    req = plugin_pb2.CodeGeneratorRequest(
        file_to_generate=targets,
        proto_file=list(fds.file),
    )
    resp = generate_code(req)
    mods: dict[str, Any] = {}
    if resp.error:
        return resp, mods
    for out_f in resp.file:
        mod_name = f"_ed_gen_{tag}_{out_f.name.removesuffix('.py').replace('/', '_')}"
        mod = types.ModuleType(mod_name)
        sys.modules[mod_name] = mod
        exec(compile(out_f.content, out_f.name, "exec"), mod.__dict__)  # noqa: S102
        mods[out_f.name] = mod
    return resp, mods


def _make_full_editions_proto(edition_str: str, pkg: str, ext_base: int) -> str:
    export_kw = "export " if edition_str in ("2024", "2026") else ""
    extra_file_opts = ""
    if edition_str == "2024":
        extra_file_opts = "option features.enforce_naming_style = STYLE2024;\n"
    elif edition_str == "2026":
        extra_file_opts = (
            "option features.enforce_naming_style = STYLE2026;\n"
            "option features.default_symbol_visibility = STRICT;\n"
        )
    override_box = f"""{export_kw}message ImplicitOverrideBox {{
  int32 imp_from_msg = 1 [features.field_presence = IMPLICIT];
  int32 exp_field_override = 2 [features.field_presence = EXPLICIT];
  message NestedExplicit {{
    int32 nested_exp = 1 [features.field_presence = EXPLICIT];
    int32 nested_imp = 2 [features.field_presence = IMPLICIT];
  }}
  NestedExplicit nested = 3;
}}"""

    return f"""edition = "{edition_str}";
package {pkg};

import "google/protobuf/descriptor.proto";

{extra_file_opts}option features.json_format = LEGACY_BEST_EFFORT;

extend google.protobuf.FileOptions {{
  string custom_file_tag{edition_str} = {ext_base + 1};
}}

extend google.protobuf.MessageOptions {{
  string custom_msg_tag{edition_str} = {ext_base + 2};
}}

extend google.protobuf.FieldOptions {{
  string custom_field_tag{edition_str} = {ext_base + 3};
}}

option (custom_file_tag{edition_str}) = "ed-{edition_str}";

{export_kw}enum OpenStatus {{
  OPEN_STATUS_UNSPECIFIED = 0;
  OPEN_STATUS_READY = 1;
  OPEN_STATUS_PAUSED = 2;
}}

{export_kw}message Child {{
  int32 id = 1;
  string label = 2 [features.field_presence = IMPLICIT];
}}

{override_box}

{export_kw}message FullRecord {{
  option (custom_msg_tag{edition_str}) = "record";

  // Explicit presence scalars (Editions default) + allowed explicit zero defaults
  int32 exp_i32 = 1 [default = 0, (custom_field_tag{edition_str}) = "f1"];
  double exp_f64 = 2 [default = 0.0];
  float exp_f32 = 3 [default = 0.0];
  bool exp_bool = 4 [default = false];
  string exp_str = 5 [default = ""];
  bytes exp_bytes = 6 [default = ""];
  OpenStatus exp_enum = 7 [default = OPEN_STATUS_UNSPECIFIED];

  // Implicit presence scalars
  int32 imp_i32 = 8 [features.field_presence = IMPLICIT];
  bool imp_bool = 9 [features.field_presence = IMPLICIT];
  string imp_str = 10 [features.field_presence = IMPLICIT];

  // Repeated (PACKED and EXPANDED)
  repeated int32 packed_nums = 11 [features.repeated_field_encoding = PACKED];
  repeated int32 expanded_nums = 12 [features.repeated_field_encoding = EXPANDED];
  repeated string labels = 13;

  // Maps
  map<string, int32> scores = 14;
  map<string, Child> children_by_key = 15;
  map<string, OpenStatus> statuses = 16;

  // Nested LENGTH_PREFIXED and DELIMITED messages (singular and repeated)
  Child lp_child = 17;
  Child delim_child = 18 [features.message_encoding = DELIMITED];
  repeated Child delim_list = 19 [features.message_encoding = DELIMITED];

  // Oneof with scalar, bool, string, bytes, and DELIMITED message branches
  oneof payload {{
    int32 oo_i32 = 20;
    bool oo_bool = 21;
    string oo_str = 22;
    bytes oo_bytes = 23;
    Child oo_delim = 24 [features.message_encoding = DELIMITED];
  }}

  ImplicitOverrideBox overrides = 25;
}}
"""


@pytest.mark.parametrize("edition", [EDITION_2023, EDITION_2024, EDITION_2026])
def test_editions_synthetic_presence_and_response_metadata(edition: int) -> None:
    file = d.FileDescriptorProto(
        name="ed.proto", syntax="editions", edition=cast(d.Edition.ValueType, edition)
    )
    file.options.features.field_presence = d.FeatureSet.IMPLICIT
    msg = file.message_type.add(name="Record")
    msg.options.features.field_presence = d.FeatureSet.EXPLICIT
    msg.field.add(name="explicit", number=1, type=5, label=1)
    msg.field.add(
        name="implicit", number=2, type=5, label=1
    ).options.features.field_presence = d.FeatureSet.IMPLICIT

    response = generate_code(
        plugin_pb2.CodeGeneratorRequest(file_to_generate=[file.name], proto_file=[file])
    )
    assert not response.error
    assert response.supported_features == 3
    assert (response.minimum_edition, response.maximum_edition) == (EDITION_2023, EDITION_2026)

    module: Any = types.ModuleType(f"_ed_synth_{edition}_omnibuf_pb")
    sys.modules[module.__name__] = module
    try:
        exec(response.file[0].content, module.__dict__)  # noqa: S102
        absent = module.Record()
        present = module.Record(explicit=0)
        assert absent.explicit is None
        assert present.explicit == 0
        assert absent.implicit == 0
        assert absent.marshal_omnibuf() != present.marshal_omnibuf()
        dec_absent = module.unmarshal_record(absent.marshal_omnibuf())
        dec_present = module.unmarshal_record(present.marshal_omnibuf())
        assert dec_absent.explicit is None
        assert dec_present.explicit == 0
    finally:
        sys.modules.pop(module.__name__, None)
    # Input FileDescriptorProto must never be mutated.
    assert file.syntax == "editions"
    assert file.edition == edition


@pytest.mark.parametrize(
    ("edition_str", "edition_num", "ext_base"),
    [
        ("2023", EDITION_2023, 51100),
        ("2024", EDITION_2024, 51200),
        ("2026", EDITION_2026, 51300),
    ],
)
def test_e2e_editions_2023_2024_2026_full_cross_tier_equivalence(
    tmp_path: Path,
    edition_str: str,
    edition_num: int,
    ext_base: int,
) -> None:
    """Compile real Editions 2023/2024/2026 .proto files and verify Tier 1, Opaque, GPB, and pbpy."""
    pkg = f"edfull{edition_str}"
    fname = f"full_{edition_str}.proto"
    fds, gpb_mods, pbpy_mods = _compile_protos(
        tmp_path,
        {fname: _make_full_editions_proto(edition_str, pkg, ext_base)},
        [fname],
        tag=f"full_{edition_str}",
    )
    assert any(f.name == fname and f.edition == edition_num for f in fds.file)

    resp, gen_mods = _generate_plugin_module(fds, [fname], tag=f"full_{edition_str}")
    assert not resp.error, resp.error
    assert resp.supported_features == 3
    assert (resp.minimum_edition, resp.maximum_edition) == (EDITION_2023, EDITION_2026)

    gen = gen_mods[f"full_{edition_str}_omnibuf_pb.py"]
    gpb = gpb_mods[fname]
    pbp = pbpy_mods.get(fname)

    # 1. Empty / absent message: explicit fields omitted, implicit fields emitted, all tiers match.
    gen_absent = gen.FullRecord()
    gpb_absent = gpb.FullRecord()
    w_gen_absent = gen_absent.marshal_omnibuf(deterministic=True)
    w_gpb_absent = marshal_proto(gpb_absent, deterministic=True)
    assert w_gen_absent == w_gpb_absent
    if pbp is not None:
        pbp_absent = pbp.FullRecord()
        w_pbp_absent = marshal_proto(pbp_absent, deterministic=True)
        assert w_pbp_absent == w_gen_absent

    dec_gen_abs = gen.unmarshal_full_record(w_gen_absent)
    assert dec_gen_abs.exp_i32 is None
    assert dec_gen_abs.exp_f64 is None
    assert dec_gen_abs.exp_f32 is None
    assert dec_gen_abs.exp_bool is None
    assert dec_gen_abs.exp_str is None
    assert dec_gen_abs.exp_bytes is None
    assert dec_gen_abs.exp_enum is None
    assert dec_gen_abs.lp_child is None
    assert dec_gen_abs.delim_child is None
    assert dec_gen_abs.which_payload() is None

    dec_gpb_abs = unmarshal_proto(w_gen_absent, gpb.FullRecord)
    for f_name in (
        "exp_i32",
        "exp_f64",
        "exp_f32",
        "exp_bool",
        "exp_str",
        "exp_bytes",
        "exp_enum",
        "lp_child",
        "delim_child",
    ):
        assert not dec_gpb_abs.HasField(f_name), f"{f_name} should be absent"
    assert dec_gpb_abs.WhichOneof("payload") is None

    # 2. Explicit zero / False / empty values vs absent: wire differs and presence round-trips.
    gen_zeros = gen.FullRecord(
        exp_i32=0,
        exp_f64=0.0,
        exp_f32=0.0,
        exp_bool=False,
        exp_str="",
        exp_bytes=b"",
        exp_enum=0,
        lp_child=gen.Child(),
        delim_child=gen.Child(),
        oo_bool=False,
        overrides=gen.ImplicitOverrideBox(
            imp_from_msg=0,
            exp_field_override=0,
            nested=gen.ImplicitOverrideBox_NestedExplicit(nested_exp=0, nested_imp=0),
        ),
    )
    gpb_zeros = gpb.FullRecord(
        exp_i32=0,
        exp_f64=0.0,
        exp_f32=0.0,
        exp_bool=False,
        exp_str="",
        exp_bytes=b"",
        exp_enum=0,
        lp_child=gpb.Child(),
        delim_child=gpb.Child(),
        oo_bool=False,
        overrides=gpb.ImplicitOverrideBox(
            imp_from_msg=0,
            exp_field_override=0,
            nested=gpb.ImplicitOverrideBox.NestedExplicit(nested_exp=0, nested_imp=0),
        ),
    )
    w_gen_zeros = gen_zeros.marshal_omnibuf(deterministic=True)
    w_gpb_zeros = marshal_proto(gpb_zeros, deterministic=True)
    assert w_gen_zeros != w_gen_absent
    assert w_gen_zeros == w_gpb_zeros

    if pbp is not None:
        pbp_zeros = pbp.FullRecord(
            exp_i32=0,
            exp_f64=0.0,
            exp_f32=0.0,
            exp_bool=False,
            exp_str="",
            exp_bytes=b"",
            exp_enum=pbp.OpenStatus(0),
            lp_child=pbp.Child(),
            delim_child=pbp.Child(),
            payload=pbpy.Oneof("oo_bool", False),
            overrides=pbp.ImplicitOverrideBox(
                imp_from_msg=0,
                exp_field_override=0,
                nested=pbp.ImplicitOverrideBox.NestedExplicit(nested_exp=0, nested_imp=0),
            ),
        )
        w_pbp_zeros = marshal_proto(pbp_zeros, deterministic=True)
        assert w_pbp_zeros == w_gen_zeros

        dec_pbp_z = unmarshal_proto(w_gen_zeros, pbp.FullRecord)
        for f_name in (
            "exp_i32",
            "exp_f64",
            "exp_f32",
            "exp_bool",
            "exp_str",
            "exp_bytes",
            "exp_enum",
            "lp_child",
            "delim_child",
            "oo_bool",
        ):
            assert dec_pbp_z.has_field(f_name), f"pbpy {f_name} lost presence"
        assert dec_pbp_z.payload == pbpy.Oneof("oo_bool", False)
        assert dec_pbp_z.overrides is not None
        assert dec_pbp_z.overrides.has_field("exp_field_override")
        assert dec_pbp_z.overrides.nested is not None
        assert dec_pbp_z.overrides.nested.has_field("nested_exp")

    dec_gen_z = gen.unmarshal_full_record(w_gpb_zeros)
    assert dec_gen_z.exp_i32 == 0
    assert dec_gen_z.exp_f64 == 0.0
    assert dec_gen_z.exp_f32 == 0.0
    assert dec_gen_z.exp_bool is False
    assert dec_gen_z.exp_str == ""
    assert dec_gen_z.exp_bytes == b""
    assert dec_gen_z.exp_enum == 0
    assert dec_gen_z.lp_child == gen.Child()
    assert dec_gen_z.delim_child == gen.Child()
    assert dec_gen_z.which_payload() == "oo_bool"
    assert dec_gen_z.oo_bool is False
    assert dec_gen_z.overrides is not None
    assert dec_gen_z.overrides.exp_field_override == 0
    assert dec_gen_z.overrides.nested is not None
    assert dec_gen_z.overrides.nested.nested_exp == 0

    dec_gpb_z = unmarshal_proto(w_gen_zeros, gpb.FullRecord)
    for f_name in (
        "exp_i32",
        "exp_f64",
        "exp_f32",
        "exp_bool",
        "exp_str",
        "exp_bytes",
        "exp_enum",
        "lp_child",
        "delim_child",
    ):
        assert dec_gpb_z.HasField(f_name), f"gpb {f_name} lost presence"
    assert dec_gpb_z.WhichOneof("payload") == "oo_bool"
    assert dec_gpb_z.oo_bool is False
    assert dec_gpb_z.overrides.HasField("exp_field_override")
    assert dec_gpb_z.overrides.nested.HasField("nested_exp")

    # 3. Populated record: open unknown enum, PACKED/EXPANDED arrays, maps, DELIMITED singular/repeated/oneof.
    gen_pop = gen.FullRecord(
        exp_i32=-42,
        exp_f64=3.25,
        exp_f32=-1.5,
        exp_bool=True,
        exp_str="editions-ok",
        exp_bytes=b"\x00\x01\xff",
        exp_enum=99,  # Unknown open enum value preserved!
        imp_i32=7,
        imp_bool=True,
        imp_str="imp",
        packed_nums=[1, -2, 3],
        expanded_nums=[10, 20, -30],
        labels=["a", "b"],
        scores={"alpha": 1, "beta": -5},
        children_by_key={"c1": gen.Child(id=1, label="one"), "c2": gen.Child(id=2, label="two")},
        statuses={"known": 1, "unknown": 77},
        lp_child=gen.Child(id=10, label="lp"),
        delim_child=gen.Child(id=11, label="delim"),
        delim_list=[gen.Child(id=12, label="d0"), gen.Child(id=13, label="d1")],
        oo_delim=gen.Child(id=14, label="oo-delim"),
    )
    gpb_pop = gpb.FullRecord(
        exp_i32=-42,
        exp_f64=3.25,
        exp_f32=-1.5,
        exp_bool=True,
        exp_str="editions-ok",
        exp_bytes=b"\x00\x01\xff",
        exp_enum=99,
        imp_i32=7,
        imp_bool=True,
        imp_str="imp",
        packed_nums=[1, -2, 3],
        expanded_nums=[10, 20, -30],
        labels=["a", "b"],
        scores={"alpha": 1, "beta": -5},
        children_by_key={"c1": gpb.Child(id=1, label="one"), "c2": gpb.Child(id=2, label="two")},
        statuses={"known": 1, "unknown": 77},
        lp_child=gpb.Child(id=10, label="lp"),
        delim_child=gpb.Child(id=11, label="delim"),
        delim_list=[gpb.Child(id=12, label="d0"), gpb.Child(id=13, label="d1")],
        oo_delim=gpb.Child(id=14, label="oo-delim"),
    )
    w_gen_pop = gen_pop.marshal_omnibuf(deterministic=True)
    w_gpb_pop = marshal_proto(gpb_pop, deterministic=True)
    assert w_gen_pop == w_gpb_pop

    # Self-describing wire equivalence and blind decode!
    sd_gen = gen_pop.marshal_omnibuf(deterministic=True, self_describing=True)
    sd_gpb = marshal_proto(gpb_pop, deterministic=True, self_describing=True)
    assert sd_gen == sd_gpb
    blind = decode_blind(sd_gen)
    assert blind["exp_enum"] == 99
    assert blind["delim_child"]["label"] == "delim"
    assert blind["delim_list"][1]["id"] == 13
    assert blind["oo_delim"]["label"] == "oo-delim"

    # Cross-decode GPB -> Tier 1 and Tier 1 -> GPB
    dec_gen_pop = gen.unmarshal_full_record(w_gpb_pop)
    assert dec_gen_pop == gen_pop
    assert dec_gen_pop.exp_enum == 99
    assert dec_gen_pop.statuses["unknown"] == 77
    assert dec_gen_pop.delim_child == gen.Child(id=11, label="delim")
    assert dec_gen_pop.which_payload() == "oo_delim"

    dec_gpb_pop = unmarshal_proto(w_gen_pop, gpb.FullRecord)
    assert dec_gpb_pop.exp_enum == 99
    assert dec_gpb_pop.statuses["unknown"] == 77
    assert dec_gpb_pop.delim_child.id == 11
    assert dec_gpb_pop.delim_child.label == "delim"
    assert [c.id for c in dec_gpb_pop.delim_list] == [12, 13]
    assert dec_gpb_pop.WhichOneof("payload") == "oo_delim"
    assert dec_gpb_pop.oo_delim.id == 14

    if pbp is not None:
        pbp_pop = pbp.FullRecord(
            exp_i32=-42,
            exp_f64=3.25,
            exp_f32=-1.5,
            exp_bool=True,
            exp_str="editions-ok",
            exp_bytes=b"\x00\x01\xff",
            exp_enum=99,
            imp_i32=7,
            imp_bool=True,
            imp_str="imp",
            packed_nums=[1, -2, 3],
            expanded_nums=[10, 20, -30],
            labels=["a", "b"],
            scores={"alpha": 1, "beta": -5},
            children_by_key={
                "c1": pbp.Child(id=1, label="one"),
                "c2": pbp.Child(id=2, label="two"),
            },
            statuses={"known": pbp.OpenStatus(1), "unknown": 77},
            lp_child=pbp.Child(id=10, label="lp"),
            delim_child=pbp.Child(id=11, label="delim"),
            delim_list=[pbp.Child(id=12, label="d0"), pbp.Child(id=13, label="d1")],
            payload=pbpy.Oneof("oo_delim", pbp.Child(id=14, label="oo-delim")),
        )
        w_pbp_pop = marshal_proto(pbp_pop, deterministic=True)
        assert w_pbp_pop == w_gen_pop
        dec_pbp_pop = unmarshal_proto(w_gen_pop, pbp.FullRecord)
        assert int(dec_pbp_pop.exp_enum) == 99
        assert int(dec_pbp_pop.statuses["unknown"]) == 77
        assert dec_pbp_pop.delim_child is not None
        assert dec_pbp_pop.delim_child.label == "delim"
        assert [c.id for c in dec_pbp_pop.delim_list] == [12, 13]
        assert dec_pbp_pop.payload is not None
        assert dec_pbp_pop.payload.field == "oo_delim"
        assert dec_pbp_pop.payload.value.id == 14

    # 4. Opaque* views: absent vs present-zero, setting explicit zeros, clearing, delimited submsg, oneof switching.
    op_abs = gen.OpaqueFullRecord(w_gen_absent)
    op_abs.validate()
    assert op_abs.has_exp_i32() is False
    assert op_abs.get_exp_i32() is None
    assert op_abs.has_exp_bool() is False
    assert op_abs.get_exp_bool() is None
    assert op_abs.has_exp_str() is False
    assert op_abs.get_exp_str() is None
    assert op_abs.has_exp_bytes() is False
    assert op_abs.get_exp_bytes() is None
    assert op_abs.get_exp_bytes_view() is None
    assert op_abs.has_exp_enum() is False
    assert op_abs.get_exp_enum() is None
    assert op_abs.has_delim_child() is False
    assert op_abs.opaque_delim_child() is None
    assert op_abs.which_payload() is None

    # Set explicit zeros via Opaque and splice/marshal!
    op_abs.set_exp_i32(0)
    op_abs.set_exp_f64(0.0)
    op_abs.set_exp_f32(0.0)
    op_abs.set_exp_bool(False)
    op_abs.set_exp_str("")
    op_abs.set_exp_bytes(b"")
    op_abs.set_exp_enum(0)
    op_abs.set_oo_str("")
    assert op_abs.has_exp_i32() is True
    assert op_abs.get_exp_i32() == 0
    assert op_abs.has_exp_bool() is True
    assert op_abs.get_exp_bool() is False
    assert op_abs.has_exp_str() is True
    assert op_abs.get_exp_str() == ""
    assert op_abs.has_exp_bytes() is True
    assert op_abs.get_exp_bytes() == b""
    bv = op_abs.get_exp_bytes_view()
    assert bv is not None and bytes(bv) == b""
    assert op_abs.has_exp_enum() is True
    assert op_abs.get_exp_enum() == 0
    assert op_abs.which_payload() == "oo_str"
    spliced_z = op_abs.marshal()
    dec_spliced_z = gen.unmarshal_full_record(spliced_z)
    assert dec_spliced_z.exp_i32 == 0
    assert dec_spliced_z.exp_bool is False
    assert dec_spliced_z.exp_str == ""
    assert dec_spliced_z.exp_bytes == b""
    assert dec_spliced_z.exp_enum == 0
    assert dec_spliced_z.which_payload() == "oo_str"
    assert dec_spliced_z.oo_str == ""

    # Single-field clear (hits splice_single_fast) and multi-field clear on OpaqueFullRecord!
    op_single_clear = gen.OpaqueFullRecord(spliced_z)
    op_single_clear.set_exp_i32(None)
    assert op_single_clear.has_exp_i32() is False
    assert op_single_clear.get_exp_i32() is None
    w_cleared_1 = op_single_clear.marshal()
    dec_cleared_1 = gen.unmarshal_full_record(w_cleared_1)
    assert dec_cleared_1.exp_i32 is None
    assert dec_cleared_1.exp_bool is False

    op_multi_clear = gen.OpaqueFullRecord(w_cleared_1)
    op_multi_clear.set_exp_bool(None)
    op_multi_clear.set_exp_str(None)
    op_multi_clear.set_exp_bytes(None)
    op_multi_clear.set_exp_enum(None)
    op_multi_clear.set_oo_str(None)
    w_cleared_all = op_multi_clear.marshal()
    dec_cleared_all = gen.unmarshal_full_record(w_cleared_all)
    assert dec_cleared_all.exp_bool is None
    assert dec_cleared_all.exp_str is None
    assert dec_cleared_all.exp_bytes is None
    assert dec_cleared_all.exp_enum is None
    assert dec_cleared_all.which_payload() is None

    # Opaque header-hop into DELIMITED submessage and oneof switching!
    op_pop = gen.OpaqueFullRecord(w_gen_pop)
    assert op_pop.get_exp_enum() == 99
    op_delim = op_pop.opaque_delim_child()
    assert op_delim is not None
    assert op_delim.get_id() == 11
    assert op_delim.get_label() == "delim"
    assert op_pop.which_payload() == "oo_delim"
    op_pop.set_oo_i32(0)
    assert op_pop.which_payload() == "oo_i32"
    assert op_pop.get_oo_i32() == 0
    assert op_pop.get_oo_delim() is None
    w_switched = op_pop.marshal()
    assert gen.unmarshal_full_record(w_switched).which_payload() == "oo_i32"
    assert unmarshal_proto(w_switched, gpb.FullRecord).WhichOneof("payload") == "oo_i32"
    assert unmarshal_proto(w_switched, gpb.FullRecord).oo_i32 == 0

    # Concatenated oneof switch: oo_delim -> oo_i32=0 -> oo_delim(id=55) across all tiers!
    w_concat = (
        gen.FullRecord(oo_delim=gen.Child(id=1, label="old")).marshal_omnibuf()
        + gen.FullRecord(oo_i32=0).marshal_omnibuf()
        + gen.FullRecord(oo_delim=gen.Child(id=55, label="new")).marshal_omnibuf()
    )
    assert gen.unmarshal_full_record(w_concat).oo_delim == gen.Child(id=55, label="new")
    gpb_concat = unmarshal_proto(w_concat, gpb.FullRecord)
    assert gpb_concat.WhichOneof("payload") == "oo_delim"
    assert gpb_concat.oo_delim.id == 55
    assert gpb_concat.oo_delim.label == "new"
    if pbp is not None:
        pbp_concat = unmarshal_proto(w_concat, pbp.FullRecord)
        assert pbp_concat.payload is not None
        assert pbp_concat.payload.field == "oo_delim"
        assert pbp_concat.payload.value.id == 55


def test_editions_file_implicit_override_and_no_string_utf8_none_allowed(tmp_path: Path) -> None:
    """File utf8_validation = NONE and file field_presence = IMPLICIT with overrides work across all tiers."""
    proto = """edition = "2026";
package edgeok;

option features.field_presence = IMPLICIT;
option features.utf8_validation = NONE;
option features.message_encoding = DELIMITED;

export message Sub {
  int32 v = 1;
}

export message SafeMsg {
  int32 imp_num = 1;
  int32 exp_num = 2 [features.field_presence = EXPLICIT];
  string verified_str = 3 [features.utf8_validation = VERIFY];
  map<string, int32> verified_map = 4 [features.utf8_validation = VERIFY];
  oneof pick {
    Sub sub_delim = 5;
    string oo_str = 6 [features.utf8_validation = VERIFY];
  }
}
"""
    fds, gpb_mods, pbpy_mods = _compile_protos(
        tmp_path,
        {"edgeok.proto": proto},
        ["edgeok.proto"],
        tag="edgeok",
    )
    resp, gen_mods = _generate_plugin_module(fds, ["edgeok.proto"], tag="edgeok")
    assert not resp.error, resp.error

    gen = gen_mods["edgeok_omnibuf_pb.py"]
    gpb = gpb_mods["edgeok.proto"]
    pbp = pbpy_mods.get("edgeok.proto")

    m_gen = gen.SafeMsg(imp_num=5, verified_str="ok", verified_map={"k": 1}, sub_delim=gen.Sub(v=9))
    m_gpb = gpb.SafeMsg(imp_num=5, verified_str="ok", verified_map={"k": 1}, sub_delim=gpb.Sub(v=9))
    w_gen = m_gen.marshal_omnibuf(deterministic=True)
    w_gpb = marshal_proto(m_gpb, deterministic=True)
    assert w_gen == w_gpb
    assert gen.unmarshal_safe_msg(w_gen).exp_num is None
    assert not unmarshal_proto(w_gen, gpb.SafeMsg).HasField("exp_num")
    if pbp is not None:
        m_pbp = pbp.SafeMsg(
            imp_num=5,
            verified_str="ok",
            verified_map={"k": 1},
            pick=pbpy.Oneof("sub_delim", pbp.Sub(v=9)),
        )
        assert marshal_proto(m_pbp, deterministic=True) == w_gen
        assert not unmarshal_proto(w_gen, pbp.SafeMsg).has_field("exp_num")


def test_editions_synthetic_oneof_feature_inheritance() -> None:
    """Synthetic descriptor tests verify oneof-level feature inheritance for UTF-8 and presence."""
    file = d.FileDescriptorProto(
        name="oo_feat.proto", syntax="editions", edition=cast(d.Edition.ValueType, EDITION_2026)
    )
    msg = file.message_type.add(name="Box")
    oo = msg.oneof_decl.add(name="choice")
    oo.options.features.utf8_validation = d.FeatureSet.NONE
    f1 = msg.field.add(name="text", number=1, type=9, label=1, oneof_index=0)
    resp = generate_code(
        plugin_pb2.CodeGeneratorRequest(file_to_generate=[file.name], proto_file=[file])
    )
    assert "utf-8" in resp.error.lower()

    # Overriding back to VERIFY on the field makes it valid.
    f1.options.features.utf8_validation = d.FeatureSet.VERIFY
    resp_ok = generate_code(
        plugin_pb2.CodeGeneratorRequest(file_to_generate=[file.name], proto_file=[file])
    )
    assert not resp_ok.error, resp_ok.error


@pytest.mark.parametrize("bad_edition", [0, 1003, 9999])
def test_unsupported_editions_rejected_in_plugin_and_reflection(bad_edition: int) -> None:
    file = d.FileDescriptorProto(name="bad_ed.proto", syntax="editions")
    msg = file.message_type.add(name="Item")
    msg.field.add(name="id", number=1, type=5, label=1)
    if bad_edition == 1003:
        # Simulate a future protoc sending raw edition varint 1003 (unknown closed enum value).
        raw_fdp = file.SerializeToString() + bytes([14 << 3, 0xEB, 0x07])
        file = d.FileDescriptorProto()
        file.ParseFromString(raw_fdp)
    else:
        file.edition = cast(d.Edition.ValueType, bad_edition)

    response = generate_code(
        plugin_pb2.CodeGeneratorRequest(file_to_generate=[file.name], proto_file=[file])
    )
    assert "unsupported protobuf edition" in response.error
    assert not response.file

    # Also verify protobuf_codec GPB reflection rejects unsupported editions (including raw 1003).
    class _FakeFileDesc:
        name = "bad_ed.proto"
        extensions_by_name: dict[str, Any] = {}
        enum_types_by_name: dict[str, Any] = {}

        def CopyToProto(self, out: d.FileDescriptorProto) -> None:
            out.CopyFrom(file)

    class _FakeDesc:
        full_name = "Item"
        name = "Item"
        file = _FakeFileDesc()
        fields: tuple[Any, ...] = ()
        extension_ranges: tuple[Any, ...] = ()
        extensions: tuple[Any, ...] = ()
        enum_types: tuple[Any, ...] = ()
        nested_types: tuple[Any, ...] = ()

    from omnibuf.protobuf_codec import _check_gpb_descriptor_supported

    with pytest.raises(OmniBufEncodeError, match="unsupported protobuf edition"):
        _check_gpb_descriptor_supported(_FakeDesc(), for_encode=True)
    with pytest.raises(OmniBufDecodeError, match="unsupported protobuf edition"):
        _check_gpb_descriptor_supported(_FakeDesc(), for_encode=False)


def _assert_rejected_everywhere(
    tmp_path: Path,
    files: dict[str, str],
    target: str,
    msg_name: str,
    err_substr: str,
    *,
    tag: str,
) -> None:
    fds, gpb_mods, pbpy_mods = _compile_protos(tmp_path, files, [target], tag=tag)

    # 1. Plugin rejects cleanly via CodeGeneratorResponse.error
    resp = generate_code(
        plugin_pb2.CodeGeneratorRequest(file_to_generate=[target], proto_file=list(fds.file))
    )
    assert resp.error, f"Expected plugin error containing {err_substr!r} for {tag}"
    assert err_substr.lower() in resp.error.lower(), resp.error
    assert not resp.file

    # 2. Tier 2 google.protobuf reflection rejects both marshal and unmarshal
    gpb_cls = getattr(gpb_mods[target], msg_name)
    with pytest.raises(OmniBufEncodeError) as enc_exc:
        marshal_proto(gpb_cls())
    assert err_substr.lower() in str(enc_exc.value).lower()
    with pytest.raises(OmniBufDecodeError) as dec_exc:
        unmarshal_proto(b"", gpb_cls)
    assert err_substr.lower() in str(dec_exc.value).lower()

    # 3. Tier 2 protobuf-py reflection rejects both marshal and unmarshal
    if target in pbpy_mods:
        pbp_cls = getattr(pbpy_mods[target], msg_name)
        with pytest.raises(OmniBufEncodeError) as pb_enc_exc:
            marshal_proto(pbp_cls())
        assert err_substr.lower() in str(pb_enc_exc.value).lower()
        with pytest.raises(OmniBufDecodeError) as pb_dec_exc:
            unmarshal_proto(b"", pbp_cls)
        assert err_substr.lower() in str(pb_dec_exc.value).lower()


@pytest.mark.parametrize(
    ("case_name", "files", "target", "msg_name", "err_substr"),
    [
        (
            "declared_closed_enum",
            {
                "closed_decl.proto": """edition = "2026";
package neg1;
export enum ClosedMode {
  option features.enum_type = CLOSED;
  CLOSED_MODE_UNSPECIFIED = 0;
  CLOSED_MODE_ON = 1;
}
export message Holder {
  int32 x = 1;
}
"""
            },
            "closed_decl.proto",
            "Holder",
            "closed",
        ),
        (
            "nested_closed_enum",
            {
                "closed_nested.proto": """edition = "2026";
package neg2;
export message Holder {
  enum InnerClosed {
    option features.enum_type = CLOSED;
    INNER_CLOSED_UNSPECIFIED = 0;
  }
  int32 x = 1;
}
"""
            },
            "closed_nested.proto",
            "Holder",
            "closed",
        ),
        (
            "cross_file_proto2_closed_enum",
            {
                "legacy_enum.proto": """syntax = "proto2";
package leg;
enum LegacyClosed {
  LEGACY_CLOSED_ZERO = 0;
  LEGACY_CLOSED_ONE = 1;
}
""",
                "use_legacy.proto": """edition = "2026";
package neg3;
import "legacy_enum.proto";
export message Holder {
  leg.LegacyClosed mode = 1;
}
""",
            },
            "use_legacy.proto",
            "Holder",
            "closed",
        ),
        (
            "cross_file_editions_closed_enum_map",
            {
                "dep_closed.proto": """edition = "2024";
package depc;
export enum DepClosed {
  option features.enum_type = CLOSED;
  DEP_CLOSED_UNSPECIFIED = 0;
}
""",
                "use_dep_closed.proto": """edition = "2026";
package neg4;
import "dep_closed.proto";
export message Holder {
  map<string, depc.DepClosed> modes = 1;
}
""",
            },
            "use_dep_closed.proto",
            "Holder",
            "closed",
        ),
        (
            "legacy_required",
            {
                "req.proto": """edition = "2026";
package neg5;
export message Holder {
  int32 must_have = 1 [features.field_presence = LEGACY_REQUIRED];
}
"""
            },
            "req.proto",
            "Holder",
            "legacy_required",
        ),
        (
            "utf8_none_scalar",
            {
                "utf8_s.proto": """edition = "2026";
package neg6;
export message Holder {
  string raw = 1 [features.utf8_validation = NONE];
}
"""
            },
            "utf8_s.proto",
            "Holder",
            "utf-8",
        ),
        (
            "utf8_none_repeated",
            {
                "utf8_r.proto": """edition = "2026";
package neg7;
export message Holder {
  repeated string raws = 1 [features.utf8_validation = NONE];
}
"""
            },
            "utf8_r.proto",
            "Holder",
            "utf-8",
        ),
        (
            "utf8_none_map_key_field_opt",
            {
                "utf8_mk.proto": """edition = "2026";
package neg8;
export message Holder {
  map<string, int32> m = 1 [features.utf8_validation = NONE];
}
"""
            },
            "utf8_mk.proto",
            "Holder",
            "utf-8",
        ),
        (
            "utf8_none_map_value_file_opt",
            {
                "utf8_mv.proto": """edition = "2026";
package neg9;
option features.utf8_validation = NONE;
export message Holder {
  map<int32, string> m = 1;
}
"""
            },
            "utf8_mv.proto",
            "Holder",
            "utf-8",
        ),
        (
            "nonzero_default_int",
            {
                "def_i.proto": """edition = "2026";
package neg10;
export message Holder {
  int32 x = 1 [default = 42];
}
"""
            },
            "def_i.proto",
            "Holder",
            "default",
        ),
        (
            "nonzero_default_neg_zero_float",
            {
                "def_f.proto": """edition = "2026";
package neg11;
export message Holder {
  float x = 1 [default = -0.0];
}
"""
            },
            "def_f.proto",
            "Holder",
            "default",
        ),
        (
            "nonzero_default_bool",
            {
                "def_b.proto": """edition = "2026";
package neg12;
export message Holder {
  bool x = 1 [default = true];
}
"""
            },
            "def_b.proto",
            "Holder",
            "default",
        ),
        (
            "nonzero_default_string",
            {
                "def_s.proto": """edition = "2026";
package neg13;
export message Holder {
  string x = 1 [default = "abc"];
}
"""
            },
            "def_s.proto",
            "Holder",
            "default",
        ),
        (
            "nonzero_default_bytes",
            {
                "def_by.proto": """edition = "2026";
package neg14;
export message Holder {
  bytes x = 1 [default = "\\000"];
}
"""
            },
            "def_by.proto",
            "Holder",
            "default",
        ),
        (
            "nonzero_default_enum",
            {
                "def_e.proto": """edition = "2026";
package neg15;
export enum Mode {
  MODE_UNSPECIFIED = 0;
  MODE_FAST = 1;
}
export message Holder {
  Mode m = 1 [default = MODE_FAST];
}
"""
            },
            "def_e.proto",
            "Holder",
            "default",
        ),
        (
            "message_extension_range",
            {
                "ext_r.proto": """edition = "2026";
package neg16;
export message Holder {
  int32 x = 1;
  extensions 100 to 200;
}
"""
            },
            "ext_r.proto",
            "Holder",
            "extension",
        ),
        (
            "file_extension_non_options",
            {
                "ext_host.proto": """edition = "2026";
package neg17;
export message Host {
  int32 x = 1;
  extensions 100 to 200;
}
""",
                "ext_use.proto": """edition = "2026";
package neg17b;
import "ext_host.proto";
extend neg17.Host {
  int32 extra = 101;
}
export message Holder {
  int32 y = 1;
}
""",
            },
            "ext_use.proto",
            "Holder",
            "extension",
        ),
        (
            "proto2_group_still_rejected",
            {
                "p2_grp.proto": """syntax = "proto2";
package neg18;
message Holder {
  optional group LegacyGroup = 1 {
    optional int32 a = 2;
  }
}
"""
            },
            "p2_grp.proto",
            "Holder",
            "group",
        ),
    ],
)
def test_editions_negative_cases_consistent_across_plugin_and_reflection(
    tmp_path: Path,
    case_name: str,
    files: dict[str, str],
    target: str,
    msg_name: str,
    err_substr: str,
) -> None:
    _assert_rejected_everywhere(
        tmp_path,
        files,
        target,
        msg_name,
        err_substr,
        tag=case_name,
    )


def test_editions_marshal_top_level_dispatch(tmp_path: Path) -> None:
    """omnibuf.marshal / omnibuf.unmarshal dispatch cleanly on Editions Tier 1 and Tier 2 messages."""
    proto = """edition = "2026";
package disp;
export message Ping {
  int32 seq = 1;
  string note = 2 [features.field_presence = IMPLICIT];
}
"""
    fds, gpb_mods, pbpy_mods = _compile_protos(
        tmp_path,
        {"disp.proto": proto},
        ["disp.proto"],
        tag="disp",
    )
    resp, gen_mods = _generate_plugin_module(fds, ["disp.proto"], tag="disp")
    assert not resp.error

    gen = gen_mods["disp_omnibuf_pb.py"]
    gpb = gpb_mods["disp.proto"]
    pbp = pbpy_mods.get("disp.proto")

    w1 = omnibuf.marshal(gen.Ping(seq=0, note="hi"))
    w2 = omnibuf.marshal(gpb.Ping(seq=0, note="hi"))
    assert w1 == w2
    assert omnibuf.unmarshal(w2, gen.Ping) == gen.Ping(seq=0, note="hi")
    g_out = omnibuf.unmarshal(w1, gpb.Ping)
    assert g_out.HasField("seq") and g_out.seq == 0 and g_out.note == "hi"
    if pbp is not None:
        w3 = omnibuf.marshal(pbp.Ping(seq=0, note="hi"))
        assert w3 == w1
        p_out = omnibuf.unmarshal(w1, pbp.Ping)
        assert p_out.has_field("seq") and p_out.seq == 0 and p_out.note == "hi"


@pytest.mark.parametrize("year", ["2023", "2024", "2026"])
def test_generated_conformance_editions_modules_cross_tier_equivalence(year: str) -> None:
    """Checked-in conformance Editions 2023/2024/2026 modules match across Tier 1, pbpy, and google.protobuf."""
    from importlib import import_module

    mod_gen: Any = import_module(f"omnibuf.gen.omnibuf.conformance.editions_{year}_omnibuf_pb")
    mod_pb: Any = import_module(f"omnibuf.gen.omnibuf.conformance.editions_{year}_pb")
    mod_pb2: Any = import_module(f"omnibuf.gen.omnibuf.conformance.editions_{year}_pb2")

    cls_gen = getattr(mod_gen, f"TestEditions{year}")
    child_gen = getattr(mod_gen, f"Editions{year}Child")
    cls_pb = getattr(mod_pb, f"TestEditions{year}")
    child_pb = getattr(mod_pb, f"Editions{year}Child")
    status_pb = getattr(mod_pb, f"Editions{year}Status")
    cls_pb2 = getattr(mod_pb2, f"TestEditions{year}")
    child_pb2 = getattr(mod_pb2, f"Editions{year}Child")

    m_gen = cls_gen(
        explicit_int=0,
        explicit_bool=False,
        explicit_string="",
        explicit_bytes=b"",
        explicit_double=0.0,
        status=0,
        implicit_count=7,
        implicit_flag=True,
        child=child_gen(id=1, note="c"),
        delimited_child=child_gen(id=2, note="d"),
        packed_vals=[1, -2, 3],
        expanded_vals=[4, -5],
        scores={"a": 1, "b": 2},
        choice_child=child_gen(id=3, note="oo"),
    )
    m_pb = cls_pb(
        explicit_int=0,
        explicit_bool=False,
        explicit_string="",
        explicit_bytes=b"",
        explicit_double=0.0,
        status=status_pb(0),
        implicit_count=7,
        implicit_flag=True,
        child=child_pb(id=1, note="c"),
        delimited_child=child_pb(id=2, note="d"),
        packed_vals=[1, -2, 3],
        expanded_vals=[4, -5],
        scores={"a": 1, "b": 2},
        choice=pbpy.Oneof("choice_child", child_pb(id=3, note="oo")),
    )
    m_pb2 = cls_pb2(
        explicit_int=0,
        explicit_bool=False,
        explicit_string="",
        explicit_bytes=b"",
        explicit_double=0.0,
        status=0,
        implicit_count=7,
        implicit_flag=True,
        child=child_pb2(id=1, note="c"),
        delimited_child=child_pb2(id=2, note="d"),
        packed_vals=[1, -2, 3],
        expanded_vals=[4, -5],
        scores={"a": 1, "b": 2},
        choice_child=child_pb2(id=3, note="oo"),
    )

    w_gen = m_gen.marshal_omnibuf(deterministic=True)
    w_pb = omnibuf.marshal(m_pb, deterministic=True)
    w_pb2 = omnibuf.marshal(m_pb2, deterministic=True)
    assert w_gen == w_pb == w_pb2

    sd_gen = m_gen.marshal_omnibuf(deterministic=True, self_describing=True)
    sd_pb = omnibuf.marshal(m_pb, deterministic=True, self_describing=True)
    sd_pb2 = omnibuf.marshal(m_pb2, deterministic=True, self_describing=True)
    assert sd_gen == sd_pb == sd_pb2

    dec_pb2 = omnibuf.unmarshal(w_gen, cls_pb2)
    assert dec_pb2.HasField("explicit_int") and dec_pb2.explicit_int == 0
    assert dec_pb2.HasField("delimited_child") and dec_pb2.delimited_child.id == 2
    assert dec_pb2.WhichOneof("choice") == "choice_child"
    assert dec_pb2.choice_child.id == 3
