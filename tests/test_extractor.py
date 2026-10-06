import numpy as np
import pytest

from pemd.features.api_categories import normalise_api
from pemd.features.extractor import FeatureExtractor, InvalidPEError, entropy
from tests.conftest import make_pe


def _get(res, ext, name):
    return res.vector[ext.index[name]]


def test_rejects_non_pe(cfg):
    ext = FeatureExtractor(cfg)
    for bad in (b"", b"hello world" * 10, b"MZ" + b"\x00" * 100):
        with pytest.raises(InvalidPEError):
            ext.extract_bytes(bad)


def test_rejects_truncated_pe(cfg):
    with pytest.raises(InvalidPEError):
        FeatureExtractor(cfg).extract_bytes(make_pe()[:300])


def test_vector_shape_and_names(cfg):
    ext = FeatureExtractor(cfg)
    res = ext.extract_bytes(make_pe())
    assert res.vector.shape == (len(ext.names),)
    assert len(set(ext.names)) == len(ext.names)
    assert np.isfinite(res.vector).all()
    assert len(res.sha256) == 64


def test_header_and_section_features(cfg):
    ext = FeatureExtractor(cfg)
    res = ext.extract_bytes(make_pe())
    assert _get(res, ext, "hdr:machine_i386") == 1
    assert _get(res, ext, "hdr:n_sections") == 2
    assert _get(res, ext, "hdr:dllchar_aslr") == 1
    assert _get(res, ext, "hdr:dllchar_nx") == 1
    assert _get(res, ext, "sec:n_executable") == 1
    assert _get(res, ext, "sec:entry_outside_sections") == 0
    assert _get(res, ext, "sec:packer_name") == 0
    assert _get(res, ext, "op:n_insn") > 0
    packed = ext.extract_bytes(make_pe(text_name=b"UPX0"))
    assert _get(packed, ext, "sec:packer_name") == 1


def test_imports_and_api_categories(cfg):
    ext = FeatureExtractor(cfg)
    res = ext.extract_bytes(make_pe(imports={
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                         "IsDebuggerPresent", "LoadLibraryA"],
    }))
    assert _get(res, ext, "imp:n_dlls") == 1
    assert _get(res, ext, "imp:n_functions") == 5
    assert _get(res, ext, "api_cat:process_injection") == 3
    assert _get(res, ext, "api_cat:anti_debug") == 1
    assert _get(res, ext, "api_cat:dynamic_resolution") == 1


def test_strings_and_entropy(cfg):
    ext = FeatureExtractor(cfg)
    res = ext.extract_bytes(make_pe(payload=b"visit http://example.com and run cmd.exe " * 3))
    assert _get(res, ext, "str:n_urls") == 3
    assert _get(res, ext, "str:n_shell") == 3
    assert entropy(bytes(range(256))) == pytest.approx(8.0)
    assert entropy(b"\x00" * 10) == 0.0


def test_normalise_api():
    assert normalise_api("CreateProcessW") == "createprocess"
    assert normalise_api("GetProcAddress") == "getprocaddress"
    assert normalise_api("WSA") == "wsa"


def test_metadata_flags_reflect_empty_directories(cfg):
    ext = FeatureExtractor(cfg)
    res = ext.extract_bytes(make_pe())
    for flag in ("has_relocations", "has_exceptions", "has_signature", "has_tls"):
        assert _get(res, ext, f"meta:{flag}") == 0


def test_vocabulary_explains_hashed_buckets(cfg):
    ext = FeatureExtractor(cfg)
    ext.collect_vocabulary()
    ext.extract_bytes(make_pe(imports={"kernel32.dll": ["VirtualAllocEx"]}))
    vocab = ext.vocabulary()
    assert any("kernel32.dll:virtualallocex" in toks for k, toks in vocab.items()
               if k.startswith("imp_fn_h:"))
    assert any(k.startswith("op_h:") for k in vocab)
