"""Additional boundary and malformed-input tests for the AQ OS prototype."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aqos_core import AQOS, AuditLog, BootStage, Clock, Denied, Firewall, HardwareKeystore, RootOfTrust, build_package, raw_pub, sign_stage


VENDOR = Ed25519PrivateKey.generate()
DEV = Ed25519PrivateKey.generate()
PIN = "482915"


def images(ver=1):
    return [
        sign_stage(VENDOR, "bootloader", b"BL", ver),
        sign_stage(VENDOR, "kernel", b"KERNEL", ver),
        sign_stage(VENDOR, "system", b"system", ver),
        sign_stage(VENDOR, "secure_services", b"SEC", ver),
    ]


def device():
    d = AQOS(RootOfTrust(raw_pub(VENDOR)), HardwareKeystore())
    assert d.power_on(images()).ok
    d.provision(PIN)
    return d


def expect_denied(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Denied:
        return
    raise AssertionError("expected Denied")


def test_unprovisioned_keystore_is_not_a_derivation_oracle():
    expect_denied(HardwareKeystore().derive, b"context", b"0" * 32)


def test_audit_verifier_returns_false_for_malformed_records():
    log = AuditLog(Clock())
    log.record("test")
    log.entries[0] = {"hash": "not-hex"}
    assert log.verify() is False


def test_malformed_manifest_types_are_rejected():
    d = device()
    bad = {"app_id": "com.example.bad", "version": 1, "permissions": "network", "domains": ["example.com"]}
    expect_denied(d.install, build_package(DEV, bad, b"code"))


def test_network_parameters_are_strictly_typed():
    fw = Firewall(AuditLog(Clock()))
    fw.register("com.example.app", ["example.com"])
    expect_denied(fw.check, "com.example.app", "example.com", True, True)
    expect_denied(fw.check, "com.example.app", "example.com", 0, True)
    expect_denied(fw.check, "com.example.app", "example.com", 443, "yes")


def test_dot_and_dotdot_are_not_storage_objects():
    d = device()
    pkg = build_package(DEV, {"app_id": "com.example.app", "version": 1, "permissions": [], "domains": []}, b"code")
    app = d.install(pkg)
    token = d.launch(app)
    expect_denied(d.syscall, token, "storage.get", name=".")
    expect_denied(d.syscall, token, "storage.get", name="..")


def test_invalid_boot_stage_types_are_rejected_without_commit():
    d = AQOS(RootOfTrust(raw_pub(VENDOR)))
    st = images()
    st[0] = BootStage("bootloader", b"BL", True, st[0].signature)
    result = d.power_on(st)
    assert not result.ok
    assert d.bootchain.rot.counters == {}


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"{len(tests)}/{len(tests)} hardening tests passed")
