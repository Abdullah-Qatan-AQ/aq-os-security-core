"""
AQ OS attack suite: every test simulates a real attack and asserts that AQ OS stops it.
Run:  python3 test_aqos.py
"""
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aqos_core import (AQOS, BootStage, Denied, HardwareKeystore, Mode, Perm, RootOfTrust, build_package,
                       raw_pub, sha256, sign_stage)

VENDOR = Ed25519PrivateKey.generate()
DEV = Ed25519PrivateKey.generate()
ATTACKER = Ed25519PrivateKey.generate()
PIN = "482915"


def images(ver=1, system=b"system", key=VENDOR):
    return [sign_stage(key, "bootloader", b"BL", ver), sign_stage(key, "kernel", b"KERNEL", ver),
            sign_stage(key, "system", system, ver), sign_stage(key, "secure_services", b"SEC", ver)]


def manifest(**over):
    m = {"app_id": "com.example.notes", "version": 1, "permissions": ["camera", "network", "contacts"],
         "domains": ["api.example.com"], "debuggable": False}
    m.update(over)
    return m


def new_device(provision=True):
    d = AQOS(RootOfTrust(raw_pub(VENDOR)), HardwareKeystore())
    assert d.power_on(images()).ok
    if provision:
        d.provision(PIN)
    return d


def with_app(d, **over):
    app = d.install(build_package(DEV, manifest(**over), b"app-code"))
    return app, d.launch(app)


def denied(fn, *a, contains=None, **kw):
    try:
        fn(*a, **kw)
    except Denied as e:
        if contains:
            assert contains in str(e), f"expected '{contains}' in '{e}'"
        return
    raise AssertionError("attack succeeded: expected Denied")


TESTS = []


def attack(name):
    def deco(f):
        TESTS.append((name, f))
        return f
    return deco


# ---------------------------------------------------------------- boot
@attack("boot: legitimate signed chain boots")
def _():
    assert AQOS(RootOfTrust(raw_pub(VENDOR))).power_on(images()).ok


@attack("boot: tampered kernel with the original signature is refused")
def _():
    d = AQOS(RootOfTrust(raw_pub(VENDOR)))
    st = images()
    st[1] = BootStage("kernel", st[1].image + b"\x00rootkit", st[1].version, st[1].signature)
    r = d.power_on(st)
    assert not r.ok and "bad signature" in r.reason


@attack("boot: chain signed by an attacker key is refused")
def _():
    assert not AQOS(RootOfTrust(raw_pub(VENDOR))).power_on(images(key=ATTACKER)).ok


@attack("boot: rollback to an older vulnerable version is refused")
def _():
    d = AQOS(RootOfTrust(raw_pub(VENDOR)))
    assert d.power_on(images(ver=2)).ok
    r = d.power_on(images(ver=1))
    assert not r.ok and "rollback" in r.reason


@attack("boot: missing or reordered stages are refused")
def _():
    d = AQOS(RootOfTrust(raw_pub(VENDOR)))
    st = images()
    assert not d.power_on(st[:3]).ok
    assert not d.power_on([st[1], st[0], st[2], st[3]]).ok


@attack("boot: a failed boot does not advance rollback counters")
def _():
    d = AQOS(RootOfTrust(raw_pub(VENDOR)))
    bad = images(ver=5)
    bad[3] = BootStage("secure_services", b"EVIL", 5, bad[3].signature)
    assert not d.power_on(bad).ok
    assert d.power_on(images(ver=1)).ok


# ---------------------------------------------------------------- vault
@attack("vault: wrong PIN is rejected, right PIN unlocks")
def _():
    d = new_device()
    d.lock()
    denied(d.unlock, "000000", contains="wrong PIN")
    d.unlock(PIN)


@attack("vault: disk dump contains no plaintext")
def _():
    d = new_device()
    _, t = with_app(d)
    secret = b"my-bank-password-hunter2"
    d.syscall(t, "storage.put", name="note", data=secret)
    assert all(secret not in blob for blob in d.vault._blobs.values())


@attack("vault: moving one app's blob into another app's slot fails integrity")
def _():
    d = new_device()
    a, ta = with_app(d)
    b = d.install(build_package(DEV, manifest(app_id="com.example.other"), b"x"))
    tb = d.launch(b)
    d.syscall(ta, "storage.put", name="x", data=b"A-secret")
    d.vault._blobs[(b, "x")] = d.vault._blobs[(a, "x")]
    denied(d.syscall, tb, "storage.get", name="x", contains="integrity")


@attack("vault: swapping blobs between names of the same app fails integrity")
def _():
    d = new_device()
    a, ta = with_app(d)
    d.syscall(ta, "storage.put", name="x", data=b"one")
    d.syscall(ta, "storage.put", name="y", data=b"two")
    d.vault._blobs[(a, "y")] = d.vault._blobs[(a, "x")]
    denied(d.syscall, ta, "storage.get", name="y", contains="integrity")


@attack("vault: PIN brute force is throttled with escalating lockouts")
def _():
    d = new_device()
    d.lock()
    for _ in range(5):
        denied(d.unlock, "111111")
    denied(d.unlock, PIN, contains="locked out")  # even the correct PIN waits
    d.clock.advance(31)
    d.unlock(PIN)


@attack("vault: 10 wrong PINs crypto-erase the device")
def _():
    d = new_device()
    _, t = with_app(d)
    d.syscall(t, "storage.put", name="n", data=b"secret")
    d.lock()
    for _ in range(9):
        denied(d.unlock, "111111")
        d.clock.advance(4000)
    denied(d.unlock, "111111", contains="wiped")
    denied(d.unlock, PIN)
    assert d.vault.wiped and not d.vault._blobs
    denied(d.keystore.derive, b"aqos-vault", d.pcr, contains="destroyed")


@attack("vault: valid-but-different OS image cannot release the hardware key")
def _():
    d = new_device()
    d.lock()
    d.power_on(images(system=b"modified-system"))  # genuinely signed, but a different measurement
    denied(d.unlock, PIN, contains="measurement mismatch")
    assert d.vault.failed == 0  # not counted as a PIN guess


@attack("vault: PINs shorter than 6 are refused at setup")
def _():
    d = new_device(provision=False)
    denied(d.provision, "1234", contains="too short")


# ---------------------------------------------------------------- packages
@attack("install: tampered code is rejected")
def _():
    d = new_device()
    p = build_package(DEV, manifest(), b"good")
    p.code = b"malicious"
    denied(d.install, p, contains="signature")


@attack("install: package whose manifest was edited after signing is rejected")
def _():
    d = new_device()
    p = build_package(DEV, manifest(permissions=["network"]), b"code")
    p.manifest["permissions"] = ["network", "camera", "microphone"]
    denied(d.install, p, contains="signature")


@attack("install: update signed by a different developer (hijack) is rejected")
def _():
    d = new_device()
    d.install(build_package(DEV, manifest(), b"v1"))
    denied(d.install, build_package(ATTACKER, manifest(version=2), b"evil"), contains="different developer")


@attack("install: downgrade and same-version replay are rejected")
def _():
    d = new_device()
    d.install(build_package(DEV, manifest(version=3), b"v3"))
    denied(d.install, build_package(DEV, manifest(version=2), b"v2"), contains="downgrade")
    denied(d.install, build_package(DEV, manifest(version=3), b"v3"), contains="downgrade")
    d.install(build_package(DEV, manifest(version=4), b"v4"))


@attack("install: path-traversal app ids, debuggable builds, unknown perms, bad domains are rejected")
def _():
    d = new_device()
    for bad in (manifest(app_id="../../system"), manifest(app_id="com/evil.app"), manifest(debuggable=True),
                manifest(permissions=["root"]), manifest(domains=["evil.com/path"]), manifest(version=True)):
        denied(d.install, build_package(DEV, bad, b"x"))


@attack("install: known-malware hash is rejected")
def _():
    d = AQOS(RootOfTrust(raw_pub(VENDOR)), malware_hashes={sha256(b"bad").hex()})
    d.power_on(images())
    denied(d.install, build_package(DEV, manifest(), b"bad"), contains="malware")


# ---------------------------------------------------------------- permissions
@attack("perm: ungranted camera is denied")
def _():
    d = new_device()
    _, t = with_app(d)
    d.set_foreground(t)
    denied(d.syscall, t, "sensor.use", sensor="camera", contains="not granted")


@attack("perm: user cannot be tricked into granting an undeclared permission")
def _():
    d = new_device()
    app, _ = with_app(d, permissions=["network"])
    denied(d.user_grant, app, Perm.MICROPHONE, Mode.WHILE_IN_USE, contains="never declared")


@attack("perm: sensors cannot be granted 'always'")
def _():
    d = new_device()
    app, _ = with_app(d)
    denied(d.user_grant, app, Perm.CAMERA, Mode.ALWAYS, contains="never")


@attack("perm: camera in the background is refused even when granted")
def _():
    d = new_device()
    app, t = with_app(d)
    d.user_grant(app, Perm.CAMERA, Mode.WHILE_IN_USE)
    denied(d.syscall, t, "sensor.use", sensor="camera", contains="background")
    d.set_foreground(t)
    assert "camera" in d.syscall(t, "sensor.use", sensor="camera")
    assert d.broker.indicators[-1][1:] == (app, "camera")  # privacy indicator recorded


@attack("perm: one-time grant is consumed after a single use")
def _():
    d = new_device()
    app, t = with_app(d)
    d.set_foreground(t)
    d.user_grant(app, Perm.CAMERA, Mode.ONCE)
    d.syscall(t, "sensor.use", sensor="camera")
    denied(d.syscall, t, "sensor.use", sensor="camera", contains="not granted")


@attack("perm: unused permissions are auto-revoked after 90 days")
def _():
    d = new_device()
    app, t = with_app(d)
    d.user_grant(app, Perm.NETWORK, Mode.ALWAYS)
    d.syscall(t, "net.connect", host="api.example.com")
    d.clock.advance(91 * 86400)
    assert (app, "network") in d.housekeeping()
    denied(d.syscall, t, "net.connect", host="api.example.com", contains="not granted")


# ---------------------------------------------------------------- firewall
def net_device():
    d = new_device()
    app, t = with_app(d)
    d.user_grant(app, Perm.NETWORK, Mode.ALWAYS)
    return d, t


@attack("net: declared domain over TLS works")
def _():
    d, t = net_device()
    assert d.syscall(t, "net.connect", host="api.example.com") == "connected"
    assert d.syscall(t, "net.connect", host="eu.api.example.com") == "connected"


@attack("net: cleartext HTTP is blocked")
def _():
    d, t = net_device()
    denied(d.syscall, t, "net.connect", host="api.example.com", port=80, tls=False, contains="cleartext")
    denied(d.syscall, t, "net.connect", host="api.example.com", port=443, tls=False, contains="cleartext")


@attack("net: look-alike and suffix-trick domains are blocked")
def _():
    d, t = net_device()
    for host in ("evilapi.example.com.evil.io", "xapi.example.com", "api.example.com.attacker.net", "example.com"):
        denied(d.syscall, t, "net.connect", host=host, contains="not in the app's declared")


@attack("net: trackers and raw IPs are blocked")
def _():
    d, t = net_device()
    denied(d.syscall, t, "net.connect", host="stats.google-analytics.com", contains="tracker")
    denied(d.syscall, t, "net.connect", host="192.168.1.1", contains="raw IP")
    denied(d.syscall, t, "net.connect", host="169.254.169.254", contains="raw IP")


@attack("net: app without the network permission cannot connect at all")
def _():
    d = new_device()
    _, t = with_app(d)
    denied(d.syscall, t, "net.connect", host="api.example.com", contains="not granted")


# ---------------------------------------------------------------- process isolation
@attack("isolation: forged process tokens are rejected")
def _():
    d = new_device()
    with_app(d)
    denied(d.syscall, "deadbeef" * 4, "storage.get", name="x")
    denied(d.syscall, None, "storage.get", name="x")


@attack("isolation: an app can only ever see its own storage")
def _():
    d = new_device()
    _, ta = with_app(d)
    b = d.install(build_package(DEV, manifest(app_id="com.example.other"), b"x"))
    tb = d.launch(b)
    d.syscall(ta, "storage.put", name="secret", data=b"A")
    assert d.syscall(tb, "storage.get", name="secret") is None
    denied(d.syscall, tb, "storage.get", name="../com.example.notes/secret", contains="invalid object name")


@attack("isolation: locking the device kills running processes")
def _():
    d = new_device()
    _, t = with_app(d)
    d.lock()
    denied(d.syscall, t, "storage.get", name="x")
    d.unlock(PIN)
    denied(d.syscall, t, "storage.get", name="x")  # old token stays dead after unlock


@attack("isolation: uninstall erases the app's data and permissions")
def _():
    d = new_device()
    app, t = with_app(d)
    d.syscall(t, "storage.put", name="n", data=b"secret")
    d.uninstall(app)
    assert not any(k[0] == app for k in d.vault._blobs)
    denied(d.syscall, t, "storage.get", name="n")


@attack("isolation: unknown syscalls and malformed arguments are refused")
def _():
    d = new_device()
    _, t = with_app(d)
    denied(d.syscall, t, "kernel.poke", addr=0)
    denied(d.syscall, t, "storage.put", name="n", data="not-bytes")
    denied(d.syscall, t, "sensor.use", sensor="network")


# ---------------------------------------------------------------- safe OS updates (v0.2)
V2 = dict(ver=2, system=b"system-v2")


@attack("update: vendor-signed update keeps all data readable after reboot")
def _():
    d = new_device()
    app, t = with_app(d)
    d.syscall(t, "storage.put", name="n", data=b"secret")
    assert d.apply_update(images(**V2), PIN)
    assert d.power_on(images(**V2)).ok
    d.unlock(PIN)
    assert d.syscall(d.launch(app), "storage.get", name="n") == b"secret"


@attack("update: after the first good boot the old OS can no longer release the key")
def _():
    d = new_device()
    old_pcr = d.pcr
    d.apply_update(images(**V2), PIN)
    d.power_on(images(**V2))
    d.unlock(PIN)  # commit point
    denied(d.keystore.derive, b"aqos-vault", old_pcr, contains="mismatch")
    assert not d.power_on(images(ver=1)).ok  # and the boot chain refuses the rollback anyway


@attack("update: a new image that never boots cannot brick the device")
def _():
    d = new_device()
    app, t = with_app(d)
    d.syscall(t, "storage.put", name="n", data=b"secret")
    d.apply_update(images(**V2), PIN)
    assert d.power_on(images()).ok  # new OS failed to start, device falls back to the old one
    d.unlock(PIN)
    assert d.syscall(d.launch(app), "storage.get", name="n") == b"secret"
    assert d.power_on(images(**V2)).ok  # booting the old OS did not commit; the update still works
    d.unlock(PIN)
    assert d.syscall(d.launch(app), "storage.get", name="n") == b"secret"


@attack("update: forged and rolled-back updates cannot be staged")
def _():
    d = new_device()
    denied(d.apply_update, images(key=ATTACKER, **V2), PIN, contains="bad signature")
    e = AQOS(RootOfTrust(raw_pub(VENDOR)), HardwareKeystore())
    assert e.power_on(images(**V2)).ok
    e.provision(PIN)
    denied(e.apply_update, images(ver=1), PIN, contains="rollback")
    assert len(e.keystore._sealed) == 1  # nothing was nominated


@attack("update: staging needs the PIN again, and wrong PINs count toward lockout")
def _():
    d = new_device()
    denied(d.apply_update, images(**V2), "000000", contains="wrong PIN")
    assert d.vault.failed == 1 and len(d.keystore._sealed) == 1


@attack("update: cannot be staged while the device is locked")
def _():
    d = new_device()
    d.lock()
    denied(d.apply_update, images(**V2), PIN, contains="unlock")


@attack("update: an image that was never staged still cannot unlock the vault")
def _():
    d = new_device()
    d.apply_update(images(**V2), PIN)
    d.lock()
    assert d.power_on(images(ver=1, system=b"other-signed-build")).ok  # validly signed, but not nominated
    denied(d.unlock, PIN, contains="measurement mismatch")
    assert d.vault.failed == 0


@attack("update: a newer staged update replaces an unbooted one")
def _():
    d = new_device()
    d.apply_update(images(ver=2, system=b"system-v2"), PIN)
    d.apply_update(images(ver=3, system=b"system-v3"), PIN)
    assert len(d.keystore._sealed) == 2  # running OS + only the newest candidate
    d.power_on(images(ver=3, system=b"system-v3"))
    d.unlock(PIN)


# ---------------------------------------------------------------- audit
@attack("audit: log is verifiable and any tampering is detected")
def _():
    d = new_device()
    _, t = with_app(d)
    d.syscall(t, "storage.put", name="n", data=b"x")
    assert d.log.verify()
    saved = dict(d.log.entries[2])
    d.log.entries[2]["data"] = {"app": "someone.else"}
    assert not d.log.verify()
    d.log.entries[2] = saved
    assert d.log.verify()
    del d.log.entries[1]
    assert not d.log.verify()


if __name__ == "__main__":
    failed = 0
    for name, fn in TESTS:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {name}\n        -> {type(e).__name__}: {e}")
    print(f"\n{len(TESTS) - failed}/{len(TESTS)} attacks stopped")
    sys.exit(1 if failed else 0)
