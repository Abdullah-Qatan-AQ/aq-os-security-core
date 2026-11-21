"""
AQ OS - Security Core (working prototype)
by Abdullah Qatan

Layers implemented here:
  1. Verified + measured boot   (Ed25519 chain, anti-rollback counters, PCR-style measurement)
  2. Hardware-keystore model    (root key never leaves; released only for a trusted boot measurement)
  3. Encrypted vault            (random DEK wrapped by scrypt(PIN) + hardware key; per-app AES-256-GCM keys,
                                 brute-force lockout, crypto-erase after too many failures)
  3b. Safe OS updates (v0.2)    (re-authenticated re-sealing; the old OS stays valid until the new one boots)
  4. Signed app packages        (developer key pinning, anti-downgrade, malware hash blocklist)
  5. Permission broker          (declared + user-granted, foreground-only sensors, one-time grants,
                                 auto-revoke of unused permissions, privacy indicators)
  6. Network firewall           (default deny, per-app domain allowlist, TLS only, tracker blocklist)
  7. Syscall gate               (unforgeable process identity; apps never choose whose data they touch)
  8. Tamper-evident audit log   (hash chain)

This is a security-core model written in Python so the design can be run and attacked
in tests. A real phone OS would implement the same policies in a memory-safe systems
language on top of a hardened microkernel and a real secure element.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
from dataclasses import dataclass
from enum import Enum

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class Denied(Exception):
    """Raised whenever the security core refuses an operation."""


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def raw_pub(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Clock:
    """Injectable clock so lockouts and auto-revoke are testable."""

    def __init__(self, start: float = 1_800_000_000.0):
        self.t = start

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


# --------------------------------------------------------------------------- audit log
class AuditLog:
    """Append-only hash chain: editing or deleting a middle entry breaks verification."""

    GENESIS = b"\x00" * 32

    def __init__(self, clock: Clock):
        self.clock = clock
        self.entries: list[dict] = []
        self._head = self.GENESIS

    def record(self, event: str, **data) -> None:
        body = {"t": self.clock.now(), "event": event, "data": data, "prev": self._head.hex()}
        digest = sha256(json.dumps(body, sort_keys=True).encode())
        self.entries.append({**body, "hash": digest.hex()})
        self._head = digest

    def verify(self) -> bool:
        prev = self.GENESIS
        try:
            for e in self.entries:
                if not isinstance(e, dict) or not isinstance(e.get("hash"), str):
                    return False
                body = {k: v for k, v in e.items() if k != "hash"}
                if body.get("prev") != prev.hex():
                    return False
                if len(e["hash"]) != 64 or sha256(json.dumps(body, sort_keys=True).encode()).hex() != e["hash"]:
                    return False
                prev = bytes.fromhex(e["hash"])
        except (KeyError, TypeError, ValueError, UnicodeError):
            return False
        return True


# --------------------------------------------------------------------------- 1. verified boot
@dataclass
class BootStage:
    name: str
    image: bytes
    version: int
    signature: bytes


def _stage_msg(name: str, version: int, image: bytes) -> bytes:
    return name.encode() + b"|" + version.to_bytes(8, "big") + sha256(image)


def sign_stage(vendor_priv: Ed25519PrivateKey, name: str, image: bytes, version: int) -> BootStage:
    return BootStage(name, image, version, vendor_priv.sign(_stage_msg(name, version, image)))


@dataclass
class BootResult:
    ok: bool
    reason: str
    pcr: bytes = b""


class RootOfTrust:
    """Models fused ROM: the vendor public key and monotonic anti-rollback counters."""

    def __init__(self, vendor_pub: bytes):
        self.vendor_pub = Ed25519PublicKey.from_public_bytes(vendor_pub)
        self.counters: dict[str, int] = {}


class BootChain:
    ORDER = ("bootloader", "kernel", "system", "secure_services")

    def __init__(self, rot: RootOfTrust):
        self.rot = rot

    def _run(self, stages: list[BootStage], commit: bool) -> BootResult:
        if tuple(s.name for s in stages) != self.ORDER:
            return BootResult(False, "boot chain has wrong stages or order")
        pcr = b"\x00" * 32
        new_counters: dict[str, int] = {}
        for s in stages:
            if (not isinstance(s.image, bytes) or not isinstance(s.signature, bytes)
                    or not isinstance(s.version, int) or isinstance(s.version, bool) or s.version < 1):
                return BootResult(False, f"invalid boot stage '{s.name}'")
            try:
                self.rot.vendor_pub.verify(s.signature, _stage_msg(s.name, s.version, s.image))
            except InvalidSignature:
                return BootResult(False, f"bad signature in stage '{s.name}'")
            if s.version < self.rot.counters.get(s.name, 0):
                return BootResult(False, f"rollback blocked for stage '{s.name}'")
            pcr = sha256(pcr + sha256(s.image))  # measured boot: each stage extends the register
            new_counters[s.name] = s.version
        if commit:
            self.rot.counters.update(new_counters)  # only advance counters if the whole chain is valid
        return BootResult(True, "ok", pcr)

    def boot(self, stages: list[BootStage]) -> BootResult:
        return self._run(stages, commit=True)

    def measure(self, stages: list[BootStage]) -> BootResult:
        """Verify a candidate chain and predict its measurement WITHOUT booting it or moving counters."""
        return self._run(stages, commit=False)


# --------------------------------------------------------------------------- 2. hardware keystore
class HardwareKeystore:
    """Secure-element model: the root key is never exported, only used inside derive()."""

    def __init__(self):
        self._k: bytes | None = os.urandom(32)
        self._sealed: set[bytes] = set()  # trusted boot measurements allowed to use the key

    def _trusts(self, pcr: bytes) -> bool:
        return any(hmac.compare_digest(s, pcr) for s in self._sealed)

    def seal_to(self, pcr: bytes) -> None:
        if self._k is None:
            raise Denied("keystore destroyed")
        if not isinstance(pcr, bytes) or len(pcr) != 32:
            raise Denied("invalid boot measurement")
        if self._sealed:
            raise Denied("keystore already sealed")
        self._sealed = {pcr}

    def allow_update(self, current_pcr: bytes, new_pcr: bytes) -> None:
        """Only code running under an already-trusted measurement may nominate the next one."""
        if self._k is None:
            raise Denied("keystore destroyed")
        if not isinstance(new_pcr, bytes) or len(new_pcr) != 32:
            raise Denied("invalid boot measurement")
        if not self._trusts(current_pcr):
            raise Denied("caller is not running a trusted measurement")
        self._sealed.add(new_pcr)

    def withdraw(self, pcr: bytes) -> None:
        self._sealed.discard(pcr)

    def commit(self, pcr: bytes) -> None:
        """Drop every other measurement: from now on only the new OS can use the key."""
        if not self._trusts(pcr):
            raise Denied("cannot commit an untrusted measurement")
        self._sealed = {pcr}

    def derive(self, context: bytes, pcr: bytes) -> bytes:
        if self._k is None:
            raise Denied("keystore destroyed")
        if not self._sealed:
            raise Denied("keystore is not provisioned")
        if not isinstance(context, bytes) or not isinstance(pcr, bytes) or len(pcr) != 32:
            raise Denied("invalid key derivation request")
        if not self._trusts(pcr):
            raise Denied("boot measurement mismatch: hardware key not released")
        return hmac.new(self._k, context + pcr, hashlib.sha256).digest()

    def destroy(self) -> None:
        self._k = None


# --------------------------------------------------------------------------- 3. encrypted vault
class Vault:
    def __init__(self, ks: HardwareKeystore, clock: Clock, log: AuditLog, max_attempts: int = 10):
        self.ks, self.clock, self.log, self.max_attempts = ks, clock, log, max_attempts
        self._salt: bytes | None = None
        self._wrapped: dict[bytes, bytes] = {}  # boot measurement -> DEK wrapped for that measurement
        self._pending: bytes | None = None  # measurement of a staged update that has not booted yet
        self._blobs: dict[tuple[str, str], bytes] = {}  # stands in for flash storage
        self._master: bytes | None = None  # random data-encryption key (DEK); in RAM only while unlocked
        self.failed = 0
        self.locked_until = 0.0
        self.wiped = False

    @property
    def unlocked(self) -> bool:
        return self._master is not None

    def _kek(self, pin: str, pcr: bytes) -> bytes:
        stretched = Scrypt(salt=self._salt, length=32, n=2**14, r=8, p=1).derive(pin.encode())
        hw = self.ks.derive(b"aqos-vault", pcr)
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"aqos-kek").derive(stretched + hw)

    @staticmethod
    def _wrap(kek: bytes, dek: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(kek).encrypt(nonce, dek, b"aqos-wrap")

    def setup(self, pin: str, pcr: bytes) -> None:
        if len(pin) < 6:
            raise Denied("PIN too short (minimum 6)")
        self._salt = os.urandom(16)
        self.ks.seal_to(pcr)
        dek = os.urandom(32)
        self._wrapped = {pcr: self._wrap(self._kek(pin, pcr), dek)}
        self._master, self._pending, self.failed, self.wiped = dek, None, 0, False
        self.log.record("vault.provisioned")

    def _unwrap(self, pin: str, pcr: bytes) -> bytes:
        """The single place a PIN is checked, so lockout and wipe apply to unlock AND to update re-auth."""
        if self.wiped or not self._wrapped:
            raise Denied("no data: device wiped or not provisioned")
        now = self.clock.now()
        if now < self.locked_until:
            raise Denied(f"locked out for {int(self.locked_until - now) + 1}s")
        kek = self._kek(pin, pcr)  # measurement mismatch raises here and is NOT counted as a guess
        blob = self._wrapped.get(pcr)
        if blob is None:
            raise Denied("boot measurement mismatch: no key wrapped for this OS")
        try:
            dek = AESGCM(kek).decrypt(blob[:12], blob[12:], b"aqos-wrap")
        except InvalidTag:
            self.failed += 1
            self.log.record("vault.unlock_failed", attempts=self.failed)
            if self.failed >= self.max_attempts:
                self.wipe()
                raise Denied("too many attempts: device wiped")
            if self.failed >= 5:
                self.locked_until = now + min(30 * 2 ** (self.failed - 5), 3600)
            raise Denied("wrong PIN")
        self.failed = 0
        return dek

    def unlock(self, pin: str, pcr: bytes) -> None:
        self._master = self._unwrap(pin, pcr)
        self.log.record("vault.unlocked")

    def stage_update(self, pin: str, current_pcr: bytes, new_pcr: bytes) -> None:
        """Re-authenticate, then ALSO wrap the DEK for the new OS. The current OS stays valid until commit,
        so a new image that fails to boot can never lock the owner out."""
        if self._master is None:
            raise Denied("vault locked")
        if not hmac.compare_digest(self._unwrap(pin, current_pcr), self._master):
            raise Denied("re-authentication mismatch")
        if self._pending is not None and self._pending != new_pcr:  # a newer update replaces an unbooted one
            self._wrapped.pop(self._pending, None)
            self.ks.withdraw(self._pending)
            self._pending = None
        if new_pcr in self._wrapped:
            return
        self.ks.allow_update(current_pcr, new_pcr)
        try:
            self._wrapped[new_pcr] = self._wrap(self._kek(pin, new_pcr), self._master)
        except Exception:
            self.ks.withdraw(new_pcr)
            raise
        self._pending = new_pcr
        self.log.record("vault.update_staged")

    def commit_update(self, pcr: bytes) -> None:
        """Runs after a successful unlock on the NEW OS. Booting the old OS never commits."""
        if self._pending is not None and hmac.compare_digest(self._pending, pcr):
            self.ks.commit(pcr)
            self._wrapped = {pcr: self._wrapped[pcr]}
            self._pending = None
            self.log.record("vault.update_committed")

    def lock(self) -> None:
        self._master = None

    def wipe(self) -> None:
        """Crypto-erase: destroy the hardware key and every wrapped secret."""
        self._blobs.clear()
        self._wrapped.clear()
        self._salt = self._master = self._pending = None
        self.wiped = True
        self.ks.destroy()
        self.log.record("vault.wiped")

    def _app_key(self, app_id: str) -> bytes:
        if self._master is None:
            raise Denied("vault locked")
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"aqos-app:" + app_id.encode()).derive(
            self._master
        )

    def put(self, app_id: str, name: str, data: bytes) -> None:
        nonce = os.urandom(12)
        ct = AESGCM(self._app_key(app_id)).encrypt(nonce, data, f"{app_id}/{name}".encode())
        self._blobs[(app_id, name)] = nonce + ct

    def get(self, app_id: str, name: str) -> bytes | None:
        blob = self._blobs.get((app_id, name))
        if blob is None:
            return None
        try:
            return AESGCM(self._app_key(app_id)).decrypt(blob[:12], blob[12:], f"{app_id}/{name}".encode())
        except InvalidTag:
            self.log.record("vault.integrity_failure", app=app_id, name=name)
            raise Denied("integrity failure: stored data was tampered with or moved")

    def delete_app(self, app_id: str) -> None:
        for k in [k for k in self._blobs if k[0] == app_id]:
            del self._blobs[k]


# --------------------------------------------------------------------------- 4. signed packages
APP_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
DOMAIN_RE = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$")


class Perm(str, Enum):
    CAMERA = "camera"
    MICROPHONE = "microphone"
    LOCATION = "location"
    CONTACTS = "contacts"
    NETWORK = "network"


SENSITIVE = {Perm.CAMERA, Perm.MICROPHONE, Perm.LOCATION}


@dataclass
class Package:
    manifest: dict
    code: bytes
    dev_pub: bytes
    signature: bytes


def _pkg_msg(manifest: dict, code: bytes) -> bytes:
    canon = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return sha256(canon) + sha256(code)


def build_package(dev_priv: Ed25519PrivateKey, manifest: dict, code: bytes) -> Package:
    return Package(manifest, code, raw_pub(dev_priv), dev_priv.sign(_pkg_msg(manifest, code)))


class PackageManager:
    def __init__(self, log: AuditLog, malware_hashes: set[str] | None = None):
        self.log = log
        self.malware_hashes = malware_hashes or set()
        self.installed: dict[str, Package] = {}
        self.pinned: dict[str, bytes] = {}

    def install(self, pkg: Package) -> str:
        m = pkg.manifest
        if not isinstance(m, dict) or not isinstance(pkg.code, bytes):
            raise Denied("malformed package")
        try:
            app_id, version = m["app_id"], m["version"]
            perms, domains = m["permissions"], m["domains"]
        except (KeyError, TypeError):
            raise Denied("manifest missing required fields")
        if not isinstance(app_id, str) or len(app_id) > 255 or not APP_ID_RE.fullmatch(app_id):
            raise Denied("invalid app_id")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise Denied("invalid version")
        if m.get("debuggable"):
            raise Denied("debuggable builds cannot be installed")
        if not isinstance(perms, list) or not isinstance(domains, list):
            raise Denied("manifest permissions and domains must be lists")
        try:
            [Perm(p) for p in perms]
        except (TypeError, ValueError):
            raise Denied("manifest requests an unknown permission")
        if not all(isinstance(d, str) and len(d) <= 253 and DOMAIN_RE.fullmatch(d.lower()) for d in domains):
            raise Denied("manifest contains an invalid domain")
        if not isinstance(pkg.dev_pub, bytes) or not isinstance(pkg.signature, bytes):
            raise Denied("malformed package signature")
        try:
            Ed25519PublicKey.from_public_bytes(pkg.dev_pub).verify(pkg.signature, _pkg_msg(m, pkg.code))
        except (InvalidSignature, ValueError):
            raise Denied("invalid package signature")
        if sha256(pkg.code).hex() in self.malware_hashes:
            raise Denied("package matches a known-malware hash")
        if app_id in self.installed:
            if not hmac.compare_digest(self.pinned[app_id], pkg.dev_pub):
                self.log.record("install.hijack_blocked", app=app_id)
                raise Denied("update signed by a different developer key")
            if version <= self.installed[app_id].manifest["version"]:
                raise Denied("downgrade or replay of same version blocked")
        else:
            self.pinned[app_id] = pkg.dev_pub
        self.installed[app_id] = pkg
        self.log.record("install", app=app_id, version=version)
        return app_id

    def remove(self, app_id: str) -> None:
        self.installed.pop(app_id, None)
        self.pinned.pop(app_id, None)


# --------------------------------------------------------------------------- 5. permissions
class Mode(Enum):
    DENY = 0
    ONCE = 1
    WHILE_IN_USE = 2
    ALWAYS = 3


class PermissionBroker:
    AUTO_REVOKE_SECONDS = 90 * 86400

    def __init__(self, clock: Clock, log: AuditLog):
        self.clock, self.log = clock, log
        self._grants: dict[tuple[str, Perm], tuple[Mode, float]] = {}
        self._last_used: dict[tuple[str, Perm], float] = {}
        self.indicators: list[tuple[float, str, str]] = []  # (time, app, sensor): drives the green dot

    def user_grant(self, app_id: str, perm: Perm, mode: Mode, declared: set[Perm]) -> None:
        if not isinstance(perm, Perm) or not isinstance(mode, Mode):
            raise Denied("invalid permission grant")
        if perm not in declared:
            raise Denied("cannot grant a permission the app never declared")
        if perm in SENSITIVE and mode is Mode.ALWAYS:
            raise Denied("sensors can never be granted 'always'")
        if mode is Mode.DENY:
            self._grants.pop((app_id, perm), None)
        else:
            self._grants[(app_id, perm)] = (mode, self.clock.now())
        self.log.record("perm.grant", app=app_id, perm=perm.value, mode=mode.name)

    def revoke(self, app_id: str, perm: Perm) -> None:
        self._grants.pop((app_id, perm), None)
        self.log.record("perm.revoke", app=app_id, perm=perm.value)

    def check(self, app_id: str, perm: Perm, declared: set[Perm], foreground: bool) -> None:
        if perm not in declared:
            raise Denied(f"{perm.value}: not declared in manifest")
        g = self._grants.get((app_id, perm))
        if g is None:
            raise Denied(f"{perm.value}: not granted by user")
        mode, _ = g
        if not foreground and (perm in SENSITIVE or mode is not Mode.ALWAYS):
            raise Denied(f"{perm.value}: background access refused")
        if mode is Mode.ONCE:
            del self._grants[(app_id, perm)]
        now = self.clock.now()
        self._last_used[(app_id, perm)] = now
        if perm in SENSITIVE:
            self.indicators.append((now, app_id, perm.value))
        self.log.record("perm.use", app=app_id, perm=perm.value)

    def auto_revoke(self) -> list[tuple[str, str]]:
        now, revoked = self.clock.now(), []
        for (app, perm), (_, granted_at) in list(self._grants.items()):
            last = max(self._last_used.get((app, perm), 0.0), granted_at)
            if now - last > self.AUTO_REVOKE_SECONDS:
                del self._grants[(app, perm)]
                revoked.append((app, perm.value))
                self.log.record("perm.auto_revoked", app=app, perm=perm.value)
        return revoked

    def drop_app(self, app_id: str) -> None:
        for k in [k for k in self._grants if k[0] == app_id]:
            del self._grants[k]


# --------------------------------------------------------------------------- 6. firewall
class Firewall:
    DEFAULT_BLOCKLIST = {"doubleclick.net", "google-analytics.com", "app-measurement.com"}

    def __init__(self, log: AuditLog):
        self.log = log
        self.blocklist = set(self.DEFAULT_BLOCKLIST)
        self._allow: dict[str, set[str]] = {}

    def register(self, app_id: str, domains: list[str]) -> None:
        self._allow[app_id] = {d.lower() for d in domains}

    @staticmethod
    def _matches(host: str, domain: str) -> bool:
        return host == domain or host.endswith("." + domain)  # dot boundary stops evilexample.com

    def check(self, app_id: str, host: str, port: int, tls: bool) -> None:
        if not isinstance(host, str) or not host or len(host) > 253:
            raise Denied("invalid destination host")
        if (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
                or not isinstance(tls, bool)):
            raise Denied("invalid network parameters")
        host = host.lower().rstrip(".")
        if not tls or port == 80:
            raise Denied("cleartext traffic is not allowed")
        try:
            ipaddress.ip_address(host)
            raise Denied("raw IP connections are not allowed (use a named, allow-listed domain)")
        except ValueError:
            pass
        if any(self._matches(host, d) for d in self.blocklist):
            raise Denied("destination is a known tracker")
        if not any(self._matches(host, d) for d in self._allow.get(app_id, ())):
            raise Denied("destination not in the app's declared domains")
        self.log.record("net.allow", app=app_id, host=host)


# --------------------------------------------------------------------------- 7. the system
class AQOS:
    MAX_BLOB = 1_000_000

    def __init__(self, rot: RootOfTrust, keystore: HardwareKeystore | None = None, clock: Clock | None = None,
                 malware_hashes: set[str] | None = None):
        self.clock = clock or Clock()
        self.log = AuditLog(self.clock)
        self.keystore = keystore or HardwareKeystore()
        self.bootchain = BootChain(rot)
        self.vault = Vault(self.keystore, self.clock, self.log)
        self.pm = PackageManager(self.log, malware_hashes)
        self.broker = PermissionBroker(self.clock, self.log)
        self.fw = Firewall(self.log)
        self.booted = False
        self.pcr = b""
        self._procs: dict[str, str] = {}
        self._fg: str | None = None

    # ---- boot & lock
    def power_on(self, stages: list[BootStage]) -> BootResult:
        res = self.bootchain.boot(stages)
        self.log.record("boot", ok=res.ok, reason=res.reason)
        self.booted, self.pcr = res.ok, (res.pcr if res.ok else b"")
        self._procs.clear()
        self._fg = None
        self.vault.lock()
        return res

    def _need_boot(self) -> None:
        if not self.booted:
            raise Denied("system not booted")

    def provision(self, pin: str) -> None:
        self._need_boot()
        self.vault.setup(pin, self.pcr)

    def unlock(self, pin: str) -> None:
        self._need_boot()
        self.vault.unlock(pin, self.pcr)
        self.vault.commit_update(self.pcr)  # first successful unlock on the new OS retires the old one

    def apply_update(self, stages: list[BootStage], pin: str) -> bool:
        """Stage a vendor-signed OS update. Needs an unlocked device AND the PIN again.
        Returns False when the image is already the running one."""
        self._need_boot()
        if not self.vault.unlocked:
            raise Denied("unlock the device before updating")
        res = self.bootchain.measure(stages)
        if not res.ok:
            self.log.record("update.rejected", reason=res.reason)
            raise Denied(f"update rejected: {res.reason}")
        if res.pcr == self.pcr:
            return False
        self.vault.stage_update(pin, self.pcr, res.pcr)
        self.log.record("update.staged")
        return True

    def lock(self) -> None:
        self.vault.lock()
        self._procs.clear()
        self._fg = None
        self.log.record("device.locked")

    # ---- apps
    def install(self, pkg: Package) -> str:
        self._need_boot()
        app_id = self.pm.install(pkg)
        self.fw.register(app_id, pkg.manifest["domains"])
        return app_id

    def uninstall(self, app_id: str) -> None:
        self.pm.remove(app_id)
        self.vault.delete_app(app_id)
        self.broker.drop_app(app_id)
        self._procs = {t: a for t, a in self._procs.items() if a != app_id}
        self.log.record("uninstall", app=app_id)

    def _declared(self, app_id: str) -> set[Perm]:
        return {Perm(p) for p in self.pm.installed[app_id].manifest["permissions"]}

    def user_grant(self, app_id: str, perm: Perm, mode: Mode) -> None:
        if not self.vault.unlocked:
            raise Denied("only the authenticated user can grant permissions")
        if app_id not in self.pm.installed:
            raise Denied("unknown app")
        self.broker.user_grant(app_id, perm, mode, self._declared(app_id))

    def launch(self, app_id: str) -> str:
        if not self.vault.unlocked:
            raise Denied("device locked")
        if app_id not in self.pm.installed:
            raise Denied("unknown app")
        token = secrets.token_hex(16)  # unforgeable process identity, held only by the kernel and the process
        self._procs[token] = app_id
        return token

    def set_foreground(self, token: str | None) -> None:
        self._fg = token

    def housekeeping(self) -> list[tuple[str, str]]:
        return self.broker.auto_revoke()

    # ---- syscall gate
    def syscall(self, token: str, op: str, **kw):
        app = self._procs.get(token) if isinstance(token, str) else None
        if app is None or not self.booted or not self.vault.unlocked:
            self.log.record("syscall.rejected", op=str(op))
            raise Denied("invalid process or device locked")
        try:
            return self._dispatch(app, token, op, kw)
        except Denied as e:
            self.log.record("syscall.denied", app=app, op=str(op), reason=str(e))
            raise

    @staticmethod
    def _name(n) -> str:
        if (not isinstance(n, str) or n in {".", ".."}
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", n)):
            raise Denied("invalid object name")
        return n

    def _dispatch(self, app: str, token: str, op: str, kw: dict):
        declared, fg = self._declared(app), self._fg == token
        if op == "storage.put":
            data = kw.get("data")
            if not isinstance(data, bytes) or len(data) > self.MAX_BLOB:
                raise Denied("invalid data")
            self.vault.put(app, self._name(kw.get("name")), data)  # app id comes from the kernel, never the caller
            return None
        if op == "storage.get":
            return self.vault.get(app, self._name(kw.get("name")))
        if op == "net.connect":
            self.broker.check(app, Perm.NETWORK, declared, fg)
            self.fw.check(app, kw.get("host", ""), kw.get("port", 443), kw.get("tls", True))
            return "connected"
        if op == "sensor.use":
            try:
                perm = Perm(kw.get("sensor"))
            except ValueError:
                raise Denied("unknown sensor")
            if perm not in SENSITIVE:
                raise Denied("not a sensor")
            self.broker.check(app, perm, declared, fg)
            return f"{perm.value} stream open (privacy indicator on)"
        if op == "contacts.read":
            self.broker.check(app, Perm.CONTACTS, declared, fg)
            return [("Example Contact", "+000000000")]
        raise Denied("unknown syscall")
