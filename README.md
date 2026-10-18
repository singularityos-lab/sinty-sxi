# sinty-sxi

SXI applications on SintyOS. SXI is the application bundle of the SIX native
image contract: one directory that carries a signed manifest, the publisher's
signing delegation and the application itself. This repository implements the
format and installs SXI applications on the Linux kernel, so the same bundles
keep working when SIX becomes the system kernel.

It contains:

- `wire`: the SXI v1 manifest decoder and encoder (deterministic CBOR,
  Unicode 16.0.0 NFC, the v1 limits and identifiers);
- `cose`: the detached COSE Sign1 signatures used by bundles, delegations,
  revocations and collection indexes;
- `trust`: publisher roots, signing delegations, revocation statements and the
  monotonic history that refuses stale signers and older releases;
- `bundle`: building a bundle from a payload directory, and verifying a bundle
  on disk without following links or crossing mounts;
- `image`: packing a verified bundle into a reproducible erofs image, the
  dm-verity hash tree for it, and mounting it read-only;
- `index`: signed collection indexes, the list of applications a source offers;
- `manager`: installs, updates, rolls back and removes applications;
- `sxid`: the system daemon on the bus as `dev.sinty.SXI1`;
- `sxi`: the publisher tool and a client for `sxid`.

## Why it exists

SintyOS ships a small base system. Everything else is installed later from the
store, either from a curated collection or from other sources the user adds.
Applications made for the system use the platform libraries the base system
already provides, so packaging them with their own runtime would duplicate
what is already there. SXI keeps each application immutable and signed, and
lets the system check who published it before a single byte runs.

## The SXI v1 bundle

```text
Name.sxi/
  SXI/Manifest.cbor
  SXI/Signatures/Manifest.cose
  SXI/Signatures/Publisher.certs
  Images/amd64/main
  Resources/
  Icons/
```

The manifest follows the SXI v1 wire schema. The `wire` package accepts and
rejects exactly what the v1 corpus in `wire/testdata/v1` expects, gives every
rejection the same failure class as the reference decoder, and reproduces the
publisher, application, payload, release and slot identifiers.

Every object outside `SXI/` is listed in the manifest inventory with its kind,
mode, size and SHA-256 digest. Directories are `0555`, data files `0444` and
images `0555`. Links, devices, sockets, FIFOs, extended attributes, extra or
missing files and objects on another mount fail verification.

## Signatures

All signatures are COSE Sign1 (RFC 9052) with Ed25519. The structure is tagged
(18). The protected header holds exactly three labels: algorithm (`1`, EdDSA
`-8`), content type (`3`) and key ID (`4`, the SHA-256 digest of the DER
SubjectPublicKeyInfo). The unprotected header is empty. The external AAD is
`SIX-SXI-SIGNATURE-v1` followed by a zero byte. Any other label, a duplicate
or unordered label, a non-shortest encoding or trailing bytes is rejected.

| Content type | Payload | Signed by |
| --- | --- | --- |
| `application/vnd.six.sxi.manifest;v=1` | the exact manifest bytes, detached | a delegated release key |
| `application/vnd.six.sxi.delegation;v=1` | a delegation record, attached | the publisher root |
| `application/vnd.six.sxi.revocation;v=1` | a revocation statement, attached | the publisher root |
| `application/vnd.sinty.sxi.index+json;v=1` | the exact index bytes, detached | a delegated index key |

`Publisher.certs` is one delegation: a deterministic CBOR map of the delegated
public key (`1`), delegation epoch (`2`), validity start and end in Unix
seconds (`3`, `4`) and the sorted purposes `index` and `release` (`5`). Only
the root delegates; a delegated key cannot delegate another key.

A revocation statement holds the revocation epoch (`1`), the lowest delegation
epoch still accepted (`2`) and the sorted key IDs it revokes (`3`).

Roots come only from the system trust store. The store remembers, for each
publisher, the highest delegation and revocation epochs and the highest
release of every application it accepted. None of them ever goes down, so a
revoked key, an old delegation, a manifest signed before a revocation, or an
older release of an installed application is refused.

Key files are raw Ed25519 keys: 64 bytes for a private key and 32 for a public
key.

## Images

A published release is the bundle packed as an erofs image, built so the same
bundle always gives the same bytes:

```sh
mkfs.erofs -z lz4hc,9 -E ztailpacking -T0 --all-root --ignore-mtime -x -1 -U UUID
```

The dm-verity hash tree uses format 1, SHA-256 and 4096-byte blocks. Its salt
is `SHA-256("SIX-SXI-VERITY-v1\0" || slot_id)` and the UUIDs come from the
salt, so a device rebuilds the same tree from the image alone. The tree this
package writes is identical, byte for byte, to the one `veritysetup format`
writes for the same parameters.

## Collections

A collection is three files under one URL: `index.json`, its detached
signature `index.json.cose` and the delegation `index.certs`. The index names
the publisher root and a sequence that never goes down, then lists each
application with its releases: version, release sequence, architecture, image
URL, size, SHA-256, verity root hash and slot ID.

`sxid` installs a release in this order: it downloads the image and checks its
size and digest against the signed index, rebuilds the verity tree and checks
its root hash, maps the image through dm-verity, mounts it without exec, and
verifies the bundle and its signatures inside. Only then does the image become
a slot. The slot is mounted read-only at `/run/sxi/apps/ID`, and its desktop
entry is written to `/run/sxi/share/applications`, launching the entry image
from the mount. An SVG icon is linked into the hicolor theme under
`/run/sxi/share/icons` so the application finds its own icon by name.

Applications built with the prefix `/run/sxi/apps/ID` keep the usual
`bin`, `lib` and `share` layout, so their compiled-in paths, translations and
data point into their own mount. sxid links their icons, D-Bus services,
Singularity search providers, app settings, capabilities, share targets, file
actions, widgets and shell plugins into `/run/sxi/share`, which comes after the
system data directories, so an application never replaces a system file. A
D-Bus service is only linked when the name it activates belongs to the
application. The previous release stays on disk for `rollback`.

GSettings schemas listed as resources are compiled into
`/run/sxi/share/glib-2.0/schemas`. Each schema, enum and flags ID must be the
application ID or start with it, and each path must sit under the path made
from the application ID, so an application can never redefine the settings of
the system or of another application.

Sources are JSON files in `/usr/share/sinty/sxi/sources.d` and
`/etc/sinty/sxi/sources.d`:

```json
{"name": "collection", "url": "https://example.org/collection", "official": true}
```

`official` marks the collection the system itself vouches for. It only counts
in `/usr/share/sinty/sxi/sources.d`, which is part of the verified system
image; a source added under `/etc` is never official.

Publisher roots are `*.pub` files in `/usr/share/sinty/sxi/roots`. State lives
in `/var/lib/sinty/sxi`.

## The daemon

`dev.sinty.SXI1` at `/dev/sinty/SXI1`:

| Method | |
| --- | --- |
| `ListAvailable() -> s` | the applications of every collection, as JSON |
| `ListInstalled() -> s` | the installed applications, as JSON |
| `Refresh()` | fetch every collection again; sxid also refreshes on its own, retrying every few seconds until the network is up |
| `Install(s id)` | install or update; progress arrives as signals |
| `Remove(s id)` | remove an application and its images |
| `Rollback(s id)` | switch back to the previous release |

Signals: `Changed()`, `Progress(s id, s stage, x done, x total)` and
`Finished(s id, s error)`, where an empty error means success. Root and human
users (uid 1000 to 59999) may change applications. Only roots in the trust
store can publish anything installable.

## Publishing

```sh
sxi keygen -o root
sxi keygen -o release
sxi delegate -root root.key -key release.pub -purpose release -o release.certs
sxi build -spec app.json -payload payload -root root.pub -key release.key -certs release.certs -o App.sxi
sxi verify -roots roots App.sxi
sxi pack -roots roots -o app.sxi App.sxi
```

`pack` prints the size, digest, verity root hash and slot ID that go into the
collection index:

```sh
sxi keygen -o index
sxi delegate -root root.key -key index.pub -purpose index -o index.certs
sxi index init -root root.pub -name "My collection" -o index.json
sxi index add -index index.json -pack app.json -url https://example.org/app-1.sxi -name App
sxi index sign -index index.json -key index.key -certs index.certs -root root.pub
```

Every `add` and `remove` raises the index sequence. `sign` checks the signed
result against the root before it writes `index.json.cose` and `index.certs`.

## Development

`sxid -session -extract -roots DIR -state DIR -run DIR -sources DIR` serves on
the session bus and extracts images into the runtime directory instead of
mounting them, after checking their verity root hash in user space. It needs
no root and is meant for working on clients. `SXI_BUS=session sxi list` talks
to it.

## Not yet implemented

- Launch confinement. An application currently runs with the rights of the
  user who starts it; per-application grants, portals and state capabilities
  from the SXI contract are not enforced yet.
- Health checks, state snapshots and schema migration on update.
- Re-checking revocation for already installed releases at launch.
- Registered extensions: every critical extension is rejected and every
  non-critical one is kept without effect.

## Build

    make build            # ./sxi and ./sxid
    make test
    go build ./...

Requires Go >= 1.26 and Linux. The tests also use `mkfs.erofs` and
`fsck.erofs` (erofs-utils) and `veritysetup` (cryptsetup) when they are
installed. The non-stdlib dependencies are `github.com/godbus/dbus/v5`,
`golang.org/x/sys/unix` and the `boot` package of
[AtomLoops](https://github.com/mirkobrombin/AtomLoops) for loop devices and
dm-verity.

The Unicode tables in `wire/unicode16.go` are Unicode 16.0.0 normalization data
under the license in `wire/UNICODE-LICENSE.txt`.
