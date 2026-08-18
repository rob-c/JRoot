# JRoot

A pure-Java client for XRootD storage, over all three of the protocols such
storage speaks: the binary `root://` protocol, XRootD's HTTP interface, and
WebDAV — with GSI (X.509 proxy) and bearer-token authentication.

JRoot is an independent implementation from the wire up. It is not a binding,
a port, or a wrapper: there is no JNI, no `libXrdCl`, and nothing outside the
JDK. It talks to the protocol, not to another client.

```xml
<dependency>
  <groupId>io.github.rob-c</groupId>
  <artifactId>jroot</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Requires Java 17. **No runtime dependencies** — the only thing on the test
classpath is JUnit.

## Using it

One handle covers every transport; the URL decides which one runs.

```java
try (JRoot jroot = JRoot.open()) {
    StatInfo stat = jroot.stat("root://eos.example.org//eos/atlas/file.root");
    byte[] header  = jroot.read("root://eos.example.org//eos/atlas/file.root", 0, 512);

    for (DirEntry entry : jroot.list("davs://webdav.example.org/store/data/")) {
        System.out.println(entry.name() + "\t" + entry.stat().map(StatInfo::size).orElse(-1L));
    }

    jroot.copy("root://eos.example.org//eos/atlas/file.root", "/scratch/file.root");
    jroot.thirdPartyCopy("root://source.example.org//store/f", "root://target.example.org//store/f");
}
```

`root://`, `roots://`, `xroot://` and `xroots://` go over the binary protocol;
`http(s)://`, `dav://` and `davs://` over HTTP and WebDAV; a bare path or
`file://` is the local filesystem, so a copy always has somewhere to land.

Anything one protocol alone can do stays on its own client, which is the same
object the facade dispatches to:

```java
try (XrdFile file = jroot.xrootd().open("root://door.example.org//store/f.root")) {
    List<ReadVSegment> baskets = file.readV(List.of(   // one kXR_readv round trip
            new long[] {  8192, 4096 },
            new long[] {131072, 8192 }));
    byte[] verified = file.pgRead(0, 65536);           // CRC32C-checked pages
}

jroot.webdav().thirdPartyCopy(source, target, /* pull */ true,
        /* the far end's token, or null for this client's own */ null,
        /* overwrite */ false);
List<LocationInfo> replicas = jroot.xrootd().locate("root://redirector//store/f");
```

Configuration is an immutable record with a `with…` for each field:

```java
Config config = Config.defaults()
        .withToken(System.getenv("BEARER_TOKEN"))
        .withTls(Config.Tls.REQUIRED)
        .withDataStreams(4)                        // TCP streams per root:// session
        .withRequestTimeout(Duration.ofSeconds(60));
```

## Command line

The jar is executable and covers the same ground:

```
$ jroot ls -l davs://webdav.example.org/store/data/
$ jroot stat root://door.example.org//store/data/file.root
$ jroot get root://door.example.org//store/data/file.root /scratch/
$ jroot cp /scratch/file.root davs://webdav.example.org/store/data/file.root
$ jroot tpc root://source.example.org//store/f root://target.example.org//store/f
$ jroot --streams 4 get root://door.example.org//store/data/big.root /scratch/
$ jroot checksum root://door.example.org//store/f adler32
$ jroot cp -r root://door.example.org//store/run1 /scratch/run1
$ jroot rm -r root://door.example.org//store/run1
$ jroot chmod 640 root://door.example.org//store/f.root
$ jroot xattr root://door.example.org//store/f.root user.checksum
$ jroot prepare root://door.example.org//store/data/file.root
$ jroot prepstat 7f3a root://door.example.org//store/data/file.root
$ jroot locality davs://webdav.example.org/store/data/file.root
```

`jroot --help` lists every command and option.

## Authentication

The server says what it will accept, and JRoot builds a ladder of the
mechanisms it can answer with, in the server's order of preference unless
`Config.withMechanisms` overrides it. Each is tried in turn, and when all of
them fail the error names every one and why it was refused, rather than
reporting only the last.

- **`ztn` — bearer tokens.** WLCG Bearer Token Discovery, in the order the C
  client uses: an explicit token, then `$BEARER_TOKEN`, then
  `$BEARER_TOKEN_FILE`, then `$XDG_RUNTIME_DIR/bt_u$UID`, then
  `/tmp/bt_u$UID`. A JWT's `exp` is read (not verified) so an expired token
  fails here rather than after a round trip, and a server that states token
  size and lifetime limits has them checked before anything is sent. Over
  HTTP the same token becomes an `Authorization: Bearer` header.
- **`gsi` — X.509 proxies.** `$X509_USER_PROXY` or `/tmp/x509up_u$UID`,
  including RFC 3820 proxy chains, with `$X509_CERT_DIR` for the CA path. The
  handshake is the unsigned Diffie-Hellman exchange stock `XrdSecgsi` runs;
  PEM, DER, PKCS#1 and PKCS#8 are all read directly. The chain the server
  offers is walked against the CA directory before its key is used — by hand,
  since PKIX rejects any proxy on sight for carrying a critical extension it
  does not know. A server that asks the client to sign a proxy for it
  (`kXGS_pxyreq`) gets one, issued per RFC 3820 and never outliving its
  parent, but only when `Config.withDelegateProxy` says it may: delegation
  hands the far end a credential that carries your identity, which is a thing
  to decide rather than to discover.
- **`sss` — a shared secret.** The keytab named by `--keytab`,
  `Config.withKeytab`, `$XrdSecSSSKT` or `~/.xrd/sss.keytab`, which must be
  mode 0600 because it holds cleartext secrets. The credential is the
  format `XrdSecsss` writes: a 16-byte cleartext header naming the key, then
  a nonce, a timestamp and the user's name under Blowfish-CFB64 with a CRC-32
  appended — `bf32`, the same transform that then signs the session's
  requests. A server that names a key (`n:<name>`) gets that key or an error,
  never a different one.
- **`krb5` — a Kerberos ticket.** The cache `kinit` wrote, named by
  `--ccache`, `Config.withCredentialCache`, `$KRB5CCNAME` or
  `/tmp/krb5cc_$UID`. The blob is `"krb5\0"` and then an AP-REQ for the
  principal the server's offer names, or `xrootd/<host>` when it names none;
  the realm in an offer is dropped, since Kerberos derives it from the
  instance. The AP-REQ comes from the JDK's own GSS-API — still no
  dependencies, and still the library the KDC's administrator tests against —
  stripped of the RFC 2743 wrapper it arrives in, because the server hands
  what follows the name straight to `krb5_rd_req`. The FILE cache format is
  read here rather than delegated, which is what turns "authentication
  failed" into "your ticket expired 40 minutes ago" before anything touches
  the network; `Krb5Ccache.tickets` is public so a caller can ask the same
  question. A server that asks for a forwarded ticket-granting ticket
  (`fwdtgt`) is refused by name.
- **`unix`** — the login name and group, for a server that asks for nothing
  better.

TLS is negotiated the way the protocol specifies: `kXR_protocol` is asked
first, and if the server sets any of `kXR_gotoTLS`, `kXR_tlsLogin`,
`kXR_tlsSess` or `kXR_tlsData`, the connection upgrades in place before the
login goes out. `roots://` and `xroots://` demand it whatever the server says,
`Config.Tls.REQUIRED` upgrades unconditionally, and `Config.Tls.DISABLED`
refuses a server that will not talk without it. A redirect that would move an
encrypted session onto a plaintext one is refused rather than followed.

Requests are signed with `kXR_sigver` whenever the server asks for it, at any
of the four security levels and honouring the per-request overrides in the
`kXR_protocol` security block.

## What is implemented

**Binary protocol** — every request in the specification:
`open`/`close`/`read`/`write`/`sync`/`truncate`, vector reads
and writes (`kXR_readv`, `kXR_writev`), checksummed paged I/O (`kXR_pgread`,
`kXR_pgwrite`), checkpoints (`kXR_chkpoint` with commit and rollback),
`stat`/`statx`/`statvfs`, `dirlist` with stat, `mkdir`/`rm`/`rmdir`/`mv`/`chmod`,
extended attributes (`kXR_fattr`), `locate`, `prepare`, `query`, `set`, `ping`,
`kXR_gpfile`, and the `login`/`auth`/`protocol`/`endsess` session requests.

**One facade over all three** — `stat`, `list`, `read`, `write`, `copy`,
`mkdir`, `rm`, `mv`, `chmod`, `truncate` and extended attributes dispatch on
the URL's scheme, and `copyTree`/`rmTree` walk a whole tree over whichever
transport it lives on — one `DELETE` for WebDAV, which is recursive by
definition, and depth-first otherwise, since a directory cannot go until it
is empty. Opaque data stays after the path on the way down, so a token that
authorises the parent authorises the children. Where a transport genuinely
has no such notion — permission bits over HTTP, say — the call says so
rather than pretending it worked.

**Paged I/O with its retransmissions** — `kXR_pgread` verifies every 4 KiB
page's CRC32C before a byte is returned, across however many `kXR_status`
frames the server splits the answer into and from an offset that need not be
on a page boundary. `kXR_pgwrite` is the interesting direction: a server that
finds a page's checksum wrong writes the data anyway and answers with the
offsets it could not trust, so the write is only finished once those pages
have been sent again, with `kXR_pgRetry` set, and accepted. Ignoring that
trailer — which is the easy thing to do, since the request did not fail —
leaves the file quietly wrong on disk.

**Multiple data streams** — `Config.withDataStreams(n)` binds `n-1` extra
sockets to a session with `kXR_bind` when a file is first opened, and reads
and writes are spread across them a chunk at a time. The frames are split the
way the protocol asks for: `dlen` counts the bytes on both links, the header
goes up the control link, and the bulk data down the bound one. A server that
refuses to bind leaves the session working on the control link alone.

**Third-party copy** — over the binary protocol as well as HTTP.
`XrdClient.thirdPartyCopy` runs the rendezvous XRootD does through opaque
tags: a placement probe to find which data server will hold the file, a
coordinator open on that server carrying the shared key, and a destination
open carrying `tpc.src`, `tpc.key` and the size, followed by the two
`kXR_sync`s — the second of which does not answer until the transfer is
done.

The response side is complete too, and that is where most of the protocol
actually lives: `kXR_oksofar` continuations, `kXR_wait` and `kXR_waitresp`,
redirects (including a redirect that names a TLS port with a negative number),
`kXR_attn` asynchronous messages, and the `kXR_status` response format with
its per-request checksums.

**HTTP and WebDAV** — `GET` whole and ranged, multi-range `GET` parsed out of
`multipart/byteranges`, `PUT` from memory or streamed from a file, `HEAD`,
`DELETE`, `PROPFIND` at depth 0 and 1, `MKCOL`, `MOVE`, `COPY`, checksums via
`Want-Digest`, and WLCG third-party copy in both the pull and push directions,
with the transfer's outcome read from the final line of the performance
markers. Redirects are followed by hand, because the JDK's own follower drops
the `Authorization` header on the way — which is exactly the header a door
redirecting to a pool needs to keep. Bodies are replayable, so a `PROPFIND` or
an upload survives the redirect intact.

**Staging from tape** — `jroot.stage(urls)` asks a site to bring files
online and hands back the handle it took the request down under;
`stageStatus(handle, urls)` says how each one is getting on, and
`locality(urls)` asks where a file is now without asking for it to move.
Over `root://` that is `kXR_prepare` with `kXR_stage`, and then
`kXR_query` with `kXR_QPrep` — the one query whose answer is JSON rather
than CGI — with `kXR_cancel` to withdraw a request by naming it rather
than its files. Over HTTP it is the WLCG Tape REST API, found by asking
the site for `/.well-known/wlcg-tape-rest-api` and falling back to
`/api/v1/tape` when nothing is published: `POST /stage` with a disk
lifetime, `GET /stage/{id}`, `POST /stage/{id}/cancel` for some of the
files, `DELETE /stage/{id}` for the whole request, `POST /release/{id}`
to give up the pins, and `POST /archiveinfo` for locality. Both schemes
answer in the same shape and the same words, so a caller that waits on
one waits on the other unchanged, and a local file — already online, by
definition — answers too.

## Known limitations

- **GSI signed Diffie-Hellman is not implemented.** A server that offers
  `kXRS_cipher` instead of `kXRS_puk` is refused by name rather than
  mis-answered; the unsigned exchange is what stock `XrdSecgsi` runs and what
  every deployment this was written against accepts.
- **`kXR_clone` is an extension, not a standard.** It is encoded exactly as
  nginx-xrootd implements it, one slot past `kXR_REQFENCE`. A stock server
  answers `kXR_InvalidRequest`, which is the correct thing for it to do.
- **`kXR_gpfile` is unfinished upstream.** The request is encoded and its
  reply parsed, but XRootD's own implementation of it is incomplete, so what
  a server does with one is between you and that server.

## Building

```
mvn package        # target/jroot-0.1.0-SNAPSHOT.jar, executable
mvn test           # 316 tests
```

The tests are not mocks of JRoot's own classes. The XRootD tests run against a
real `ServerSocket` speaking real frames, and the HTTP tests against a real
`com.sun.net.httpserver` — so a wrong offset, a dropped header or a
mis-declared length fails the test instead of passing through a stub. The GSI
tests are the same: real certificates, a real Diffie-Hellman exchange and a
real PKCS#10, with the test playing the server's half, so the two ends have to
agree on a key rather than be told they did.

## Licence

LGPL-3.0-or-later. See [COPYING.LESSER](COPYING.LESSER) and
[COPYING](COPYING).
