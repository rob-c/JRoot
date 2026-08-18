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
    jroot.thirdPartyCopy("https://source.example.org/f", "https://target.example.org/f");
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
        .withRequestTimeout(Duration.ofSeconds(60));
```

## Command line

The jar is executable and covers the same ground:

```
$ jroot ls -l davs://webdav.example.org/store/data/
$ jroot stat root://door.example.org//store/data/file.root
$ jroot get root://door.example.org//store/data/file.root /scratch/
$ jroot cp /scratch/file.root davs://webdav.example.org/store/data/file.root
$ jroot tpc https://source.example.org/f https://target.example.org/f
$ jroot checksum root://door.example.org//store/f adler32
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
  PEM, DER, PKCS#1 and PKCS#8 are all read directly.
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

**Binary protocol** — every request in the specification except `kXR_gpfile`
and `kXR_clone`: `open`/`close`/`read`/`write`/`sync`/`truncate`, vector reads
and writes (`kXR_readv`, `kXR_writev`), checksummed paged I/O (`kXR_pgread`,
`kXR_pgwrite`), checkpoints (`kXR_chkpoint` with commit and rollback),
`stat`/`statx`/`statvfs`, `dirlist` with stat, `mkdir`/`rm`/`rmdir`/`mv`/`chmod`,
extended attributes (`kXR_fattr`), `locate`, `prepare`, `query`, `set`, `ping`,
and the `login`/`auth`/`protocol`/`endsess` session requests.

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

## Known limitations

- **One data stream per connection.** `kXR_bind` is encoded and the response
  parsed, but nothing binds a second socket to a session, so a transfer uses a
  single TCP stream. This is a throughput ceiling on a long fat network, not a
  correctness limit; parallel streams are the next thing worth adding.
- **Third-party copy is HTTP only.** The binary protocol arranges a TPC
  through opaque tags on `kXR_open` rather than a request of its own, and
  `JRoot.thirdPartyCopy` refuses anything but HTTP at both ends rather than
  pretending otherwise.
- **`kXR_gpfile` and `kXR_clone` are not implemented.**
- GSI runs the unsigned Diffie-Hellman handshake; the signed variant and
  delegation are not implemented.

## Building

```
mvn package        # target/jroot-0.1.0-SNAPSHOT.jar, executable
mvn test           # 168 tests
```

The tests are not mocks of JRoot's own classes. The XRootD tests run against a
real `ServerSocket` speaking real frames, and the HTTP tests against a real
`com.sun.net.httpserver` — so a wrong offset, a dropped header or a
mis-declared length fails the test instead of passing through a stub.

## Licence

LGPL-3.0-or-later. See [COPYING.LESSER](COPYING.LESSER) and
[COPYING](COPYING).
