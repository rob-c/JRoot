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

A copy is a transfer in its own right, not a read followed by a write: it
draws chunks from every replica at once, steps past the ones that will not
answer, and checks what landed against what the source says it should be.

```java
Transfer.Result result = jroot.transfer().copy(
        List.of("root://door1.example.org//store/f.root",     // the same file,
                "root://door2.example.org//store/f.root"),    // two sites
        "/scratch/f.root");
System.out.println(result);       // 4294967296 bytes to /scratch/f.root in 61.3s
                                  // (66.8 MB/s), adler32 verified

jroot.transfer().run(Transfer.plan(List.of(source), target)
        .withParallel(16)
        .withChunkSize(32 << 20)
        .withAlgorithm("crc32c")
        .withProgress((done, total) -> bar.update(done, total)));
```

A lone `root://` source is asked of its redirector first, so a manager's
answer to `kXR_locate` becomes the list of data servers to read from — one
file, several sockets, several machines. A `.meta4` source is fetched and
unfolded into its replicas in the publisher's priority order, and the hash
the metalink carries becomes what the copy is checked against.

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

Nothing here blocks a caller who does not want it to. `jroot.async()` is the
same client answered with futures, and XRootD multiplexes requests over one
connection per server, so a hundred outstanding calls to one door are a
hundred requests in flight on one socket:

```java
List<CompletableFuture<StatInfo>> all = urls.stream()
        .map(jroot.async()::stat).toList();
CompletableFuture.allOf(all.toArray(CompletableFuture[]::new)).join();
```

A session that breaks under an open file is rebuilt rather than reported: the
client reconnects to the same server, opens the same path again and repeats
the request that failed, for as long as `withRecoveryWindow` allows. Every
XRootD request carries its own offset, so repeating one writes the same bytes
to the same place — which is what makes this safe here and not in a protocol
with a cursor.

Configuration is immutable, with a `with…` for each field and a builder for
when several change together:

```java
Config config = Config.defaults()
        .withToken(System.getenv("BEARER_TOKEN"))
        .withTls(Config.Tls.REQUIRED)
        .withDataStreams(4)                        // TCP streams per root:// session
        .withRequestTimeout(Duration.ofSeconds(60));

Config tuned = Config.fromEnvironment().toBuilder()
        .appName("analysis")                       // what the site's monitoring records
        .recoveryWindow(Duration.ofMinutes(2))     // how long a lost session is worth
        .build();
```

When a transfer goes wrong at three in the morning, `XRD_LOGLEVEL=Debug` —
with `XRD_LOGFILE` and `XRD_LOGMASK` if the whole trace is too much — prints
what the client decided and why: which server it was redirected to, which
mechanism authenticated, which replica it gave up on, which session it
rebuilt.

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
$ jroot --progress --parallel 16 xcp root://a//store/f root://b//store/f /scratch/f
$ jroot cp --checksum crc32c root://door//store/f.root /scratch/f.root
$ jroot cp https://data.example.org/f.root.meta4 /scratch/f.root
$ jroot zip root://door//store/bundle.zip
$ jroot unzip root://door//store/bundle.zip data/histograms.root > histograms.root
$ jroot get 'root://door//store/bundle.zip?xrdcl.unzip=data/histograms.root' /scratch/
$ jroot --trace debug --appname analysis stat root://door.example.org//store/f
```

The `XRD_*` environment the reference client reads is read here too, so a
site's worker-node tuning applies unchanged: `XRD_REQUESTTIMEOUT`,
`XRD_CONNECTIONWINDOW`, `XRD_STREAMTIMEOUT`, `XRD_REDIRECTLIMIT`,
`XRD_SUBSTREAMSPERCHANNEL`, `XRD_TLSNOVERIFYCERT`, `XRD_STREAMERRORWINDOW`,
`XRD_APPNAME`, `XRD_INFO`, `XRD_CPCHUNKSIZE` and `XRD_CPPARALLELCHUNKS`, with
the trace following `XRD_LOGLEVEL`, `XRD_LOGFILE` and `XRD_LOGMASK`. Options
given on the command line win.

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

**Deep locate** — a federation is a tree of redirectors, so one `kXR_locate`
answers with the managers below rather than with replicas. `deepLocate`
follows it down to the data servers actually holding the file, visiting no
manager twice and treating one that will not answer as a gap rather than a
failure. It is what a copy asks before deciding where to read from, and what
`jroot locate -r` prints.

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

**Copying** — the transfer engine divides a file into chunks and pulls them
in parallel from as many replicas as it was given, opening one more connection
per chunk in flight and no more. A replica that will not open is dropped and
the next one takes its share; a chunk that fails is retried on a different
replica rather than the one that just refused it. Checksums are compared at
the end, and the algorithm is whichever both ends will compute — the server
is asked to compute its own where it can, so verification does not mean
reading the file back across the network. A mismatch fails the copy loudly,
since a copy that is not the file is worse than no copy. Where neither end
will produce a checksum the transfer is reported unverified rather than
failed, because plenty of storage carries no checksum at all.

Verification is a second pass and not a running sum, deliberately: parallel
chunks arrive out of order, and no streaming checksum can be fed out of
order. An HTTP destination is written by one `PUT` of the whole object, so
those copies land on local disk first and upload from there — the parallel
read still pays for itself.

A whole tree is copied several files at a time, since a run directory is
spent on round trips rather than on bandwidth, and a file that will not copy
is recorded and the walk goes on — one unreadable file should not undo a good
copy of the other five thousand, so the failures come back in the result
rather than as an exception halfway through.

A transfer that does not finish leaves nothing behind. A file that is part of
a file is the dangerous kind of wrong — plausible name, plausible size, not
the data — so a copy that fails, or fails to verify, takes its destination
away again, which is what `kXR_posc` asks a server to do and what `xrdcp`
does for itself where the server will not.

**Sessions that come back** — a data server restarts, a route drops, a
firewall times an idle connection out; none of that is news to the file the
job had open. The client reconnects to the same server, opens the same path
again — without the flags that created it, which would empty it — and repeats
the request that failed, until `XRD_STREAMERRORWINDOW` runs out. Threads that
noticed the same break recover once between them. What cannot be rebuilt is
not attempted: a checkpoint is state the lost server held, and a `kXR_clone`
names a handle another file was granted, so both fail rather than quietly
doing something else.

**Saying who you are, and writing down what happened** — every session's
`kXR_login` carries the CGI a site's monitoring reads: country, timezone,
application name, free text, hostname and release. Without it a client is
invisible in the reports an operator uses to find out which workload is
hammering a pool. The trace on the other side of that is `XRD_LOGLEVEL`,
`XRD_LOGFILE` and `XRD_LOGMASK`, with the reference client's five levels and
per-topic masking, off and free until somebody asks for it.

**Metalink** — RFC 5854 (`.meta4`) and the older metalink 3, parsed into the
replicas they name, sorted by the publisher's priority, with the strongest
hash they carry taken as the expected checksum.

**ZIP members over the wire** — an archive on a storage element is read
through its own index rather than downloaded: the end-of-directory record,
then the central directory, then the one member asked for, which is three
requests regardless of how big the archive is. ZIP64 is understood, stored
and deflated members alike, a range of a member is served by a range of the
archive where the member is stored uncompressed, and every member read whole
is checked against the CRC32 the directory recorded. `?xrdcl.unzip=member` on
a URL — the same tag the reference client uses — reads a member anywhere a
URL is accepted.

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
mvn test           # 419 tests
```

The tests are not mocks of JRoot's own classes. The XRootD tests run against a
real `ServerSocket` speaking real frames, and the HTTP tests against a real
`com.sun.net.httpserver` — so a wrong offset, a dropped header or a
mis-declared length fails the test instead of passing through a stub. The GSI
tests are the same: real certificates, a real Diffie-Hellman exchange and a
real PKCS#10, with the test playing the server's half, so the two ends have to
agree on a key rather than be told they did.

There is one thing all of that cannot catch: a client and a server written
from the same reading of the spec agree with each other whether or not the
reading is right. So `GsiInteropTest` puts the client in front of the official
`xrootd` — a throwaway CA, host certificate and X.509 proxy minted by
`xrdgsiproxy`, a server bound to `sec.protbind * only gsi`, all set up by
`src/test/resources/it/xrootd-gsi-server.sh` — and carries a file up and back
over `root://`, once with ordinary reads and writes and once with `kXR_writev`
and `kXR_readv`. What arrived is compared against the server's own copy on
disk, not only against what the client reads back. That test skips, and only
skips, when the official tools are not installed:

```
mvn test -Dtest=GsiInteropTest     # needs xrootd, xrdgsiproxy and openssl
src/test/resources/it/xrootd-gsi-server.sh start /tmp/xrd 21094   # by hand
src/test/resources/it/xrootd-gsi-server.sh stop  /tmp/xrd
```

## Licence

LGPL-3.0-or-later. See [COPYING.LESSER](COPYING.LESSER) and
[COPYING](COPYING).
