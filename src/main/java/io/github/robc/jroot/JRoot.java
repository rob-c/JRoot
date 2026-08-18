package io.github.robc.jroot;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.github.robc.jroot.client.XrdClient;
import io.github.robc.jroot.client.XrdFile;
import io.github.robc.jroot.client.XrdUrl;
import io.github.robc.jroot.http.HttpStorage;
import io.github.robc.jroot.http.WebDav;
import io.github.robc.jroot.wire.Types.ChecksumInfo;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.FattrItem;
import io.github.robc.jroot.wire.Types.ReadVSegment;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * One handle onto storage, whichever protocol reaches it.
 *
 * <p>A URL decides the transport: {@code root://} and {@code xroot://} (plus
 * their TLS spellings) go over the binary protocol, {@code http(s)://} and
 * {@code dav(s)://} over HTTP and WebDAV, and a bare path or {@code file://}
 * is the local filesystem — present so that a copy has somewhere to land
 * without the caller writing the loop.
 *
 * <p>The operations here are the ones every transport can do. Anything
 * protocol-specific — an open file handle, a vector read, {@code kXR_prepare},
 * a WebDAV property — stays on {@link #xrootd()} and {@link #webdav()}, which
 * are the same underlying clients this class dispatches to.
 *
 * <p>Instances are thread-safe and pool their connections; one per process is
 * the intended shape.
 */
public final class JRoot implements Closeable {

    /** Big enough that a wide-area round trip is amortised, small enough that
     *  a copy of any size still runs in a modest heap. */
    private static final int COPY_CHUNK = 8 << 20;

    private final Config config;
    private volatile XrdClient xrootd;
    private volatile WebDav webdav;

    public JRoot() {
        this(Config.defaults());
    }

    public JRoot(Config config) {
        this.config = config;
    }

    public static JRoot open() {
        return new JRoot();
    }

    public static JRoot open(Config config) {
        return new JRoot(config);
    }

    public Config config() {
        return config;
    }

    /** The binary-protocol client, created on first use. */
    public XrdClient xrootd() {
        XrdClient client = xrootd;
        if (client == null) {
            synchronized (this) {
                client = xrootd;
                if (client == null) {
                    client = new XrdClient(config);
                    xrootd = client;
                }
            }
        }
        return client;
    }

    /** The WebDAV client, which is also the plain-HTTP one. */
    public WebDav webdav() {
        WebDav client = webdav;
        if (client == null) {
            synchronized (this) {
                client = webdav;
                if (client == null) {
                    client = new WebDav(config);
                    webdav = client;
                }
            }
        }
        return client;
    }

    /** The HTTP client, for callers that want {@code GET}/{@code PUT} without
     *  the WebDAV verbs. */
    public HttpStorage http() {
        return webdav();
    }

    // -----------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------

    /** Which transport a URL names. */
    public enum Transport { XROOTD, HTTP, LOCAL }

    public static Transport transportOf(String url) {
        String scheme = schemeOf(url);
        if (scheme == null || scheme.equals("file")) {
            return Transport.LOCAL;
        }
        if (XrdUrl.isXrootd(scheme)) {
            return Transport.XROOTD;
        }
        if (HttpStorage.handles(scheme)) {
            return Transport.HTTP;
        }
        throw new XrdException("no transport for " + scheme + "://");
    }

    /** The scheme of a URL, or null for a bare path. A Windows-style drive
     *  letter is not a scheme, but a one-letter scheme does not exist either,
     *  so anything shorter than two characters is a path. */
    private static String schemeOf(String url) {
        int colon = url.indexOf(':');
        if (colon < 2 || url.indexOf('/') < colon) {
            return null;
        }
        String scheme = url.substring(0, colon);
        for (int i = 0; i < scheme.length(); i++) {
            char c = scheme.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '+' && c != '-' && c != '.') {
                return null;
            }
        }
        return scheme.toLowerCase();
    }

    static Path localPath(String url) {
        if (schemeOf(url) == null) {
            return Path.of(url);
        }
        URI uri = URI.create(url);
        return uri.getAuthority() == null || uri.getAuthority().isEmpty()
                ? Path.of(uri.getPath())
                : Path.of(uri.getAuthority() + uri.getPath());   // file://relative/path
    }

    // -----------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------

    public StatInfo stat(String url) {
        return switch (transportOf(url)) {
            case XROOTD -> xrootd().stat(url);
            case HTTP -> webdav().stat(url);
            case LOCAL -> localStat(localPath(url));
        };
    }

    public boolean exists(String url) {
        return switch (transportOf(url)) {
            case XROOTD -> xrootd().exists(url);
            case HTTP -> webdav().exists(url);
            case LOCAL -> Files.exists(localPath(url));
        };
    }

    public Optional<StatInfo> statIfPresent(String url) {
        try {
            return Optional.of(stat(url));
        } catch (XrdServerException e) {
            if (e.isNotFound()) {
                return Optional.empty();
            }
            throw e;
        }
    }

    public List<DirEntry> list(String url) {
        return switch (transportOf(url)) {
            case XROOTD -> xrootd().list(url);
            case HTTP -> webdav().list(url);
            case LOCAL -> localList(localPath(url));
        };
    }

    /**
     * The checksum the server holds, if it holds one. Over the binary
     * protocol that is {@code kXR_query} with {@code kXR_Qcksum}; over HTTP
     * it is a {@code Want-Digest} negotiation, which needs an algorithm to
     * ask for — {@code adler32} being what WLCG storage carries.
     */
    public Optional<ChecksumInfo> checksum(String url) {
        return checksum(url, "adler32");
    }

    public Optional<ChecksumInfo> checksum(String url, String algorithm) {
        return switch (transportOf(url)) {
            case XROOTD -> Optional.of(xrootd().checksum(url));
            case HTTP -> webdav().checksum(url, algorithm).map(digest -> {
                int equals = digest.indexOf('=');
                return equals < 0
                        ? new ChecksumInfo(algorithm, digest.trim())
                        : new ChecksumInfo(digest.substring(0, equals).trim(),
                                digest.substring(equals + 1).trim());
            });
            case LOCAL -> Optional.empty();
        };
    }

    /** Reachability: a {@code kXR_ping}, or a {@code HEAD} of the URL. */
    public void ping(String url) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().ping(url);
            case HTTP -> webdav().stat(url);
            case LOCAL -> localStat(localPath(url));
        }
    }

    // -----------------------------------------------------------------
    // Data
    // -----------------------------------------------------------------

    public byte[] read(String url) {
        return switch (transportOf(url)) {
            case XROOTD -> xrootd().read(url);
            case HTTP -> webdav().read(url);
            case LOCAL -> localRead(localPath(url));
        };
    }

    /** A range: the point of a storage client, and the one operation every
     *  transport does differently. */
    public byte[] read(String url, long offset, int length) {
        return switch (transportOf(url)) {
            case XROOTD -> {
                try (XrdFile file = xrootd().open(url)) {
                    yield file.read(offset, length);
                }
            }
            case HTTP -> webdav().read(url, offset, length);
            case LOCAL -> localRead(localPath(url), offset, length);
        };
    }

    /**
     * Several ranges of one object at once: {@code kXR_readv} over the binary
     * protocol, a multi-range {@code GET} over HTTP, positional reads
     * locally. Each range is {@code {offset, length}}.
     */
    public List<ReadVSegment> readV(String url, List<long[]> ranges) {
        return switch (transportOf(url)) {
            case XROOTD -> {
                try (XrdFile file = xrootd().open(url)) {
                    yield file.readV(ranges);
                }
            }
            case HTTP -> webdav().readV(url, ranges);
            case LOCAL -> {
                Path path = localPath(url);
                List<ReadVSegment> out = new ArrayList<>();
                for (long[] range : ranges) {
                    out.add(new ReadVSegment(new byte[0], range[0],
                            localRead(path, range[0], (int) range[1])));
                }
                yield out;
            }
        };
    }

    public void write(String url, byte[] data) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().write(url, data);
            case HTTP -> webdav().write(url, data);
            case LOCAL -> localWrite(localPath(url), data);
        }
    }

    /**
     * Ask the two servers to move the data between themselves, without it
     * passing through this process.
     *
     * <p>Both ends must speak the same protocol, because the two arrangements
     * share nothing: HTTP uses a {@code COPY} with a delegated bearer token,
     * the binary protocol a rendezvous key carried on two {@code kXR_open}s.
     * A copy between the two is an ordinary {@link #copy}, which is what a
     * caller who does not mind the bytes passing through should ask for.
     */
    public void thirdPartyCopy(String source, String target) {
        Transport transport = transportOf(source);
        if (transport != transportOf(target) || transport == Transport.LOCAL) {
            throw new XrdException("a third-party copy needs two servers of the same"
                    + " protocol: " + source + " to " + target);
        }
        switch (transport) {
            case XROOTD -> xrootd().thirdPartyCopy(source, target);
            case HTTP -> webdav().thirdPartyCopy(source, target);
            case LOCAL -> throw new IllegalStateException();
        }
    }

    /**
     * Stream an object to {@code out} in bounded chunks — what a caller wants
     * when the destination is a pipe rather than a file, and the reason
     * {@code cat} of a large file does not need a large heap.
     */
    public long stream(String url, java.io.OutputStream out) {
        try (Source in = source(url)) {
            long size = in.size();
            long offset = 0;
            while (offset < size) {
                byte[] chunk = in.read(offset, (int) Math.min(COPY_CHUNK, size - offset));
                if (chunk.length == 0) {
                    break;
                }
                out.write(chunk);
                offset += chunk.length;
            }
            out.flush();
            return offset;
        } catch (IOException e) {
            throw new XrdException("cannot stream " + url + ": " + e.getMessage(), e);
        }
    }

    /** Download to a local file. */
    public void readTo(String url, Path target) {
        copy(url, target.toUri().toString());
    }

    /** Upload a local file. */
    public void writeFrom(Path source, String url) {
        copy(source.toUri().toString(), url);
    }

    /**
     * Copy between any two URLs, in {@value #COPY_CHUNK}-byte chunks so that
     * size is bounded by the chunk and not by the file.
     *
     * <p>An HTTP destination is the exception: {@code PUT} is one request for
     * the whole object, so a copy that ends there streams a local source
     * straight through it, and stages any other source through a temporary
     * file first. Nothing is buffered whole in memory either way.
     */
    public void copy(String source, String target) {
        if (transportOf(target) == Transport.HTTP) {
            if (transportOf(source) == Transport.LOCAL) {
                webdav().write(target, localPath(source));
                return;
            }
            Path staged = null;
            try {
                staged = Files.createTempFile("jroot-", ".part");
                copy(source, staged.toUri().toString());
                webdav().write(target, staged);
            } catch (IOException e) {
                throw new XrdException("cannot stage a copy of " + source + ": "
                        + e.getMessage(), e);
            } finally {
                deleteQuietly(staged);
            }
            return;
        }
        try (Source in = source(source); Sink out = sink(target)) {
            long size = in.size();
            long offset = 0;
            while (offset < size || size < 0) {
                int want = size < 0 ? COPY_CHUNK : (int) Math.min(COPY_CHUNK, size - offset);
                byte[] chunk = in.read(offset, want);
                if (chunk.length == 0) {
                    break;                       // the source ended early; take what we got
                }
                out.write(offset, chunk);
                offset += chunk.length;
            }
        }
    }

    /**
     * Copy a whole tree. A file is copied as {@link #copy(String, String)}
     * would; a directory is created at the far end and its children copied
     * into it, so the destination ends up with the source's contents rather
     * than with the source inside it — the {@code cp -r src/. dst} sense,
     * which is the only one that composes when the recursion goes a level
     * deeper.
     */
    public void copyTree(String source, String target) {
        if (!stat(source).isDirectory()) {
            copy(source, target);
            return;
        }
        mkdir(target, true);
        for (DirEntry entry : list(source)) {
            String from = child(source, entry.name());
            String to = child(target, entry.name());
            if (entry.isDirectory()) {
                copyTree(from, to);
            } else {
                copy(from, to);
            }
        }
    }

    // -----------------------------------------------------------------
    // Namespace
    // -----------------------------------------------------------------

    public void mkdir(String url) {
        mkdir(url, false);
    }

    public void mkdir(String url, boolean makePath) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().mkdir(url, XrdConst.DEFAULT_DIR_MODE, makePath);
            case HTTP -> webdav().mkdir(url, makePath);
            case LOCAL -> {
                Path path = localPath(url);
                try {
                    if (makePath) {
                        Files.createDirectories(path);
                    } else {
                        Files.createDirectory(path);
                    }
                } catch (java.nio.file.FileAlreadyExistsException e) {
                    throw new XrdServerException(XrdConst.kXR_ItExists, path + " exists");
                } catch (IOException e) {
                    throw localFailure("create", path, e);
                }
            }
        }
    }

    public void rm(String url) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().rm(url);
            case HTTP -> webdav().delete(url);
            case LOCAL -> localDelete(localPath(url), false);
        }
    }

    public void rmdir(String url) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().rmdir(url);
            case HTTP -> webdav().rmdir(url);
            case LOCAL -> localDelete(localPath(url), true);
        }
    }

    /**
     * Rename. Both ends must be the same server: a rename is a namespace
     * operation, and moving data between servers is {@link #copy} followed by
     * {@link #rm}, which the caller should decide to do rather than have it
     * happen silently.
     */
    public void mv(String source, String target) {
        Transport transport = transportOf(source);
        if (transport != transportOf(target)) {
            throw new XrdException("cannot rename across transports: "
                    + source + " to " + target + "; copy then remove instead");
        }
        switch (transport) {
            case XROOTD -> xrootd().mv(source, target);
            case HTTP -> webdav().move(source, target);
            case LOCAL -> {
                try {
                    Files.move(localPath(source), localPath(target),
                            StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                    throw localFailure("rename", localPath(source), e);
                }
            }
        }
    }

    /**
     * Remove a directory and everything under it.
     *
     * <p>Only WebDAV has this as one request — {@code DELETE} of a collection
     * is recursive by definition — so elsewhere the tree is walked and
     * removed depth first, which is also the only order a server will accept:
     * a directory cannot go until it is empty.
     */
    public void rmTree(String url) {
        if (!statIfPresent(url).map(StatInfo::isDirectory).orElse(false)) {
            rm(url);
            return;
        }
        switch (transportOf(url)) {
            case HTTP -> webdav().rmdir(url);
            case LOCAL -> localDelete(localPath(url), true);
            case XROOTD -> {
                for (DirEntry entry : list(url)) {
                    rmTree(child(url, entry.name()));
                }
                rmdir(url);
            }
        }
    }

    // -----------------------------------------------------------------
    // Attributes
    // -----------------------------------------------------------------

    /**
     * Change the permission bits. A namespace operation, so it exists only
     * where there is a namespace to change: HTTP has no notion of one, and
     * says so rather than pretending the call succeeded.
     */
    public void chmod(String url, int mode) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().chmod(url, mode);
            case LOCAL -> {
                Path path = localPath(url);
                try {
                    Files.setPosixFilePermissions(path, modeToPermissions(mode));
                } catch (IOException e) {
                    throw localFailure("chmod", path, e);
                } catch (UnsupportedOperationException e) {
                    throw new XrdException(path + ": this filesystem has no POSIX modes");
                }
            }
            case HTTP -> throw new XrdException(
                    "HTTP has no permission bits: " + url);
        }
    }

    /** Cut a file to {@code size}, extending it with zeroes if it was shorter. */
    public void truncate(String url, long size) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().truncate(url, size);
            case LOCAL -> {
                Path path = localPath(url);
                try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
                    if (size <= channel.size()) {
                        channel.truncate(size);
                    } else {
                        channel.write(java.nio.ByteBuffer.allocate(1), size - 1);
                    }
                } catch (IOException e) {
                    throw localFailure("truncate", path, e);
                }
            }
            case HTTP -> throw new XrdException(
                    "HTTP can replace an object but not truncate one: " + url);
        }
    }

    /** Every extended attribute and its value, by name. */
    public Map<String, byte[]> attributes(String url) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        switch (transportOf(url)) {
            case XROOTD -> {
                for (FattrItem item : xrootd().listAttributes(url, true).items()) {
                    out.put(item.name(), item.value());
                }
            }
            case LOCAL -> {
                UserDefinedFileAttributeView view = localAttributes(localPath(url));
                try {
                    for (String name : view.list()) {
                        java.nio.ByteBuffer buffer =
                                java.nio.ByteBuffer.allocate(view.size(name));
                        view.read(name, buffer);
                        out.put(name, buffer.array());
                    }
                } catch (IOException e) {
                    throw localFailure("read the attributes of", localPath(url), e);
                }
            }
            case HTTP -> throw unsupportedAttributes(url);
        }
        return out;
    }

    /** One extended attribute, or empty when the file carries no such name. */
    public Optional<byte[]> attribute(String url, String name) {
        return switch (transportOf(url)) {
            case XROOTD -> xrootd().getAttribute(url, name).items().stream()
                    .filter(item -> item.code() == 0 && item.value() != null)
                    .map(FattrItem::value)
                    .findFirst();
            case LOCAL -> Optional.ofNullable(attributes(url).get(name));
            case HTTP -> throw unsupportedAttributes(url);
        };
    }

    public void setAttribute(String url, String name, byte[] value) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().setAttribute(url, name, value);
            case LOCAL -> {
                try {
                    localAttributes(localPath(url))
                            .write(name, java.nio.ByteBuffer.wrap(value));
                } catch (IOException e) {
                    throw localFailure("set an attribute on", localPath(url), e);
                }
            }
            case HTTP -> throw unsupportedAttributes(url);
        }
    }

    public void deleteAttribute(String url, String name) {
        switch (transportOf(url)) {
            case XROOTD -> xrootd().deleteAttribute(url, name);
            case LOCAL -> {
                try {
                    localAttributes(localPath(url)).delete(name);
                } catch (IOException e) {
                    throw localFailure("remove an attribute from", localPath(url), e);
                }
            }
            case HTTP -> throw unsupportedAttributes(url);
        }
    }

    private static XrdException unsupportedAttributes(String url) {
        return new XrdException("no transport carries extended attributes over HTTP: " + url);
    }

    private static UserDefinedFileAttributeView localAttributes(Path path) {
        UserDefinedFileAttributeView view =
                Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
        if (view == null) {
            throw new XrdException(path + ": this filesystem has no extended attributes");
        }
        if (!Files.exists(path)) {
            throw new XrdServerException(XrdConst.kXR_NotFound, path + " does not exist");
        }
        return view;
    }

    private static Set<PosixFilePermission> modeToPermissions(int mode) {
        Set<PosixFilePermission> permissions = EnumSet.noneOf(PosixFilePermission.class);
        PosixFilePermission[] bits = {
            PosixFilePermission.OTHERS_EXECUTE, PosixFilePermission.OTHERS_WRITE,
            PosixFilePermission.OTHERS_READ, PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_READ,
            PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_READ,
        };
        for (int i = 0; i < bits.length; i++) {
            if ((mode & (1 << i)) != 0) {
                permissions.add(bits[i]);
            }
        }
        return permissions;
    }

    /**
     * A child of {@code url}, with whatever opaque data the parent carried
     * kept where it belongs — after the path, not inside it.
     */
    static String child(String url, String name) {
        int query = url.indexOf('?');
        String path = query < 0 ? url : url.substring(0, query);
        String cgi = query < 0 ? "" : url.substring(query);
        return (path.endsWith("/") ? path + name : path + "/" + name) + cgi;
    }

    // -----------------------------------------------------------------
    // Copy plumbing
    // -----------------------------------------------------------------

    /** A readable end of a copy: a size and random access to it. */
    private interface Source extends Closeable {
        long size();

        byte[] read(long offset, int length);

        @Override
        void close();
    }

    /** A writable end of a copy: sequential, but told its offsets. */
    private interface Sink extends Closeable {
        void write(long offset, byte[] data);

        @Override
        void close();
    }

    /**
     * How much of a copy chunk one stream carries. With a single stream that
     * is the whole chunk — splitting it would only add round trips — and with
     * several it is a share large enough to still amortise one, so that a
     * chunk keeps every stream busy at the same time.
     */
    private static int streamChunk(XrdFile file) {
        int streams = file.streams().length;
        return streams <= 1 ? COPY_CHUNK : Math.max(COPY_CHUNK / streams, 1 << 20);
    }

    private Source source(String url) {
        return switch (transportOf(url)) {
            case XROOTD -> {
                XrdFile file = xrootd().open(url);
                yield new Source() {
                    private final long size = file.size();
                    private final int chunk = streamChunk(file);

                    @Override public long size() {
                        return size;
                    }

                    @Override public byte[] read(long offset, int length) {
                        return file.readAcross(offset, length, chunk);
                    }

                    @Override public void close() {
                        file.close();
                    }
                };
            }
            case HTTP -> new Source() {
                private final long size = webdav().stat(url).size();

                @Override public long size() {
                    return size;
                }

                @Override public byte[] read(long offset, int length) {
                    return webdav().read(url, offset, length);
                }

                @Override public void close() {
                    // stateless: each range is its own request
                }
            };
            case LOCAL -> localSource(localPath(url));
        };
    }

    private Sink sink(String url) {
        return switch (transportOf(url)) {
            case XROOTD -> {
                XrdFile file = xrootd().create(url, XrdConst.DEFAULT_FILE_MODE);
                yield new Sink() {
                    private final int chunk = streamChunk(file);

                    @Override public void write(long offset, byte[] data) {
                        file.writeAcross(offset, data, chunk);
                    }

                    @Override public void close() {
                        file.close();
                    }
                };
            }
            // Reached only for a local source, which copy() handles by
            // streaming the file straight through PUT.
            case HTTP -> throw new XrdException(
                    "an HTTP destination is written whole, not in chunks");
            case LOCAL -> localSink(localPath(url));
        };
    }

    // -----------------------------------------------------------------
    // Local filesystem
    // -----------------------------------------------------------------

    /**
     * A filesystem failure in the protocol's own vocabulary, so that a caller
     * handling {@code kXR_NotFound} from a server handles it from the local
     * disk too. Anything without an equivalent stays an {@link XrdException}.
     */
    private static XrdException localFailure(String what, Path path, IOException e) {
        if (e instanceof java.nio.file.NoSuchFileException) {
            return new XrdServerException(XrdConst.kXR_NotFound, path + " does not exist");
        }
        if (e instanceof java.nio.file.AccessDeniedException) {
            return new XrdServerException(XrdConst.kXR_NotAuthorized,
                    "not permitted to " + what + " " + path);
        }
        return new XrdException("cannot " + what + " " + path + ": " + e.getMessage(), e);
    }

    private static StatInfo localStat(Path path) {
        try {
            var attributes = Files.readAttributes(path,
                    java.nio.file.attribute.BasicFileAttributes.class);
            int flags = (attributes.isDirectory() ? XrdConst.kXR_isDir : 0)
                    | (Files.isReadable(path) ? XrdConst.kXR_readable : 0)
                    | (Files.isWritable(path) ? XrdConst.kXR_writable : 0)
                    | (attributes.isOther() || attributes.isSymbolicLink()
                            ? XrdConst.kXR_other : 0);
            return new StatInfo("", attributes.size(), flags,
                    attributes.lastModifiedTime().to(java.util.concurrent.TimeUnit.SECONDS),
                    path.toString());
        } catch (IOException e) {
            throw localFailure("stat", path, e);
        }
    }

    private static List<DirEntry> localList(Path path) {
        try (var stream = Files.list(path)) {
            List<DirEntry> out = new ArrayList<>();
            stream.sorted(Comparator.comparing(Path::getFileName))
                    .forEach(child -> out.add(new DirEntry(
                            child.getFileName().toString(), path.toString(),
                            Optional.of(localStat(child)))));
            return out;
        } catch (java.nio.file.NotDirectoryException e) {
            throw new XrdServerException(XrdConst.kXR_NotFile, path + " is not a directory");
        } catch (IOException e) {
            throw localFailure("list", path, e);
        }
    }

    private static byte[] localRead(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw localFailure("read", path, e);
        }
    }

    private static byte[] localRead(Path path, long offset, int length) {
        try (var channel = java.nio.channels.FileChannel.open(path,
                StandardOpenOption.READ)) {
            java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(length);
            long at = offset;
            while (buffer.hasRemaining()) {
                int read = channel.read(buffer, at);
                if (read < 0) {
                    break;
                }
                at += read;
            }
            byte[] out = new byte[buffer.position()];
            buffer.flip();
            buffer.get(out);
            return out;
        } catch (IOException e) {
            throw localFailure("read", path, e);
        }
    }

    private static void localWrite(Path path, byte[] data) {
        try {
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(path, data);
        } catch (IOException e) {
            throw localFailure("write", path, e);
        }
    }

    private static void localDelete(Path path, boolean directory) {
        try {
            if (directory && Files.isDirectory(path)) {
                try (var stream = Files.walk(path)) {
                    List<Path> paths = stream.sorted(Comparator.reverseOrder()).toList();
                    for (Path child : paths) {
                        Files.delete(child);
                    }
                }
                return;
            }
            Files.delete(path);
        } catch (IOException e) {
            throw localFailure("remove", path, e);
        }
    }

    private static Source localSource(Path path) {
        java.nio.channels.FileChannel channel;
        long size;
        try {
            channel = java.nio.channels.FileChannel.open(path, StandardOpenOption.READ);
            size = channel.size();
        } catch (IOException e) {
            throw localFailure("read", path, e);
        }
        return new Source() {
            @Override public long size() {
                return size;
            }

            @Override public byte[] read(long offset, int length) {
                try {
                    java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(length);
                    long at = offset;
                    while (buffer.hasRemaining()) {
                        int read = channel.read(buffer, at);
                        if (read < 0) {
                            break;
                        }
                        at += read;
                    }
                    byte[] out = new byte[buffer.position()];
                    buffer.flip();
                    buffer.get(out);
                    return out;
                } catch (IOException e) {
                    throw localFailure("read", path, e);
                }
            }

            @Override public void close() {
                closeQuietly(channel);
            }
        };
    }

    private static Sink localSink(Path path) {
        java.nio.channels.FileChannel channel;
        try {
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            channel = java.nio.channels.FileChannel.open(path, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            throw localFailure("write", path, e);
        }
        return new Sink() {
            @Override public void write(long offset, byte[] data) {
                try {
                    java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(data);
                    long at = offset;
                    while (buffer.hasRemaining()) {
                        at += channel.write(buffer, at);
                    }
                } catch (IOException e) {
                    throw localFailure("write", path, e);
                }
            }

            @Override public void close() {
                closeQuietly(channel);
            }
        };
    }

    /** Copy a modification time onto a local file, best effort. */
    static void touch(Path path, long epochSeconds) {
        if (epochSeconds <= 0) {
            return;
        }
        try {
            Files.setLastModifiedTime(path, FileTime.fromMillis(epochSeconds * 1000L));
        } catch (IOException e) {
            // the data is what matters; a timestamp that would not stick is not an error
        }
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException e) {
            throw new XrdException("cannot close: " + e.getMessage(), e);
        }
    }

    private static void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            // a leftover in the temp directory is not worth failing a finished copy
        }
    }

    @Override
    public void close() {
        XrdClient client = xrootd;
        if (client != null) {
            client.close();
        }
        WebDav dav = webdav;
        if (dav != null) {
            dav.close();
        }
    }

    @Override
    public String toString() {
        return "JRoot[" + config + "]";
    }
}
