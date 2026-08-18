package io.github.robc.jroot.zip;

import java.io.Closeable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.transfer.Source;

/**
 * One member of a remote ZIP archive, read without fetching the archive.
 *
 * <p>HEP stores small files in bundles — a few thousand histograms in one
 * archive, because a storage element would rather hold one large file than a
 * thousand small ones — and then wants one of them back. Downloading the
 * bundle to get at a member of it defeats the arrangement, so the XRootD
 * client reads the archive's index over the wire and range-reads the member
 * out of the middle. That is what this does, and it works over any transport
 * {@link io.github.robc.jroot.JRoot} can open, because all it needs is the
 * ability to read a range.
 *
 * <p>Three round trips find a member: the end-of-central-directory record at
 * the tail, the central directory it points at, and the member's own local
 * header. After that a read is one range request. ZIP64 is handled, since an
 * archive worth storing remotely is frequently over 4 GiB.
 *
 * <p>The reference client spells the member in the URL, as
 * {@code ?xrdcl.unzip=member.root}; {@link #memberOf} reads that tag, so a
 * URL written for one client works with this one.
 */
public final class ZipArchive implements Closeable {

    /** What the URL tag naming a member inside an archive is called. */
    public static final String UNZIP_TAG = "xrdcl.unzip";

    private static final int EOCD_SIGNATURE = 0x06054b50;
    private static final int EOCD64_LOCATOR = 0x07064b50;
    private static final int EOCD64_SIGNATURE = 0x06064b50;
    private static final int CENTRAL_SIGNATURE = 0x02014b50;
    private static final int LOCAL_SIGNATURE = 0x04034b50;
    private static final int EOCD_LENGTH = 22;
    private static final int LOCAL_LENGTH = 30;

    /** The tail an end-of-directory record can hide in: 22 bytes plus a comment. */
    private static final int TAIL = EOCD_LENGTH + 0xFFFF;

    private static final int STORED = 0;
    private static final int DEFLATED = 8;

    /** One file in the archive, as the central directory describes it. */
    public record Member(String name, long size, long compressedSize, int method,
                         long crc32, long headerOffset) {

        public boolean isStored() {
            return method == STORED;
        }

        public boolean isDirectory() {
            return name.endsWith("/");
        }
    }

    private final Source source;
    private final String name;
    private final Map<String, Member> members;

    private ZipArchive(Source source, String name, Map<String, Member> members) {
        this.source = source;
        this.name = name;
        this.members = members;
    }

    /**
     * Read {@code source}'s index. The archive takes ownership: closing this
     * closes the source it was read from.
     */
    public static ZipArchive open(Source source, String name) {
        try {
            return new ZipArchive(source, name, index(source, name));
        } catch (RuntimeException e) {
            source.close();
            throw e;
        }
    }

    /** Every member, in the order the central directory lists them. */
    public List<Member> members() {
        return List.copyOf(members.values());
    }

    public Optional<Member> member(String memberName) {
        return Optional.ofNullable(members.get(memberName));
    }

    /**
     * A whole member, decompressed, with its CRC checked against what the
     * archive says it should be — which is the only thing that establishes
     * the range came back intact.
     */
    public byte[] read(String memberName) {
        Member member = members.get(memberName);
        if (member == null) {
            throw new XrdException(name + " holds no member called " + memberName
                    + "; it holds " + members.size() + " others");
        }
        byte[] raw = source.read(dataOffset(member), (int) checkedLength(member));
        byte[] out = member.isStored() ? raw : inflate(raw, member);
        CRC32 crc = new CRC32();
        crc.update(out);
        if (member.crc32() != 0 && crc.getValue() != member.crc32()) {
            throw new XrdException(memberName + " in " + name + " does not match its own"
                    + " CRC32; the archive or the range that came back is damaged");
        }
        return out;
    }

    /**
     * Part of a member. A stored member is a range of the archive and is read
     * as one; a deflated member has to be inflated from its start, since a
     * deflate stream cannot be entered in the middle, so the range is taken
     * after the fact.
     */
    public byte[] read(String memberName, long offset, int length) {
        Member member = members.get(memberName);
        if (member == null) {
            throw new XrdException(name + " holds no member called " + memberName);
        }
        if (offset < 0 || length < 0) {
            throw new XrdException("a read of " + memberName + " asked for " + length
                    + " bytes at " + offset);
        }
        if (member.isStored()) {
            long want = Math.min(length, Math.max(0, member.size() - offset));
            return source.read(dataOffset(member) + offset, (int) want);
        }
        byte[] whole = read(memberName);
        if (offset >= whole.length) {
            return new byte[0];
        }
        int end = (int) Math.min(whole.length, offset + (long) length);
        return java.util.Arrays.copyOfRange(whole, (int) offset, end);
    }

    /**
     * One member as a random-access source, so that a member can be copied,
     * checksummed or read in ranges anywhere a URL is accepted. Closing it
     * closes the archive, and the source the archive was opened over.
     *
     * <p>A stored member is served as ranges of the archive itself. A
     * deflated one is inflated once, on the first read, and served from
     * there: a deflate stream cannot be entered in the middle, so the
     * alternative is inflating the whole member again for every chunk.
     */
    public Source source(String memberName) {
        Member member = member(memberName).orElseThrow(() -> new XrdException(
                name + " holds no member called " + memberName));
        return new Source() {
            private byte[] whole;

            @Override public long size() {
                return member.size();
            }

            @Override public synchronized byte[] read(long offset, int length) {
                if (member.isStored()) {
                    return ZipArchive.this.read(memberName, offset, length);
                }
                if (whole == null) {
                    whole = ZipArchive.this.read(memberName);
                }
                if (offset < 0 || length < 0) {
                    throw new XrdException("a read of " + memberName + " asked for "
                            + length + " bytes at " + offset);
                }
                if (offset >= whole.length) {
                    return new byte[0];
                }
                int end = (int) Math.min(whole.length, offset + (long) length);
                return java.util.Arrays.copyOfRange(whole, (int) offset, end);
            }

            @Override public void close() {
                ZipArchive.this.close();
            }
        };
    }

    /** The member a URL names with {@code ?xrdcl.unzip=}, if it names one. */
    public static Optional<String> memberOf(String url) {
        if (url == null) {
            return Optional.empty();
        }
        int query = url.indexOf('?');
        if (query < 0) {
            return Optional.empty();
        }
        for (String pair : url.substring(query + 1).split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0 && pair.substring(0, equals).strip().equals(UNZIP_TAG)) {
                String member = pair.substring(equals + 1).strip();
                return member.isEmpty() ? Optional.empty() : Optional.of(member);
            }
        }
        return Optional.empty();
    }

    /** The same URL with the member tag taken off, which is the archive itself. */
    public static String archiveOf(String url) {
        int query = url.indexOf('?');
        if (query < 0) {
            return url;
        }
        StringBuilder kept = new StringBuilder();
        for (String pair : url.substring(query + 1).split("&")) {
            int equals = pair.indexOf('=');
            String key = equals > 0 ? pair.substring(0, equals).strip() : pair.strip();
            if (key.equals(UNZIP_TAG) || pair.isEmpty()) {
                continue;
            }
            kept.append(kept.length() == 0 ? "" : "&").append(pair);
        }
        return kept.length() == 0 ? url.substring(0, query)
                : url.substring(0, query + 1) + kept;
    }

    @Override
    public void close() {
        source.close();
    }

    // -----------------------------------------------------------------
    // Reading the index
    // -----------------------------------------------------------------

    private static Map<String, Member> index(Source source, String name) {
        long size = source.size();
        if (size < EOCD_LENGTH) {
            throw new XrdException(name + " is too short to be a ZIP archive");
        }
        int tail = (int) Math.min(size, TAIL);
        byte[] end = source.read(size - tail, tail);
        int at = lastSignature(end, EOCD_SIGNATURE);
        if (at < 0) {
            throw new XrdException(name + " has no ZIP end-of-directory record in its"
                    + " last " + tail + " bytes, so it is not a ZIP archive");
        }
        ByteBuffer eocd = little(end);
        long entries = eocd.getShort(at + 10) & 0xFFFFL;
        long directoryAt = eocd.getInt(at + 16) & 0xFFFFFFFFL;
        long directorySize = eocd.getInt(at + 12) & 0xFFFFFFFFL;
        if (directoryAt == 0xFFFFFFFFL || directorySize == 0xFFFFFFFFL || entries == 0xFFFFL) {
            long[] zip64 = zip64(source, end, at, size - tail, name);
            entries = zip64[0];
            directorySize = zip64[1];
            directoryAt = zip64[2];
        }
        if (directorySize > Integer.MAX_VALUE) {
            throw new XrdException(name + " has a " + directorySize
                    + "-byte central directory, which is more than this client will hold");
        }
        return directory(source.read(directoryAt, (int) directorySize), entries, name);
    }

    /**
     * The ZIP64 records, for an archive that outgrew the 32-bit fields. The
     * locator sits immediately before the ordinary record and points at the
     * real one, wherever it went.
     */
    private static long[] zip64(Source source, byte[] end, int at, long tailAt, String name) {
        int locator = at - 20;
        ByteBuffer buffer = little(end);
        if (locator < 0 || buffer.getInt(locator) != EOCD64_LOCATOR) {
            throw new XrdException(name + " says it is a ZIP64 archive but carries no"
                    + " ZIP64 locator before its end-of-directory record");
        }
        long recordAt = buffer.getLong(locator + 8);
        byte[] record;
        if (recordAt >= tailAt) {
            record = java.util.Arrays.copyOfRange(end, (int) (recordAt - tailAt), end.length);
        } else {
            record = source.read(recordAt, 56);
        }
        ByteBuffer zip64 = little(record);
        if (record.length < 56 || zip64.getInt(0) != EOCD64_SIGNATURE) {
            throw new XrdException(name + " has no ZIP64 end-of-directory record where its"
                    + " locator says it is");
        }
        return new long[] {zip64.getLong(32), zip64.getLong(40), zip64.getLong(48)};
    }

    private static Map<String, Member> directory(byte[] bytes, long entries, String name) {
        ByteBuffer buffer = little(bytes);
        Map<String, Member> found = new LinkedHashMap<>();
        int at = 0;
        while (at + 46 <= bytes.length && buffer.getInt(at) == CENTRAL_SIGNATURE) {
            int method = buffer.getShort(at + 10) & 0xFFFF;
            long crc = buffer.getInt(at + 16) & 0xFFFFFFFFL;
            long compressed = buffer.getInt(at + 20) & 0xFFFFFFFFL;
            long size = buffer.getInt(at + 24) & 0xFFFFFFFFL;
            int nameLength = buffer.getShort(at + 28) & 0xFFFF;
            int extraLength = buffer.getShort(at + 30) & 0xFFFF;
            int commentLength = buffer.getShort(at + 32) & 0xFFFF;
            long offset = buffer.getInt(at + 42) & 0xFFFFFFFFL;
            String member = new String(bytes, at + 46, nameLength, StandardCharsets.UTF_8);
            long[] wide = wide(bytes, at + 46 + nameLength, extraLength,
                    new long[] {size, compressed, offset});
            found.put(member, new Member(member, wide[0], wide[1], method, crc, wide[2]));
            at += 46 + nameLength + extraLength + commentLength;
        }
        if (found.isEmpty() && entries > 0) {
            throw new XrdException(name + " has a central directory this client cannot read");
        }
        return found;
    }

    /**
     * The ZIP64 extended-information field, which supplies whichever of the
     * size, compressed size and offset overflowed their 32-bit fields — and
     * only those, in that order, which is what makes it awkward to read.
     */
    private static long[] wide(byte[] bytes, int at, int length, long[] values) {
        ByteBuffer buffer = little(bytes);
        int end = at + length;
        while (at + 4 <= end && at + 4 <= bytes.length) {
            int id = buffer.getShort(at) & 0xFFFF;
            int size = buffer.getShort(at + 2) & 0xFFFF;
            if (id == 0x0001) {
                int field = at + 4;
                for (int i = 0; i < values.length; i++) {
                    if (values[i] == 0xFFFFFFFFL && field + 8 <= Math.min(end, bytes.length)) {
                        values[i] = buffer.getLong(field);
                        field += 8;
                    }
                }
                return values;
            }
            at += 4 + size;
        }
        return values;
    }

    /**
     * Where a member's bytes start. The central directory gives the offset of
     * the local header, whose name and extra fields are free to differ in
     * length from the ones in the directory, so it has to be read.
     */
    private long dataOffset(Member member) {
        byte[] header = source.read(member.headerOffset(), LOCAL_LENGTH);
        ByteBuffer buffer = little(header);
        if (header.length < LOCAL_LENGTH || buffer.getInt(0) != LOCAL_SIGNATURE) {
            throw new XrdException(member.name() + " in " + name + " has no local header"
                    + " where the central directory says it has one");
        }
        return member.headerOffset() + LOCAL_LENGTH
                + (buffer.getShort(26) & 0xFFFF) + (buffer.getShort(28) & 0xFFFF);
    }

    private long checkedLength(Member member) {
        if (member.compressedSize() > Integer.MAX_VALUE) {
            throw new XrdException(member.name() + " is " + member.compressedSize()
                    + " bytes compressed, which is more than this client will hold in memory");
        }
        return member.compressedSize();
    }

    private byte[] inflate(byte[] raw, Member member) {
        if (member.method() != DEFLATED) {
            throw new XrdException(member.name() + " in " + name + " is stored with"
                    + " compression method " + member.method()
                    + ", and this client reads only stored and deflated members");
        }
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(raw);
            byte[] out = new byte[(int) Math.max(member.size(), 0)];
            int at = 0;
            while (at < out.length && !inflater.finished()) {
                int written = inflater.inflate(out, at, out.length - at);
                if (written == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    break;
                }
                at += written;
            }
            if (at != out.length) {
                throw new XrdException(member.name() + " inflated to " + at + " bytes where"
                        + " the archive says it is " + out.length);
            }
            return out;
        } catch (DataFormatException e) {
            throw new XrdException(member.name() + " in " + name
                    + " is not a deflate stream: " + e.getMessage(), e);
        } finally {
            inflater.end();
        }
    }

    private static int lastSignature(byte[] bytes, int signature) {
        ByteBuffer buffer = little(bytes);
        for (int at = bytes.length - 4; at >= 0; at--) {
            if (buffer.getInt(at) == signature) {
                return at;
            }
        }
        return -1;
    }

    /** ZIP is little-endian throughout, which is the one place this library is. */
    private static ByteBuffer little(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public String toString() {
        return "ZipArchive[" + name + ", " + members.size() + " members]";
    }
}
