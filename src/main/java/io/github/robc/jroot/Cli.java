package io.github.robc.jroot;

import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.github.robc.jroot.wire.Types.ChecksumInfo;
import io.github.robc.jroot.wire.Types.DirEntry;
import io.github.robc.jroot.wire.Types.LocationInfo;
import io.github.robc.jroot.wire.Types.SpaceInfo;
import io.github.robc.jroot.wire.Types.StatInfo;
import io.github.robc.jroot.wire.XrdConst;

/**
 * The command line: enough of one to use the library from a shell and to
 * check a real endpoint without writing Java.
 *
 * <p>Every command takes URLs in any scheme the library speaks, so
 * {@code jroot cp root://host//data/file /tmp/file} and
 * {@code jroot cp /tmp/file davs://host/data/file} are the same command with
 * the transports swapped.
 */
public final class Cli {

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withLocale(Locale.ROOT);

    private final PrintStream out;
    private final PrintStream err;
    private boolean longListing;
    private boolean makePath;
    private boolean debug;

    Cli(PrintStream out, PrintStream err) {
        this.out = out;
        this.err = err;
    }

    public static void main(String[] args) {
        System.exit(new Cli(System.out, System.err).run(args));
    }

    // -----------------------------------------------------------------
    // Argument handling
    // -----------------------------------------------------------------

    int run(String[] args) {
        Config config = Config.defaults();
        List<String> operands = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("-") || arg.equals("-")) {
                operands.add(arg);
                continue;
            }
            String name = arg;
            String value = null;
            int equals = arg.indexOf('=');
            if (equals > 0) {
                name = arg.substring(0, equals);
                value = arg.substring(equals + 1);
            }
            try {
                switch (name) {
                    case "-h", "--help" -> {
                        usage(out);
                        return 0;
                    }
                    case "-V", "--version" -> {
                        out.println("jroot " + version());
                        return 0;
                    }
                    case "-l", "--long" -> longListing = true;
                    case "-p", "--parents" -> makePath = true;
                    case "-d", "--debug" -> debug = true;
                    case "--token" -> config = config.withToken(value != null ? value : args[++i]);
                    case "--proxy" -> config = config.withProxyPath(
                            Path.of(value != null ? value : args[++i]));
                    case "--ca" -> config = config.withCaPath(
                            Path.of(value != null ? value : args[++i]));
                    case "--user" -> config = config.withUsername(
                            value != null ? value : args[++i]);
                    case "--tls" -> config = config.withTls(
                            tlsMode(value != null ? value : args[++i]));
                    case "--no-verify" -> config = config.withVerifyPeer(false);
                    case "--delegate" -> config = config.withDelegateProxy(true);
                    case "--streams" -> config = config.withDataStreams(
                            Integer.parseInt(value != null ? value : args[++i]));
                    case "--timeout" -> config = config.withRequestTimeout(
                            Duration.ofSeconds(Long.parseLong(value != null ? value : args[++i])));
                    default -> {
                        err.println("jroot: unknown option " + name);
                        usage(err);
                        return 2;
                    }
                }
            } catch (ArrayIndexOutOfBoundsException e) {
                err.println("jroot: " + name + " needs a value");
                return 2;
            } catch (IllegalArgumentException e) {
                err.println("jroot: " + name + ": " + e.getMessage());
                return 2;
            }
        }
        if (operands.isEmpty()) {
            usage(err);
            return 2;
        }
        String command = operands.remove(0);
        try (JRoot jroot = JRoot.open(config)) {
            return dispatch(jroot, command, operands);
        } catch (XrdException e) {
            err.println("jroot: " + e.getMessage());
            if (debug) {
                e.printStackTrace(err);
            }
            return 1;
        } catch (RuntimeException e) {
            err.println("jroot: " + e);
            if (debug) {
                e.printStackTrace(err);
            }
            return 1;
        }
    }

    private static Config.Tls tlsMode(String value) {
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "auto" -> Config.Tls.AUTO;
            case "require", "required", "on" -> Config.Tls.REQUIRED;
            case "off", "none", "disabled" -> Config.Tls.DISABLED;
            default -> throw new IllegalArgumentException(
                    "expected auto, require or off, not " + value);
        };
    }

    // -----------------------------------------------------------------
    // Commands
    // -----------------------------------------------------------------

    private int dispatch(JRoot jroot, String command, List<String> args) {
        switch (command) {
            case "ls" -> {
                require(args, 1, "ls URL");
                list(jroot, args.get(0));
            }
            case "stat" -> {
                require(args, 1, "stat URL");
                print(jroot.stat(args.get(0)));
            }
            case "cat" -> {
                require(args, 1, "cat URL");
                jroot.stream(args.get(0), out);
            }
            case "get" -> {
                require(args, 1, "get URL [DEST]");
                String url = args.get(0);
                Path target = Path.of(args.size() > 1 ? args.get(1) : nameOf(url));
                jroot.copy(url, target.toUri().toString());
                out.println(target + ": " + size(target));
            }
            case "put" -> {
                require(args, 2, "put FILE URL");
                jroot.copy(Path.of(args.get(0)).toUri().toString(), args.get(1));
                out.println(args.get(1) + ": written");
            }
            case "cp" -> {
                require(args, 2, "cp SOURCE DEST");
                jroot.copy(args.get(0), args.get(1));
                out.println(args.get(1) + ": written");
            }
            case "tpc" -> {
                require(args, 2, "tpc SOURCE DEST");
                jroot.thirdPartyCopy(args.get(0), args.get(1));
                out.println(args.get(1) + ": transferred by the servers");
            }
            case "rm" -> {
                require(args, 1, "rm URL");
                args.forEach(jroot::rm);
            }
            case "mkdir" -> {
                require(args, 1, "mkdir URL");
                for (String url : args) {
                    jroot.mkdir(url, makePath);
                }
            }
            case "rmdir" -> {
                require(args, 1, "rmdir URL");
                args.forEach(jroot::rmdir);
            }
            case "mv" -> {
                require(args, 2, "mv SOURCE DEST");
                jroot.mv(args.get(0), args.get(1));
            }
            case "checksum" -> {
                require(args, 1, "checksum URL [ALGORITHM]");
                ChecksumInfo checksum = jroot.checksum(args.get(0),
                        args.size() > 1 ? args.get(1) : "adler32")
                        .orElseThrow(() -> new XrdException(
                                args.get(0) + ": the server holds no checksum"));
                out.println(checksum.algorithm() + " " + checksum.value());
            }
            case "ping" -> {
                require(args, 1, "ping URL");
                long start = System.nanoTime();
                jroot.ping(args.get(0));
                out.printf("%s: alive in %.1f ms%n", args.get(0),
                        (System.nanoTime() - start) / 1e6);
            }
            case "locate" -> {
                require(args, 1, "locate URL");
                for (LocationInfo location : jroot.xrootd().locate(args.get(0))) {
                    out.println(location.address() + "\t" + location.type()
                            + location.access());
                }
            }
            case "space" -> {
                require(args, 1, "space URL");
                SpaceInfo space = jroot.xrootd().space(args.get(0));
                out.printf("%s total=%d free=%d largest=%d used=%d quota=%d%n",
                        space.name(), space.total(), space.free(),
                        space.largestFree(), space.used(), space.quota());
            }
            case "query" -> {
                require(args, 2, "query URL CONFIG-ITEM");
                out.println(jroot.xrootd().config(args.get(0), args.get(1)));
            }
            case "prepare" -> {
                require(args, 1, "prepare URL...");
                out.println(jroot.xrootd().prepare(args, XrdConst.kXR_stage, 1));
            }
            case "help" -> usage(out);
            default -> {
                err.println("jroot: unknown command " + command);
                usage(err);
                return 2;
            }
        }
        return 0;
    }

    private void list(JRoot jroot, String url) {
        List<DirEntry> entries = jroot.list(url);
        for (DirEntry entry : entries) {
            if (!longListing) {
                out.println(entry.name());
                continue;
            }
            StatInfo stat = entry.stat().orElse(null);
            if (stat == null) {
                out.printf("%-11s %12s %19s %s%n", "?", "?", "?", entry.name());
                continue;
            }
            out.printf("%-11s %12d %19s %s%n", flags(stat), stat.size(),
                    timestamp(stat.mtime()), entry.name());
        }
    }

    private void print(StatInfo stat) {
        out.println("path   " + stat.path());
        out.println("size   " + stat.size());
        out.println("flags  " + flags(stat) + " (0x"
                + Integer.toHexString(stat.flags()) + ")");
        out.println("mtime  " + timestamp(stat.mtime()));
        if (!stat.id().isEmpty()) {
            out.println("id     " + stat.id());
        }
    }

    /** A one-glance rendering of the stat bitfield, in the order the protocol
     *  defines the bits. */
    private static String flags(StatInfo stat) {
        int flags = stat.flags();
        StringBuilder text = new StringBuilder();
        text.append(stat.isDirectory() ? 'd' : (flags & XrdConst.kXR_other) != 0 ? 'o' : '-');
        text.append(stat.isReadable() ? 'r' : '-');
        text.append(stat.isWritable() ? 'w' : '-');
        text.append((flags & XrdConst.kXR_xset) != 0 ? 'x' : '-');
        text.append(stat.isOffline() ? 'O' : '-');
        text.append((flags & XrdConst.kXR_poscpend) != 0 ? 'P' : '-');
        text.append((flags & XrdConst.kXR_bkpexist) != 0 ? 'B' : '-');
        return text.toString();
    }

    private static String timestamp(long epochSeconds) {
        if (epochSeconds <= 0) {
            return "-";
        }
        return TIMESTAMP.format(Instant.ofEpochSecond(epochSeconds)
                .atZone(ZoneId.systemDefault()));
    }

    private static String size(Path path) {
        try {
            return java.nio.file.Files.size(path) + " bytes";
        } catch (java.io.IOException e) {
            return "written";
        }
    }

    /** The last path element of a URL, for {@code get} with no destination. */
    private static String nameOf(String url) {
        String path = url;
        int query = path.indexOf('?');
        if (query >= 0) {
            path = path.substring(0, query);
        }
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        int slash = path.lastIndexOf('/');
        String name = slash < 0 ? path : path.substring(slash + 1);
        return name.isEmpty() ? "download" : name;
    }

    private static void require(List<String> args, int count, String form) {
        if (args.size() < count) {
            throw new IllegalArgumentException("usage: jroot " + form);
        }
    }

    static String version() {
        String version = Cli.class.getPackage().getImplementationVersion();
        return version != null ? version : "(development build)";
    }

    private static void usage(PrintStream to) {
        to.println("""
                jroot — an XRootD, XRootD-HTTP and WebDAV client

                usage: jroot [options] COMMAND [arguments]

                commands:
                  ls URL                 list a directory
                  stat URL               size, flags and modification time
                  cat URL                write a file to standard output
                  get URL [DEST]         download a file
                  put FILE URL           upload a file
                  cp SOURCE DEST         copy between any two URLs
                  tpc SOURCE DEST        server-to-server copy
                  rm URL...              remove files
                  mkdir URL...           create directories
                  rmdir URL...           remove directories
                  mv SOURCE DEST         rename within one server
                  checksum URL [ALG]     the checksum the server holds
                  ping URL               round-trip time to a server
                  locate URL             which servers hold a file  (root:// only)
                  space URL              space token usage           (root:// only)
                  query URL ITEM         a configuration item        (root:// only)
                  prepare URL...         stage files from tape       (root:// only)

                urls:
                  root://host[:port]//path        the binary protocol
                  roots://host[:port]//path       the binary protocol, TLS throughout
                  https://host/path               XRootD-HTTP
                  davs://host/path                WebDAV over TLS
                  /path or file:///path           the local filesystem

                options:
                  -l, --long             a long listing
                  -p, --parents          create missing parent directories
                  --token VALUE          a bearer token (else the WLCG discovery order)
                  --proxy PATH           an X.509 proxy (else $X509_USER_PROXY)
                  --ca PATH              the CA directory (else $X509_CERT_DIR)
                  --user NAME            the login name to present
                  --tls auto|require|off when to turn on TLS
                  --no-verify            do not verify the server certificate
                  --delegate             sign a proxy for a server that asks
                  --timeout SECONDS      how long one request may take
                  --streams N            TCP streams per root:// session (default 1)
                  -d, --debug            print stack traces
                  -V, --version          print the version
                  -h, --help             this text
                """);
    }
}
