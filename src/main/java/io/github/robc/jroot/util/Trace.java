package io.github.robc.jroot.util;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * What the client did, for whoever has to explain what a job did last night.
 *
 * <p>A storage client fails in places its caller cannot see — a redirect
 * that went somewhere unexpected, a mechanism that was skipped for want of a
 * credential, a replica that answered slowly and then not at all. The
 * reference client answers that with {@code XRD_LOGLEVEL}, and an operator
 * debugging a site expects the same lever to work here: the level, the file
 * and the topic mask are read from the same three variables, and the output
 * carries the same five level names.
 *
 * <p>Off is the default and off is free — a disabled call formats nothing
 * and allocates only its own argument array. Nothing here throws: a log
 * file that cannot be opened falls back to standard error, because losing
 * the trace is a nuisance and losing the transfer is not.
 */
public final class Trace {

    /** The reference client's levels, in its own order: the ordinal is the
     *  number {@code XRD_LOGLEVEL} accepts in place of the name. */
    public enum Level {
        NONE, ERROR, WARNING, INFO, DEBUG, DUMP;

        /** {@code text} as a level, by name or by number, or {@code fallback}
         *  when it says nothing either way. */
        public static Level parse(String text, Level fallback) {
            if (text.isEmpty()) {
                return fallback;
            }
            for (Level candidate : values()) {
                if (candidate.name().equalsIgnoreCase(text)) {
                    return candidate;
                }
            }
            int number = Env.parse(text, 0, values().length - 1);
            return number == Env.UNSET ? fallback : values()[number];
        }
    }

    /** The topics the library itself traces under. A caller may use its own:
     *  the mask matches whatever string is passed. */
    public static final String CONNECTION = "Connection";
    public static final String XROOTD = "XRootD";
    public static final String AUTH = "Auth";
    public static final String HTTP = "Http";
    public static final String COPY = "Copy";

    private static final DateTimeFormatter CLOCK = DateTimeFormatter
            .ofPattern("HH:mm:ss.SSS").withLocale(Locale.ROOT);

    private static volatile Level level = Level.NONE;
    private static volatile Set<String> topics = Set.of();
    private static volatile PrintStream sink = System.err;

    static {
        fromEnvironment();
    }

    private Trace() {
    }

    /**
     * Read {@code XRD_LOGLEVEL}, {@code XRD_LOGFILE} and {@code XRD_LOGMASK}.
     * Called once when the class loads; call it again after changing the
     * environment, which only a test has any way of doing.
     */
    public static void fromEnvironment() {
        Level wanted = Level.parse(Env.text("XRD_LOGLEVEL"), Level.NONE);
        PrintStream where = System.err;
        String file = Env.text("XRD_LOGFILE");
        if (wanted != Level.NONE && !file.isEmpty()) {
            where = open(file);
        }
        configure(wanted, where, mask(Env.text("XRD_LOGMASK")));
    }

    /** Where a mask like {@code Connection,Copy} names the topics to keep;
     *  empty, {@code all} or {@code *} keeps every one. */
    private static Set<String> mask(String text) {
        Set<String> wanted = new LinkedHashSet<>();
        for (String part : text.split(",")) {
            String name = part.strip();
            if (name.equalsIgnoreCase("all") || name.equals("*")) {
                return Set.of();
            }
            if (!name.isEmpty()) {
                wanted.add(name.toLowerCase(Locale.ROOT));
            }
        }
        return Set.copyOf(wanted);
    }

    private static PrintStream open(String file) {
        try {
            return new PrintStream(new FileOutputStream(file, true), true,
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("jroot: cannot write the trace to " + file
                    + " (" + e.getMessage() + "); using standard error");
            return System.err;
        }
    }

    /** Set the level, the sink and the topic mask directly. An empty mask
     *  means every topic. */
    public static synchronized void configure(Level wanted, PrintStream where,
                                              Set<String> wantedTopics) {
        PrintStream previous = sink;
        level = wanted == null ? Level.NONE : wanted;
        topics = wantedTopics == null ? Set.of() : Set.copyOf(wantedTopics);
        sink = where == null ? System.err : where;
        if (previous != sink && previous != System.err && previous != System.out) {
            previous.close();
        }
    }

    public static Level level() {
        return level;
    }

    /** Whether a message on {@code topic} at {@code wanted} would be kept.
     *  Worth asking before building an argument that costs something. */
    public static boolean enabled(Level wanted, String topic) {
        return wanted.ordinal() <= level.ordinal()
                && (topics.isEmpty() || topics.contains(topic.toLowerCase(Locale.ROOT)));
    }

    public static void error(String topic, String format, Object... arguments) {
        log(Level.ERROR, topic, format, arguments);
    }

    public static void warn(String topic, String format, Object... arguments) {
        log(Level.WARNING, topic, format, arguments);
    }

    public static void info(String topic, String format, Object... arguments) {
        log(Level.INFO, topic, format, arguments);
    }

    public static void debug(String topic, String format, Object... arguments) {
        log(Level.DEBUG, topic, format, arguments);
    }

    /** Every frame, for the day a byte is in the wrong place. */
    public static void dump(String topic, String format, Object... arguments) {
        log(Level.DUMP, topic, format, arguments);
    }

    private static void log(Level at, String topic, String format, Object... arguments) {
        if (!enabled(at, topic)) {
            return;
        }
        String message;
        try {
            message = arguments.length == 0 ? format : String.format(format, arguments);
        } catch (RuntimeException e) {
            // A trace that cannot be formatted still says where it came from,
            // and must not be the thing that ends a transfer.
            message = format + " <unformattable: " + e + ">";
        }
        sink.println("[" + LocalTime.now().format(CLOCK) + "]["
                + name(at) + "][" + topic + "][" + Thread.currentThread().getName() + "] "
                + message);
    }

    private static String name(Level at) {
        String lower = at.name().toLowerCase(Locale.ROOT);
        return Character.toUpperCase(lower.charAt(0)) + lower.substring(1);
    }
}
