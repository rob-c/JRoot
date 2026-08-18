package io.github.robc.jroot.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The trace: what it keeps, what it drops, and that nothing it is asked to
 * write can be the thing that fails.
 */
class TraceTest {

    private final ByteArrayOutputStream written = new ByteArrayOutputStream();

    private String traced() {
        return written.toString(StandardCharsets.UTF_8);
    }

    private void at(Trace.Level level, Set<String> topics) {
        Trace.configure(level, new PrintStream(written, true, StandardCharsets.UTF_8), topics);
    }

    @AfterEach
    void restore() {
        Trace.fromEnvironment();
    }

    @Test
    void writesNothingWhenNobodyAskedForATrace() {
        at(Trace.Level.NONE, Set.of());
        Trace.error(Trace.XROOTD, "a server said no");
        assertEquals("", traced());
        assertFalse(Trace.enabled(Trace.Level.ERROR, Trace.XROOTD));
    }

    @Test
    void keepsWhatIsAtOrAboveTheLevelAndDropsTheRest() {
        at(Trace.Level.INFO, Set.of());
        Trace.error(Trace.XROOTD, "an error");
        Trace.warn(Trace.XROOTD, "a warning");
        Trace.info(Trace.XROOTD, "something worth saying");
        Trace.debug(Trace.XROOTD, "a detail");
        Trace.dump(Trace.XROOTD, "a frame");
        String output = traced();
        assertTrue(output.contains("an error"), output);
        assertTrue(output.contains("a warning"), output);
        assertTrue(output.contains("something worth saying"), output);
        assertFalse(output.contains("a detail"), output);
        assertFalse(output.contains("a frame"), output);
    }

    @Test
    void keepsOnlyTheTopicsTheMaskNames() {
        at(Trace.Level.DEBUG, Set.of("copy"));
        Trace.debug(Trace.COPY, "a replica opened");
        Trace.debug(Trace.XROOTD, "a request went out");
        assertTrue(traced().contains("a replica opened"));
        assertFalse(traced().contains("a request went out"));
        assertTrue(Trace.enabled(Trace.Level.DEBUG, Trace.COPY));
        assertFalse(Trace.enabled(Trace.Level.DEBUG, Trace.XROOTD));
    }

    @Test
    void namesTheLevelTheTopicAndTheThread() {
        at(Trace.Level.DEBUG, Set.of());
        Trace.debug(Trace.CONNECTION, "connected to %s:%d", "store.example", 1094);
        String line = traced().strip();
        assertTrue(line.endsWith("connected to store.example:1094"), line);
        assertTrue(line.contains("[Debug][Connection]["
                + Thread.currentThread().getName() + "]"), line);
    }

    @Test
    void readsALevelByNameOrByNumber() {
        assertEquals(Trace.Level.DUMP, Trace.Level.parse("Dump", Trace.Level.NONE));
        assertEquals(Trace.Level.DEBUG, Trace.Level.parse("debug", Trace.Level.NONE));
        assertEquals(Trace.Level.WARNING, Trace.Level.parse("2", Trace.Level.NONE));
        assertEquals(Trace.Level.NONE, Trace.Level.parse("0", Trace.Level.DUMP));
    }

    @Test
    void keepsTheCallersLevelWhenTheSettingMakesNoSense() {
        assertEquals(Trace.Level.INFO, Trace.Level.parse("", Trace.Level.INFO));
        assertEquals(Trace.Level.INFO, Trace.Level.parse("chatty", Trace.Level.INFO));
        assertEquals(Trace.Level.INFO, Trace.Level.parse("99", Trace.Level.INFO));
    }

    @Test
    void survivesAFormatItCannotApply() {
        at(Trace.Level.DEBUG, Set.of());
        Trace.debug(Trace.COPY, "%d replicas", "not a number");
        String output = traced();
        assertTrue(output.contains("%d replicas"), output);
        assertTrue(output.contains("unformattable"), output);
    }

    @Test
    void leavesAPercentAloneWhenThereIsNothingToSubstitute() {
        at(Trace.Level.DEBUG, Set.of());
        Trace.debug(Trace.COPY, "100% of the file");
        assertTrue(traced().contains("100% of the file"));
    }
}
