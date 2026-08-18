package io.github.robc.jroot.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The XRD_* variables, and what this client does with a bad one. */
class EnvTest {

    @Test
    void takesACountInsideItsRange() {
        assertEquals(4, Env.parse("4", 1, 16));
        assertEquals(1, Env.parse(" 1 ".strip(), 1, 16));
    }

    @Test
    void leavesTheDefaultAloneWhenTheValueIsNoUse() {
        assertEquals(Env.UNSET, Env.parse("", 1, 16));
        assertEquals(Env.UNSET, Env.parse("four", 1, 16));
        assertEquals(Env.UNSET, Env.parse("0", 1, 16));
        assertEquals(Env.UNSET, Env.parse("17", 1, 16));
        assertEquals(Env.UNSET, Env.parse("99999999999999", 1, 16));
    }

    @Test
    void readsAFlagHoweverItWasSpelt() {
        assertTrue(Env.flagOf("1"));
        assertTrue(Env.flagOf("true"));
        assertTrue(Env.flagOf("YES"));
        assertFalse(Env.flagOf("0"));
        assertFalse(Env.flagOf(""));
        assertFalse(Env.flagOf("no"));
    }

    @Test
    void saysNothingAboutAVariableNobodySet() {
        assertEquals("", Env.text("JROOT_NOTHING_IS_SET_HERE"));
        assertEquals(Env.UNSET, Env.number("JROOT_NOTHING_IS_SET_HERE", 1, 2));
        assertFalse(Env.flag("JROOT_NOTHING_IS_SET_HERE"));
        assertEquals(null, Env.seconds("JROOT_NOTHING_IS_SET_HERE"));
    }
}
