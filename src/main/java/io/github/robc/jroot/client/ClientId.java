package io.github.robc.jroot.client;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.util.Version;

/**
 * What a client tells a server about itself at login.
 *
 * <p>{@code kXR_login} carries a free-form token, and every XRootD client
 * puts the same CGI in it: where the client is, what is running, and which
 * release. Sites read it — an operator asking which application is hammering
 * a pool, or a monitoring stream separating one experiment's transfers from
 * another's, has nothing else to go on, and a client that sends an empty
 * token is simply invisible in those reports.
 *
 * <p>Only what the caller set is sent. The application name and the free
 * text are the caller's to choose ({@link Config#appName()},
 * {@link Config#clientInfo()}, or {@code $XRD_APPNAME} and {@code $XRD_INFO});
 * nothing here reaches into the environment for anything else that might
 * identify a person.
 */
public final class ClientId {

    /** As much of an application name as the reference client sends. */
    public static final int MAX_APPNAME = 16;

    /** As much free text as the reference client sends. */
    public static final int MAX_INFO = 256;

    /** The one character CGI cannot carry inside a value, and the ones that
     *  would end it. */
    private static final String SEPARATORS = "&=?";

    private static final String HOSTNAME = hostname();

    private ClientId() {
    }

    /** The login token for {@code config}: {@code xrd.cc=gb&xrd.tz=0&...}. */
    public static String of(Config config) {
        List<String> fields = new ArrayList<>();
        String country = Locale.getDefault().getCountry().toLowerCase(Locale.ROOT);
        if (country.length() == 2) {
            fields.add("xrd.cc=" + country);
        }
        fields.add("xrd.tz=" + timezone());
        String app = clean(config.appName(), MAX_APPNAME);
        if (!app.isEmpty()) {
            fields.add("xrd.appname=" + app);
        }
        String info = clean(config.clientInfo(), MAX_INFO);
        if (!info.isEmpty()) {
            fields.add("xrd.info=" + info);
        }
        if (!HOSTNAME.isEmpty()) {
            fields.add("xrd.hostname=" + HOSTNAME);
        }
        fields.add("xrd.rn=" + Version.release());
        return String.join("&", fields);
    }

    /**
     * Hours west of UTC, as the C client derives it from {@code timezone}.
     * A client west of Greenwich reports a positive number.
     */
    static int timezone() {
        return -ZonedDateTime.now(ZoneId.systemDefault()).getOffset().getTotalSeconds() / 3600;
    }

    /**
     * {@code value} with everything that would end a CGI field taken out, cut
     * to {@code limit}. A separator inside a value would turn the text after
     * it into a key of its own, so the value loses it rather than the token
     * losing its shape; spaces become underscores, which keeps a name like
     * "my job" readable in a report.
     */
    static String clean(String value, int limit) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length() && out.length() < limit; i++) {
            char c = value.charAt(i);
            if (c > ' ' && c != 0x7F && SEPARATORS.indexOf(c) < 0) {
                out.append(c);
            } else if (Character.isWhitespace(c) && out.length() > 0) {
                out.append('_');
            }
        }
        while (out.length() > 0 && out.charAt(out.length() - 1) == '_') {
            out.setLength(out.length() - 1);
        }
        return out.toString();
    }

    private static String hostname() {
        try {
            return clean(InetAddress.getLocalHost().getHostName(), 64);
        } catch (UnknownHostException | RuntimeException e) {
            return "";                              // a host with no name says nothing
        }
    }
}
