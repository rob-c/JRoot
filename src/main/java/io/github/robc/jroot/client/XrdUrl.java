package io.github.robc.jroot.client;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.wire.XrdConst;

/**
 * An xrootd URL: {@code root://[user@]host[:port][,host:port...]//path[?cgi]}.
 *
 * <p>The double slash before the path is the convention, not an accident —
 * {@code root://server//store/file} names {@code /store/file}. A single
 * slash is accepted and read the same way, because that is what people
 * type and no xrootd path is ever relative.
 */
public final class XrdUrl {

    private final String scheme;
    private final String user;
    private final List<Endpoint> endpoints;
    private final String path;
    private final String cgi;

    /** One {@code host:port} of a URL's endpoint list. */
    public record Endpoint(String host, int port) {

        @Override
        public String toString() {
            return host + ":" + port;
        }
    }

    private XrdUrl(String scheme, String user, List<Endpoint> endpoints,
                   String path, String cgi) {
        this.scheme = scheme;
        this.user = user;
        this.endpoints = List.copyOf(endpoints);
        this.path = path;
        this.cgi = cgi;
    }

    public static XrdUrl parse(String url) {
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) {
            throw new XrdException("\"" + url + "\" is not a URL: it names no scheme");
        }
        String scheme = url.substring(0, schemeEnd).toLowerCase();
        if (!isXrootd(scheme)) {
            throw new XrdException("scheme \"" + scheme + "\" is not an xrootd scheme");
        }
        String rest = url.substring(schemeEnd + 3);

        String cgi = "";
        int question = rest.indexOf('?');
        if (question >= 0) {
            cgi = rest.substring(question + 1);
            rest = rest.substring(0, question);
        }

        String authority = rest;
        String path = "";
        int slash = rest.indexOf('/');
        if (slash >= 0) {
            authority = rest.substring(0, slash);
            path = rest.substring(slash);
            // The double slash separates authority from an absolute path.
            if (path.startsWith("//")) {
                path = path.substring(1);
            }
        }

        String user = "";
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            user = authority.substring(0, at);
            authority = authority.substring(at + 1);
        }
        if (authority.isBlank()) {
            throw new XrdException("\"" + url + "\" names no host");
        }

        List<Endpoint> endpoints = new ArrayList<>();
        for (String part : authority.split(",")) {
            endpoints.add(endpoint(part.strip(), url));
        }
        return new XrdUrl(scheme, user, endpoints, path, cgi);
    }

    private static Endpoint endpoint(String authority, String url) {
        if (authority.startsWith("[")) {                 // [2001:db8::1]:1094
            int close = authority.indexOf(']');
            if (close < 0) {
                throw new XrdException("\"" + url + "\" has an unclosed IPv6 literal");
            }
            String host = authority.substring(1, close);
            String tail = authority.substring(close + 1);
            return new Endpoint(host, tail.startsWith(":")
                    ? port(tail.substring(1), url) : XrdConst.DEFAULT_PORT);
        }
        int colon = authority.lastIndexOf(':');
        if (colon < 0) {
            return new Endpoint(authority, XrdConst.DEFAULT_PORT);
        }
        return new Endpoint(authority.substring(0, colon), port(authority.substring(colon + 1), url));
    }

    private static int port(String text, String url) {
        try {
            int port = Integer.parseInt(text);
            if (port < 1 || port > 65535) {
                throw new NumberFormatException();
            }
            return port;
        } catch (NumberFormatException e) {
            throw new XrdException("\"" + url + "\" names port \"" + text + "\"");
        }
    }

    public static boolean isXrootd(String scheme) {
        return switch (scheme.toLowerCase()) {
            case "root", "roots", "xroot", "xroots" -> true;
            default -> false;
        };
    }

    public String scheme() {
        return scheme;
    }

    public String user() {
        return user;
    }

    public List<Endpoint> endpoints() {
        return endpoints;
    }

    public Endpoint endpoint() {
        return endpoints.get(0);
    }

    public String host() {
        return endpoint().host();
    }

    public int port() {
        return endpoint().port();
    }

    public String path() {
        return path;
    }

    public String cgi() {
        return cgi;
    }

    /** The path with the URL's CGI attached, which is what requests carry. */
    public String pathWithCgi() {
        return cgi.isEmpty() ? path : path + "?" + cgi;
    }

    /** Whether the scheme itself demands TLS ({@code roots://}). */
    public boolean requiresTls() {
        return scheme.equals("roots") || scheme.equals("xroots");
    }

    public Map<String, String> cgiParameters() {
        Map<String, String> out = new LinkedHashMap<>();
        for (String pair : cgi.split("&")) {
            if (pair.isBlank()) {
                continue;
            }
            int eq = pair.indexOf('=');
            if (eq < 0) {
                out.put(pair, "");
            } else {
                out.put(pair.substring(0, eq), pair.substring(eq + 1));
            }
        }
        return out;
    }

    /** The same URL pointed at a different server, as a redirect gives it. */
    public XrdUrl at(String host, int port, boolean tls) {
        return new XrdUrl(tls ? "roots" : "root", user,
                List.of(new Endpoint(host, port)), path, cgi);
    }

    /** The same server, a different path. */
    public XrdUrl withPath(String newPath) {
        return new XrdUrl(scheme, user, endpoints, newPath, cgi);
    }

    public XrdUrl withCgi(String newCgi) {
        return new XrdUrl(scheme, user, endpoints, path, newCgi == null ? "" : newCgi);
    }

    /** Just the server, no path — the key a connection pool is keyed on. */
    public String serverKey() {
        return scheme + "://" + (user.isEmpty() ? "" : user + "@") + endpoint();
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder(scheme).append("://");
        if (!user.isEmpty()) {
            out.append(user).append('@');
        }
        for (int i = 0; i < endpoints.size(); i++) {
            out.append(i == 0 ? "" : ",").append(endpoints.get(i));
        }
        out.append('/').append(path);
        if (!cgi.isEmpty()) {
            out.append('?').append(cgi);
        }
        return out.toString();
    }
}
