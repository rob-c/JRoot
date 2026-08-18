package io.github.robc.jroot.http;

import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.github.robc.jroot.Config;
import io.github.robc.jroot.XrdException;
import io.github.robc.jroot.XrdProtocolException;
import io.github.robc.jroot.util.Json;
import io.github.robc.jroot.wire.Responses;
import io.github.robc.jroot.wire.Types.PrepareStatus;

/**
 * The WLCG Tape REST API — staging over HTTP.
 *
 * <p>{@code root://} stages with {@code kXR_prepare} and asks how it is going
 * with {@code kXR_QPrep}; the HTTP face of the same storage element does both
 * over a small JSON API, which is what FTS and Rucio drive when they bring a
 * dataset back from tape. This is that API, answering in the same
 * {@link PrepareStatus} the binary protocol answers in, so a caller that
 * knows one scheme knows the other.
 *
 * <p>The API is rooted at the server rather than under the export path,
 * because it names files in its request bodies rather than in the URL. Where
 * that root is differs between implementations — dCache serves it at
 * {@code /api/v1/tape} and CTA at {@code /api/v1} — so it is discovered from
 * the {@code /.well-known/wlcg-tape-rest-api} document the specification
 * defines for exactly this, and only guessed at when a site publishes none.
 */
public final class TapeApi extends HttpStorage {

    /** Where the specification says a site advertises its endpoint. */
    static final String WELL_KNOWN = "/.well-known/wlcg-tape-rest-api";

    /** The root to try when a site publishes no discovery document. */
    static final String DEFAULT_ROOT = "/api/v1/tape";

    private static final Map<String, String> JSON =
            Map.of("Content-Type", "application/json", "Accept", "application/json");

    /** Discovery is a round trip, and one per host is enough. */
    private final Map<String, URI> roots = new ConcurrentHashMap<>();

    public TapeApi(Config config) {
        super(config);
    }

    // -----------------------------------------------------------------
    // Staging
    // -----------------------------------------------------------------

    /**
     * Ask for these files to be brought online. Returns the request handle,
     * which is what every other method here takes.
     *
     * <p>{@code lifetime} is an ISO 8601 duration — {@code "P1D"} for a day —
     * asking the site to keep the files on disk that long once they arrive.
     * Left empty, the site's own policy decides.
     */
    public String stage(List<String> urls, String lifetime) {
        if (urls.isEmpty()) {
            return "";
        }
        List<Object> files = new ArrayList<>(urls.size());
        for (String path : pathsOf(urls)) {
            Map<String, Object> file = new LinkedHashMap<>();
            file.put("path", path);
            if (lifetime != null && !lifetime.isBlank()) {
                file.put("diskLifetime", lifetime);
            }
            files.add(file);
        }
        URI target = resolve(urls.get(0), "stage");
        HttpResponse<byte[]> response = post(target, Json.write(Map.of("files", files)));
        String handle = Json.text(document(response.body(), target), "requestId");
        if (!handle.isEmpty()) {
            return handle;
        }
        // Some servers put the id only in the Location they point a poller at.
        return response.headers().firstValue("Location")
                .map(location -> location.replaceAll("/+$", ""))
                .map(location -> location.substring(location.lastIndexOf('/') + 1))
                .orElseThrow(() -> new XrdProtocolException(target
                        + " took the staging request but named no request id"));
    }

    public String stage(List<String> urls) {
        return stage(urls, "");
    }

    /**
     * How the staging request {@code handle} is going, one status per URL.
     *
     * <p>A file is online once the server says so; not online and not given
     * up on means the bytes are still where staging fetches them from, which
     * is the tape. The states are the specification's own vocabulary, which
     * dCache spells {@code SUBMITTED}, {@code STARTED}, {@code COMPLETED},
     * {@code CANCELLED} and {@code FAILED}.
     */
    public List<PrepareStatus> status(String url, String handle, List<String> urls) {
        URI target = resolve(url, "stage/" + handle);
        HttpResponse<byte[]> response = send(builder(target).GET(),
                BodyHandlers.ofByteArray(), target);
        check(response, target, "GET");
        Map<String, PrepareStatus> found = new LinkedHashMap<>();
        for (Object entry : entries(document(response.body(), target))) {
            String state = Json.text(entry, "state").toUpperCase();
            boolean online = Json.flag(entry, "onDisk") || state.equals("COMPLETED");
            String path = Json.text(entry, "path");
            found.put(path, new PrepareStatus(path,
                    true,                           // the server took the request
                    !online && !state.equals("FAILED") && !state.equals("CANCELLED"),
                    online,
                    true,
                    true,
                    Json.text(entry, "startedAt"),
                    Json.text(entry, "error"),
                    state));
        }
        return Responses.ordered(found, pathsOf(urls));
    }

    /** Stop staging these files, leaving the rest of the request running. */
    public void cancel(String url, String handle, List<String> urls) {
        URI target = resolve(url, "stage/" + handle + "/cancel");
        post(target, Json.write(Map.of("paths", pathsOf(urls))));
    }

    /** Withdraw the whole request, files and all. */
    public void delete(String url, String handle) {
        URI target = resolve(url, "stage/" + handle);
        HttpResponse<Void> response = send(builder(target).DELETE(),
                BodyHandlers.discarding(), target);
        check(response, target, "DELETE");
    }

    /**
     * Give up the disk copies this request pinned. The files stay staged
     * until the site needs the space, which is the difference between this
     * and {@link #delete}: releasing says "I am finished with these", where
     * deleting says "I no longer want them brought back at all".
     */
    public void release(String url, String handle, List<String> urls) {
        URI target = resolve(url, "release/" + handle);
        post(target, Json.write(Map.of("paths", pathsOf(urls))));
    }

    /**
     * Where each of these files lives, without asking for any of it to move.
     *
     * <p>Deployments differ over the vocabulary — {@code DISK}/{@code TAPE}
     * in the specification, {@code ONLINE}/{@code NEARLINE} in the storage
     * systems it describes — and both spell the third case as a compound
     * ({@code ONLINE_AND_NEARLINE}), so the two halves are read separately
     * rather than whole words matched. A locality that names neither is a
     * file the site cannot give you: lost, unavailable, or not there at all.
     */
    public List<PrepareStatus> archiveInfo(List<String> urls) {
        if (urls.isEmpty()) {
            return List.of();
        }
        List<String> paths = pathsOf(urls);
        URI target = resolve(urls.get(0), "archiveinfo");
        HttpResponse<byte[]> response = post(target, Json.write(Map.of("paths", paths)));
        Map<String, PrepareStatus> found = new LinkedHashMap<>();
        for (Object entry : entries(document(response.body(), target))) {
            String path = Json.text(entry, "path");
            found.put(path, locality(path, Json.text(entry, "locality"),
                    Json.text(entry, "error")));
        }
        return Responses.ordered(found, paths);
    }

    static PrepareStatus locality(String path, String word, String error) {
        String upper = word.toUpperCase();
        boolean online = upper.contains("DISK") || upper.contains("ONLINE");
        boolean onTape = upper.contains("TAPE") || upper.contains("NEARLINE");
        String why = !error.isEmpty() ? error
                : online || onTape ? "" : word.toLowerCase();
        return new PrepareStatus(path, online || onTape, onTape, online, false, false, "",
                why, upper);
    }

    // -----------------------------------------------------------------
    // Where the API lives
    // -----------------------------------------------------------------

    /** The endpoint root for {@code url}'s server, discovered once per host. */
    public URI root(String url) {
        URI uri = normalise(url);
        return roots.computeIfAbsent(uri.getScheme() + "://" + uri.getRawAuthority(),
                this::discover);
    }

    /**
     * Ask the host where its tape API lives. A site that publishes no
     * discovery document gets the default root rather than an error: the
     * document postdates the API, and plenty of endpoints serving one have
     * never served the other.
     */
    private URI discover(String host) {
        URI well = URI.create(host + WELL_KNOWN);
        try {
            HttpResponse<byte[]> response = send(builder(well).GET(),
                    BodyHandlers.ofByteArray(), well);
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                for (Object endpoint : Json.array(
                        Json.object(document(response.body(), well)).get("endpoints"))) {
                    String named = endpoint instanceof String bare
                            ? bare : Json.text(endpoint, "uri");
                    if (!named.isBlank()) {
                        return URI.create(named);
                    }
                }
            }
        } catch (XrdException e) {
            // No discovery document, or a host that will not say. Guess.
        }
        return URI.create(host + DEFAULT_ROOT);
    }

    private URI resolve(String url, String operation) {
        String root = root(url).toString().replaceAll("/+$", "");
        return URI.create(root + "/" + operation);
    }

    private HttpResponse<byte[]> post(URI target, String body) {
        var builder = builder(target).POST(BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        JSON.forEach(builder::header);
        HttpResponse<byte[]> response = send(builder, BodyHandlers.ofByteArray(), target,
                BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        check(response, target, "POST");
        return response;
    }

    /** The file list of a reply, whether it is the body or a member of it. */
    private static List<Object> entries(Object document) {
        if (document instanceof List) {
            return Json.array(document);
        }
        for (String key : List.of("files", "responses")) {
            Object found = Json.object(document).get(key);
            if (found != null) {
                return Json.array(found);
            }
        }
        return List.of();
    }

    private static Object document(byte[] payload, URI uri) {
        String text = new String(payload, StandardCharsets.UTF_8).strip();
        try {
            return Json.parse(text.isEmpty() ? "{}" : text);
        } catch (XrdException e) {
            throw new XrdProtocolException(uri + " did not answer with JSON: "
                    + text.substring(0, Math.min(text.length(), 120)), e);
        }
    }

    private static List<String> pathsOf(List<String> urls) {
        return urls.stream().map(url -> normalise(url).getRawPath()).toList();
    }

    @Override
    public String toString() {
        return "TapeApi[" + config + "]";
    }
}
