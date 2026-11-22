import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.regex.*;

/**
 * VT IOC lookup service. Zero dependencies, Java 21.
 *
 * Threading model
 *  - HttpServer runs every request on a virtual thread.
 *  - /api/batch fans each indicator out to its own virtual thread; results stream back
 *    as NDJSON the moment each one finishes (completion order, not input order).
 *  - A per-API-key RateLimiter spaces VirusTotal calls so a key never exceeds its quota,
 *    while threads for different keys never block each other.
 *  - A TTL cache and in-flight de-duplication make repeated indicators cost zero quota.
 */
public class Main {
    static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    static final ExecutorService POOL = Executors.newVirtualThreadPerTaskExecutor();
    static final ConcurrentHashMap<String, Cached> CACHE = new ConcurrentHashMap<>();
    static final ConcurrentHashMap<String, CompletableFuture<Result>> INFLIGHT = new ConcurrentHashMap<>();
    static final ConcurrentHashMap<String, Limiter> LIMITERS = new ConcurrentHashMap<>();
    static final long TTL_MS = 6 * 3600_000L;
    static final int MAX_BATCH = 500, MAX_CACHE = 5000;
    static final String VT_BASE = Optional.ofNullable(System.getenv("VT_BASE_URL")).orElse("https://www.virustotal.com");
    static final long WINDOW_MS = Long.parseLong(Optional.ofNullable(System.getenv("VT_WINDOW_MS")).orElse("61000"));
    static final long HEARTBEAT_MS = Long.parseLong(Optional.ofNullable(System.getenv("HEARTBEAT_MS")).orElse("15000"));
    static final String ORIGIN = Optional.ofNullable(System.getenv("ALLOWED_ORIGIN")).orElse("*");

    record Result(String value, String type, String status, int malicious, int suspicious, int total,
                  String link, String error, boolean cached) {
        Result withCached() { return new Result(value, type, status, malicious, suspicious, total, link, error, true); }
        String json(Integer idx) {
            StringBuilder b = new StringBuilder("{");
            if (idx != null) b.append("\"idx\":").append(idx).append(',');
            b.append("\"value\":").append(q(value)).append(",\"type\":").append(q(type))
             .append(",\"status\":").append(q(status)).append(",\"malicious\":").append(malicious)
             .append(",\"suspicious\":").append(suspicious).append(",\"total\":").append(total)
             .append(",\"link\":").append(q(link)).append(",\"cached\":").append(cached);
            if (error != null) b.append(",\"error\":").append(q(error));
            return b.append('}').toString();
        }
    }
    record Cached(Result r, long exp) {}

    /**
     * Sliding-window limiter: never more than `rpm` requests in any 61s window (1s safety margin).
     * Nothing is reserved in advance, so a retried request takes the next free slot instead of
     * joining the back of a queue. A rate-limit reply pauses the whole key for a minute.
     */
    static final class Limiter {
        static final long WINDOW = WINDOW_MS;
        private final int rpm; private final ArrayDeque<Long> sent = new ArrayDeque<>(); private long blockedUntil = 0;
        Limiter(int rpm) { this.rpm = rpm; }
        /** Waits for a free slot. Returns false if `cancelled` turns true while waiting (the browser left). */
        boolean acquire(java.util.function.BooleanSupplier cancelled) throws InterruptedException {
            for (;;) {
                if (cancelled.getAsBoolean()) return false;
                long wait;
                synchronized (this) {
                    long now = System.currentTimeMillis();
                    while (!sent.isEmpty() && now - sent.peekFirst() >= WINDOW) sent.pollFirst();
                    wait = Math.max(blockedUntil - now, sent.size() >= rpm ? sent.peekFirst() + WINDOW - now : 0);
                    if (wait <= 0) { sent.addLast(now); return true; }
                }
                Thread.sleep(Math.min(Math.max(wait, 5), 500));
            }
        }
        synchronized void penalize(long ms) { blockedUntil = Math.max(blockedUntil, System.currentTimeMillis() + ms); }
    }

    // ---------- helpers ----------
    static String q(String s) {
        if (s == null) return "\"\"";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\""); case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n"); case '\r' -> b.append("\\r"); case '\t' -> b.append("\\t");
                default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c); }
            }
        }
        return b.append('"').toString();
    }
    static String unescape(String s) {
        return s.replace("\\/", "/").replace("\\\"", "\"").replace("\\\\", "\\");
    }
    // ---- de-obfuscation: runs before any validation ----
    static final Pattern BR_DOT = Pattern.compile("[\\[({]\\s*(?:\\.|dot)\\s*[\\])}]", Pattern.CASE_INSENSITIVE);   // [.] (.) {.} [dot]
    static final Pattern BR_SEP = Pattern.compile("[\\[({]\\s*([:/\\\\]+)\\s*[\\])}]");                          // [:] [/] [//] [://] [//:]
    static final Pattern SCHEME = Pattern.compile("^(?:h[xt*]{2}p|meow)(\\[?s\\]?)?\\s*[:/\\\\]+", Pattern.CASE_INSENSITIVE); // hxxp hxxps h**p hxxp[s] meow
    static final Pattern HOSTPORT = Pattern.compile("^([^/?#:\\s]+)(?::(\\d{1,5}))?([/?#].*)?$");

    static String refang(String raw) {
        String s = raw.trim().replace("\\.", ".");
        s = BR_DOT.matcher(s).replaceAll(".");
        s = BR_SEP.matcher(s).replaceAll("$1");
        // stray wrappers and trailing punctuation: <x>  "x"  [x]  x.  x,
        s = s.replaceAll("^[\\s\"'<({\\[]+", "").replaceAll("[\\s\"'>)}\\].,;]+$", "").replaceFirst("^\\*\\.", "");
        Matcher m = SCHEME.matcher(s);
        if (m.find()) s = "http" + (m.group(1) != null ? "s" : "") + "://" + s.substring(m.end());
        if (!s.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) {
            Matcher h = HOSTPORT.matcher(s);
            if (h.matches()) {
                String host = h.group(1), port = h.group(2), rest = h.group(3);
                boolean hostOk = IPV4.matcher(host).matches() || DOMAIN.matcher(host).matches();
                if (hostOk && rest != null) s = "http://" + host + (port != null ? ":" + port : "") + rest;   // evil.com/login
                else if (hostOk && port != null) s = host;                                                    // 1.2.3.4:8080
            }
        }
        return s;
    }

    static final Pattern IPV4 = Pattern.compile("^((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1?\\d?\\d)$");
    static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:]{2,39}$");
    static final Pattern HASH = Pattern.compile("^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$");
    static final Pattern DOMAIN = Pattern.compile("^(?=.{1,253}$)([a-zA-Z0-9_-]{1,63}\\.)+[a-zA-Z]{2,63}$");
    static final Pattern URLP = Pattern.compile("^https?://\\S+$", Pattern.CASE_INSENSITIVE);

    static String classify(String v) {
        if (URLP.matcher(v).matches()) return "url";
        if (IPV4.matcher(v).matches() || (v.contains(":") && IPV6.matcher(v).matches())) return "ip";
        if (HASH.matcher(v).matches()) return "hash";
        if (DOMAIN.matcher(v).matches()) return "domain";
        return null;
    }
    static String sha(String s) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static int num(String block, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*(\\d+)").matcher(block);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    // ---------- lookup pipeline ----------
    static Result lookup(String raw, String key, int rpm) { return lookup(raw, key, rpm, () -> false); }

    static Result lookup(String raw, String key, int rpm, java.util.function.BooleanSupplier cancelled) {
        String value = refang(raw), type = classify(value);
        if (type == null) return new Result(value, "", "invalid", 0, 0, 0, "", value.matches("^\\d{1,3}(\\.\\d{1,3}){1,2}$") ? "Incomplete IP address: an IPv4 needs 4 parts" : "Not a recognised IP, domain, URL or hash", false);
        if (type.equals("hash") || type.equals("domain")) value = value.toLowerCase();

        String ck = type + ":" + value;
        Cached c = CACHE.get(ck);
        if (c != null && c.exp > System.currentTimeMillis()) return c.r.withCached();

        final String v = value, t = type;
        // identical indicators requested at the same moment share one VirusTotal call
        CompletableFuture<Result> mine = new CompletableFuture<>();
        CompletableFuture<Result> existing = INFLIGHT.putIfAbsent(ck, mine);
        if (existing != null) return existing.join().withCached();
        try {
            Result r = callVt(v, t, key, rpm, cancelled);
            if (r.status.equals("ok") || r.status.equals("notfound")) {
                if (CACHE.size() > MAX_CACHE) CACHE.clear();
                CACHE.put(ck, new Cached(r, System.currentTimeMillis() + TTL_MS));
            }
            mine.complete(r);
            return r;
        } catch (RuntimeException e) {
            mine.completeExceptionally(e); throw e;
        } finally { INFLIGHT.remove(ck); }
    }

    /** One VirusTotal request. Rate limits and network hiccups return status "retry"; the caller re-queues them. */
    static Result callVt(String value, String type, String key, int rpm, java.util.function.BooleanSupplier cancelled) {
        String path = switch (type) {
            case "ip" -> "ip_addresses/" + value;
            case "domain" -> "domains/" + value;
            case "hash" -> "files/" + value;
            default -> "urls/" + Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
        };
        Limiter lim = LIMITERS.computeIfAbsent(sha(key) + ":" + rpm, k -> new Limiter(rpm));
        String link = "https://www.virustotal.com/gui/search/" + URLEncoder.encode(value, StandardCharsets.UTF_8);
        try {
            if (!lim.acquire(cancelled)) return new Result(value, type, "retry", 0, 0, 0, "", "Cancelled", false);
            HttpRequest req = HttpRequest.newBuilder(URI.create(VT_BASE + "/api/v3/" + path))
                    .header("x-apikey", key).timeout(Duration.ofSeconds(10)).GET().build();
            HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            switch (res.statusCode()) {
                case 200 -> {
                    Matcher m = Pattern.compile("\"last_analysis_stats\"\\s*:\\s*\\{([^}]*)\\}").matcher(res.body());
                    String blk = m.find() ? m.group(1) : "";
                    int total = 0; Matcher n = Pattern.compile(":\\s*(\\d+)").matcher(blk);
                    while (n.find()) total += Integer.parseInt(n.group(1));
                    return new Result(value, type, "ok", num(blk, "malicious"), num(blk, "suspicious"), total, link, null, false);
                }
                case 404 -> { return new Result(value, type, "notfound", 0, 0, 0, link, null, false); }
                case 401, 403 -> { return new Result(value, type, "badkey", 0, 0, 0, "", "VirusTotal rejected that API key.", false); }
                case 429 -> {
                    if (res.body().contains("QuotaExceeded"))
                        return new Result(value, type, "error", 0, 0, 0, "", "Your VirusTotal quota is used up. Try again later.", false);
                    lim.penalize(WINDOW_MS);   // per-minute limit hit: pause this key for a full window, then retry
                    return new Result(value, type, "retry", 0, 0, 0, "", "VirusTotal rate limit hit. Lower requests per minute.", false);
                }
                default -> { return new Result(value, type, "error", 0, 0, 0, "", "VirusTotal returned HTTP " + res.statusCode(), false); }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(value, type, "error", 0, 0, 0, "", "Interrupted", false);
        } catch (IOException e) {
            return new Result(value, type, "retry", 0, 0, 0, "", "VirusTotal request failed: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()), false);
        }
    }

    /** A "retry" that ran out of attempts becomes a plain error. */
    static Result settle(Result r) {
        return r.status.equals("retry") ? new Result(r.value, r.type, "error", 0, 0, 0, "", r.error, false) : r;
    }

    // ---------- HTTP layer ----------
    static void cors(HttpExchange x) {
        Headers h = x.getResponseHeaders();
        h.set("Access-Control-Allow-Origin", ORIGIN);
        h.set("Access-Control-Allow-Headers", "Content-Type, X-VT-Key, X-VT-Rpm");
        h.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        h.set("Cache-Control", "no-store");
    }
    static void send(HttpExchange x, int code, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type", "application/json");
        x.sendResponseHeaders(code, b.length);
        try (OutputStream o = x.getResponseBody()) { o.write(b); }
    }
    static String key(HttpExchange x) {
        String k = Optional.ofNullable(x.getRequestHeaders().getFirst("X-VT-Key")).orElse("").trim();
        return k.matches("(?i)^[a-f0-9]{64}$") ? k : null;
    }
    static int rpm(HttpExchange x) {
        try { return Math.max(1, Math.min(1000, Integer.parseInt(x.getRequestHeaders().getFirst("X-VT-Rpm")))); }
        catch (Exception e) { return 4; }
    }
    static String body(HttpExchange x) throws IOException {
        return new String(x.getRequestBody().readNBytes(2_000_000), StandardCharsets.UTF_8);
    }
    /** Reads a JSON string array by field name. Scans string-by-string so ']' inside a value (e.g. evil[.]com) is safe. */
    static List<String> strings(String json, String field) {
        List<String> out = new ArrayList<>();
        Matcher a = Pattern.compile("\"" + field + "\"\\s*:\\s*\\[").matcher(json);
        if (!a.find()) return out;
        int i = a.end();
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == ']') break;
            if (c == '"') {
                StringBuilder sb = new StringBuilder();
                i++;
                while (i < json.length() && json.charAt(i) != '"') {
                    if (json.charAt(i) == '\\' && i + 1 < json.length()) { sb.append(json.charAt(i)).append(json.charAt(i + 1)); i += 2; }
                    else sb.append(json.charAt(i++));
                }
                out.add(unescape(sb.toString()));
            }
            i++;
        }
        return out;
    }

    static boolean gate(HttpExchange x) throws IOException {
        cors(x);
        if (x.getRequestMethod().equals("OPTIONS")) { x.sendResponseHeaders(204, -1); return false; }
        if (!x.getRequestMethod().equals("POST")) { send(x, 405, "{\"error\":\"POST only\"}"); return false; }
        if (key(x) == null) { send(x, 401, "{\"error\":\"That does not look like a VirusTotal API key (64 characters).\",\"badKey\":true}"); return false; }
        return true;
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(Optional.ofNullable(System.getenv("PORT")).orElse("8080"));
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
        s.setExecutor(POOL);

        s.createContext("/api/health", x -> { cors(x); send(x, 200, "{\"ok\":true,\"cache\":" + CACHE.size() + "}"); });

        s.createContext("/api/lookup", x -> {
            if (!gate(x)) return;
            String ind = extract(body(x), "indicator");
            if (ind == null || ind.isBlank()) { send(x, 400, "{\"error\":\"Send {\\\"indicator\\\": \\\"...\\\"}\"}"); return; }
            Result r = lookup(ind, key(x), rpm(x));
            for (int t = 1; t < 3 && r.status.equals("retry"); t++) r = lookup(ind, key(x), rpm(x));
            send(x, 200, settle(r).json(null));
        });

        s.createContext("/api/batch", x -> {
            if (!gate(x)) return;
            List<String> items = strings(body(x), "indicators");
            if (items.isEmpty()) { send(x, 400, "{\"error\":\"Send {\\\"indicators\\\": [...]}\"}"); return; }
            if (items.size() > MAX_BATCH) items = items.subList(0, MAX_BATCH);
            final String k = key(x); final int r = rpm(x);

            x.getResponseHeaders().set("Content-Type", "application/x-ndjson");
            x.getResponseHeaders().set("X-Accel-Buffering", "no");
            x.sendResponseHeaders(200, 0);                       // chunked stream
            OutputStream out = x.getResponseBody();
            Object lock = new Object();
            AtomicBoolean gone = new AtomicBoolean(false);       // set when the browser disconnects
            java.util.function.Consumer<String> write = line -> {
                synchronized (lock) {
                    if (gone.get()) return;
                    try { out.write((line + "\n").getBytes(StandardCharsets.UTF_8)); out.flush(); }
                    catch (IOException e) { gone.set(true); }
                }
            };

            // A few workers pull from a queue. Retries go to the FRONT, so they are never stuck behind the rest.
            record Task(int idx, String ind, int tries) {}
            ConcurrentLinkedDeque<Task> queue = new ConcurrentLinkedDeque<>();
            for (int i = 0; i < items.size(); i++) queue.add(new Task(i, items.get(i), 0));
            AtomicInteger unfinished = new AtomicInteger(items.size());
            int workers = Math.min(items.size(), Math.max(1, Math.min(r, 16)));
            CountDownLatch done = new CountDownLatch(workers);
            for (int w = 0; w < workers; w++) {
                POOL.submit(() -> {
                    try {
                        while (!gone.get() && unfinished.get() > 0) {
                            Task t = queue.pollFirst();
                            if (t == null) { Thread.sleep(200); continue; }   // another worker may still re-queue a retry
                            Result res;
                            try { res = lookup(t.ind(), k, r, gone::get); }
                            catch (RuntimeException e) { res = new Result(t.ind(), "", "error", 0, 0, 0, "", String.valueOf(e.getMessage()), false); }
                            if (res.status.equals("retry") && t.tries() < 2) { queue.addFirst(new Task(t.idx(), t.ind(), t.tries() + 1)); continue; }
                            write.accept(settle(res).json(t.idx()));
                            unfinished.decrementAndGet();
                        }
                    } catch (InterruptedException ignored) {
                    } finally { done.countDown(); }
                });
            }
            // heartbeat: keeps proxies from closing a quiet connection and lets us notice a closed tab
            var heartbeat = POOL.submit(() -> {
                try { while (done.getCount() > 0 && !gone.get()) { Thread.sleep(HEARTBEAT_MS); write.accept("{\"ping\":true}"); } }
                catch (InterruptedException ignored) {}
            });
            try { done.await(); } catch (InterruptedException ignored) {}
            heartbeat.cancel(true);
            if (gone.get()) System.out.println("Client disconnected: batch stopped, no more quota spent.");
            try { out.close(); } catch (IOException ignored) {}
        });

        s.createContext("/api/quota", x -> {
            if (!gate(x)) return;
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(VT_BASE + "/api/v3/users/" + key(x)))
                        .header("x-apikey", key(x)).timeout(Duration.ofSeconds(8)).GET().build();
                HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
                if (res.statusCode() == 401 || res.statusCode() == 403) {
                    send(x, 401, "{\"error\":\"VirusTotal rejected that API key.\",\"badKey\":true}"); return;
                }
                int[] h = quota(res.body(), "api_requests_hourly"), d = quota(res.body(), "api_requests_daily");
                if (res.statusCode() != 200 || (h[0] == 0 && d[0] == 0)) { send(x, 200, "{\"known\":false}"); return; }
                send(x, 200, "{\"known\":true,\"hourlyAllowed\":" + h[0] + ",\"hourlyUsed\":" + h[1]
                        + ",\"dailyAllowed\":" + d[0] + ",\"dailyUsed\":" + d[1] + "}");
            } catch (Exception e) { send(x, 200, "{\"known\":false}"); }
        });

        s.start();
        System.out.println("IOC backend listening on :" + port);
    }

    /** Reads {allowed, used} from one block of VirusTotal's quotas object. */
    static int[] quota(String body, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\\{([^}]*)\\}").matcher(body);
        return m.find() ? new int[]{num(m.group(1), "allowed"), num(m.group(1), "used")} : new int[]{0, 0};
    }

    static String extract(String json, String field) {
        Matcher m = Pattern.compile("\"" + field + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        return m.find() ? unescape(m.group(1)).replace("\"", "") : null;
    }
}
