package net.i2p.jetty;

import java.io.IOException;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.GracefulHandler;
import org.eclipse.jetty.server.handler.StatisticsHandler;
import org.eclipse.jetty.util.BufferUtil;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import net.i2p.I2PAppContext;
import net.i2p.app.ClientAppState;
import net.i2p.router.RouterContext;
import net.i2p.router.web.RouterConsoleRunner;
import net.i2p.servlet.filters.XI2PLocationFilter;

/** Controlled slow I/O and HTTP lifecycle checks, without network sockets. */
public class AsyncWebServerRegression {
    private static int checks, failures;

    private static void check(boolean ok, String message) {
        checks++;
        if (!ok) { failures++; System.out.println("FAIL: " + message); }
    }

    private static void await(BooleanSupplier condition, String label) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        if (!condition.getAsBoolean()) throw new AssertionError(label);
    }

    private static int status(String response) { return Integer.parseInt(response.substring(9, 12)); }
    private static String wire(String path, String headers) {
        return "GET " + path + " HTTP/1.1\r\nHost: localhost:7658\r\nConnection: close\r\n" + headers + "\r\n";
    }

    private static Handler successful() {
        return new Handler.Abstract() {
            public boolean handle(Request request, Response response, Callback callback) {
                response.write(true, BufferUtil.toBuffer("ok"), callback);
                return true;
            }
        };
    }

    private static class ClockRate extends RequestRateLimitHandler {
        long now;
        protected long nanoTime() { return now; }
    }

    private static void rates() throws Exception {
        ClockRate rate = new ClockRate();
        rate.setRequestsPerSecond(1);
        rate.setBurst(2);
        AtomicInteger calls = new AtomicInteger();
        rate.setHandler(new Handler.Abstract() {
            public boolean handle(Request request, Response response, Callback callback) {
                calls.incrementAndGet();
                callback.succeeded();
                return true;
            }
        });
        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        server.setHandler(rate);
        try {
            server.start();
            check(status(connector.getResponse(wire("/", ""))) == 200, "first burst token admitted");
            check(status(connector.getResponse(wire("/", ""))) == 200, "second burst token admitted");
            String denied = connector.getResponse(wire("/", ""));
            check(status(denied) == 429 && denied.contains("Retry-After: 1") && denied.contains("Cache-Control: no-store"), "rate rejection gives a non-cacheable retry response");
            check(calls.get() == 2, "rate-rejected work never reaches the application");
            rate.now += TimeUnit.MILLISECONDS.toNanos(500);
            check(status(connector.getResponse(wire("/", ""))) == 429, "partial token does not admit a request");
            rate.now += TimeUnit.MILLISECONDS.toNanos(500);
            check(status(connector.getResponse(wire("/", ""))) == 200, "monotonic refill restores one token");
            check(status(connector.getResponse(wire("/", ""))) == 429, "one refill cannot be spent twice");
            check(rate.getRejectedRequests() == 3, "rate rejections are observable");
            server.stop();
            server.start();
            check(status(connector.getResponse(wire("/", ""))) == 200, "restart resets the token bucket");
        } finally { server.stop(); server.destroy(); }
        for (double invalid : new double[] {0, -1, Double.NaN, Double.POSITIVE_INFINITY}) {
            try { new ClockRate().setRequestsPerSecond(invalid); check(false, "invalid rate rejected"); }
            catch (IllegalArgumentException expected) { check(true, "invalid rate rejected"); }
        }
    }

    private static void bodyAndDrain() throws Exception {
        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        AtomicReference<Response> heldResponse = new AtomicReference<>();
        AtomicReference<Callback> heldCallback = new AtomicReference<>();
        AtomicInteger calls = new AtomicInteger();
        server.setHandler(WebServerPolicy.protect(new Handler.Abstract() {
            public boolean handle(Request request, Response response, Callback callback) {
                calls.incrementAndGet();
                if (request.getHttpURI().getPath().equals("/hold")) {
                    heldResponse.set(response);
                    heldCallback.set(callback);
                } else {
                    if (request.getHttpURI().getPath().equals("/custom"))
                        response.getHeaders().put("Referrer-Policy", "same-origin");
                    Content.Source.consumeAll(request, Callback.from(
                        () -> response.write(true, BufferUtil.toBuffer("ok"), callback),
                        failure -> Response.writeError(request, response, callback, failure)));
                }
                return true;
            }
        }, 10000, 128, 8));
        server.setStopTimeout(2000);
        try {
            server.start();
            String headers = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n";
            check(status(connector.getResponse(headers + "Content-Length: 8\r\n\r\n12345678")) == 200, "body at the limit is accepted");
            int before = calls.get();
            check(status(connector.getResponse(headers + "Content-Length: 9\r\n\r\n123456789")) == 413, "declared oversized body rejected with 413");
            check(calls.get() == before, "declared oversized body rejected before application");
            check(status(connector.getResponse(headers + "Transfer-Encoding: chunked\r\n\r\n9\r\n123456789\r\n0\r\n\r\n")) == 413, "streamed chunked bodies obey the same limit");
            String response = connector.getResponse(wire("/", ""));
            check(response.contains("X-Content-Type-Options: nosniff") && response.contains("Referrer-Policy: no-referrer"), "application responses receive default privacy headers");
            check(connector.getResponse(wire("/custom", "")).contains("Referrer-Policy: same-origin"), "application policy can override the default");
            LocalConnector.LocalEndPoint held = connector.executeRequest(wire("/hold", ""));
            await(() -> heldCallback.get() != null, "held request not entered");
            GracefulHandler graceful = server.getDescendant(GracefulHandler.class);
            var draining = graceful.shutdown();
            check(!draining.isDone(), "graceful shutdown waits for in-flight work");
            check(status(connector.getResponse(wire("/", ""))) == 503, "shutdown rejects new work with 503");
            heldResponse.get().write(true, BufferUtil.toBuffer("finished"), heldCallback.get());
            check(status(held.getResponse(false, 5, TimeUnit.SECONDS)) == 200, "in-flight response finishes during drain");
            draining.get(5, TimeUnit.SECONDS);
            check(graceful.getCurrentRequestCount() == 0, "draining releases all request accounting");
            StatisticsHandler statistics = server.getDescendant(StatisticsHandler.class);
            check(statistics.getResponses4xx() >= 2 && statistics.getResponses5xx() >= 1, "standard response metrics include rejections");
        } finally { server.stop(); server.destroy(); }
    }

    private static class SlowWriter extends Writer {
        final CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        final StringBuilder records = new StringBuilder();
        boolean closed;
        public void write(char[] chars, int offset, int length) throws IOException {
            entered.countDown();
            try {
                if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("test gate timeout");
            } catch (InterruptedException interrupted) { throw new IOException(interrupted); }
            records.append(chars, offset, length);
        }
        public void flush() {}
        public void close() { closed = true; }
    }

    private static void logging() throws Exception {
        SlowWriter sink = new SlowWriter();
        AsyncLogWriter writer = new AsyncLogWriter(sink, true, 2);
        writer.start();
        try {
            writer.write("first\n");
            check(sink.entered.await(2, TimeUnit.SECONDS), "slow log sink is active");
            long before = System.nanoTime();
            for (int i = 0; i < 10; i++) writer.write("queued" + i + "\n");
            check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before) < 500, "a stalled log disk does not block request submission");
            check(writer.getQueuedRecords() == 2 && writer.getDroppedRecords() == 8, "log queue capacity and dropped records are bounded and visible");
        } finally { sink.release.countDown(); writer.stop(); }
        check(sink.closed && sink.records.toString().equals("first\nqueued0\nqueued1\n"), "shutdown drains accepted log records in order and closes the sink");
        writer.write("after stop\n");
        check(writer.getDroppedRecords() == 9, "late log submission cannot race past shutdown");

        Files.createDirectories(Path.of("logs"));
        I2PRequestLog log = new I2PRequestLog("logs/requests.log");
        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        server.addBean(log);
        server.setHandler(new Handler.Abstract() {
            public boolean handle(Request request, Response response, Callback callback) {
                HttpFields fields = HttpFields.build(request.getHeaders())
                    .put("User-Agent", "agent\"\\forged\u2028line").put("X-I2P-DestB32", "site\nforged").asImmutable();
                Request logged = new Request.Wrapper(request) {
                    public HttpFields getHeaders() { return fields; }
                    public HttpURI getHttpURI() { return HttpURI.from("http://user:URI_PASSWORD_PRIVATE_MARKER@localhost/path"); }
                };
                log.log(logged, response);
                callback.succeeded();
                return true;
            }
        });
        try { server.start(); connector.getResponse(wire("/", "")); }
        finally { server.stop(); server.destroy(); }
        String line = Files.readString(Path.of("logs/requests.log"));
        check(!line.contains("URI_PASSWORD_PRIVATE_MARKER"), "URI credentials never enter access logs");
        check(line.lines().count() == 1 && !line.contains("\u2028"), "request fields cannot forge extra log records");
        check(line.contains("agent\\\"\\\\forged_line"), "quoted log fields escape quotes and backslashes");
    }

    private static class SlowLocation extends XI2PLocationFilter {
        final CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        final AtomicInteger calls = new AtomicInteger();
        SlowLocation(I2PAppContext context) { super(context); }
        protected String getXI2PLocation(String host, String port) {
            calls.incrementAndGet();
            entered.countDown();
            try { release.await(5, TimeUnit.SECONDS); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            return "example.i2p";
        }
    }

    private static void metadata(I2PAppContext context) throws Exception {
        SlowLocation location = new SlowLocation(context);
        location.setHandler(successful());
        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        server.setHandler(location);
        try {
            server.start();
            long before = System.nanoTime();
            String first = connector.getResponse(wire("/path?x=1", ""));
            check(status(first) == 200 && TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before) < 500, "slow metadata I/O does not delay HTTP");
            check(location.entered.await(2, TimeUnit.SECONDS), "metadata lookup runs in background");
            check(!connector.getResponse(wire("/path?x=1", "")).contains("X-I2P-Location"), "response proceeds while lookup remains incomplete");
            check(location.calls.get() == 1, "simultaneous metadata refreshes coalesce");
            location.release.countDown();
            AtomicReference<String> loaded = new AtomicReference<>();
            await(() -> {
                try { loaded.set(connector.getResponse(wire("/path?x=1", ""))); }
                catch (Exception failure) { throw new RuntimeException(failure); }
                return loaded.get().contains("X-I2P-Location");
            }, "metadata did not publish");
            check(loaded.get().contains("X-I2P-Location: http://example.i2p/path?x=1"), "I2P location preserves path and query without leaking backend port");
            check(!connector.getResponse(wire("/", "X-I2P-DestHash: tunnel-client\r\n")).contains("X-I2P-Location"), "tunnel requests do not receive direct-access advertisements");
            server.stop(); server.start();
            check(status(connector.getResponse(wire("/", ""))) == 200, "metadata worker lifecycle supports restart");
        } finally { location.release.countDown(); server.stop(); server.destroy(); }

        Path config = Path.of("memory-jetty.xml").toAbsolutePath();
        Files.writeString(config, "<!DOCTYPE Configure PUBLIC \"-//Jetty//Configure//EN\" \"https://jetty.org/configure_10_0.dtd\">" +
                "<Configure class=\"org.eclipse.jetty.server.Server\"><Set name=\"handler\"><New class=\"org.eclipse.jetty.server.handler.DefaultHandler\"/></Set></Configure>");
        JettyStart app = new JettyStart(null, null, new String[] {config.toString()});
        Field servers = JettyStart.class.getDeclaredField("_jettys");
        servers.setAccessible(true);
        try {
            for (int i = 0; i < 2; i++) {
                app.startup();
                await(() -> app.getState() == ClientAppState.RUNNING, "Jetty lifecycle did not start");
                Server managed = (Server) ((List<?>) servers.get(app)).get(0);
                check(managed.getDescendants(XI2PLocationFilter.class).size() == 1, "managed restart installs exactly one metadata filter");
                app.shutdown(null);
                await(() -> app.getState() == ClientAppState.STOPPED, "Jetty lifecycle did not stop");
            }
        } finally { if (app.getState() == ClientAppState.RUNNING) app.shutdown(null); }
    }

    private static void consoleShutdown(RouterContext context) throws Exception {
        RouterConsoleRunner console = new RouterConsoleRunner(context, null, new String[0]);
        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        AtomicReference<Response> heldResponse = new AtomicReference<>();
        AtomicReference<Callback> heldCallback = new AtomicReference<>();
        server.setHandler(WebServerPolicy.protect(new Handler.Abstract() {
            public boolean handle(Request request, Response response, Callback callback) {
                heldResponse.set(response); heldCallback.set(callback); return true;
            }
        }, 1000, 128, 1024));
        server.setStopTimeout(2000);
        Field field = RouterConsoleRunner.class.getDeclaredField("_server");
        field.setAccessible(true); field.set(console, server);
        try {
            server.start();
            LocalConnector.LocalEndPoint client = connector.executeRequest(wire("/", ""));
            await(() -> heldCallback.get() != null, "console request did not enter");
            long before = System.nanoTime();
            console.shutdown(null);
            check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before) < 500, "console shutdown returns while requests drain in background");
            await(() -> server.getDescendant(GracefulHandler.class).isShutdown(), "console did not initiate drain");
            check(console.getState() == ClientAppState.STOPPING, "console stays STOPPING while draining");
            check(connector.isShutdown(), "console shutdown stops admission of new connections");
            heldResponse.get().write(true, BufferUtil.toBuffer("done"), heldCallback.get());
            check(status(client.getResponse(false, 5, TimeUnit.SECONDS)) == 200, "console drain lets the current response finish");
            await(() -> console.getState() == ClientAppState.STOPPED, "console shutdown did not complete");
            check(server.isStopped(), "console reports STOPPED after the server stops");
        } finally {
            if (heldCallback.get() != null && !server.isStopped()) heldCallback.get().failed(new IOException("test cleanup"));
            server.stop(); server.destroy();
        }

        Server failing = new Server() {
            protected void doStop() throws Exception {
                super.doStop();
                throw new IOException("controlled shutdown failure");
            }
        };
        RouterConsoleRunner broken = new RouterConsoleRunner(context, null, new String[0]);
        field.set(broken, failing);
        try {
            failing.start();
            broken.shutdown(null);
            await(() -> broken.getState() == ClientAppState.CRASHED, "failed shutdown reported success");
            check(failing.isFailed(), "controlled server stop failure is retained");
            check(broken.getState() != ClientAppState.STOPPED, "failed console shutdown does not report a normal stop");
        } finally { failing.destroy(); }
    }

    private static class AdvertisementConnector extends ServerConnector {
        AdvertisementConnector(Server server) { super(server, 0, 1); }
        protected void doStart() {}
        protected void doStop() {}
        public int getLocalPort() { return 8443; }
    }

    private static void http3Policy() throws Exception {
        Path directory = Http3Support.privateDirectory(Path.of("quic-private"));
        check(Files.getPosixFilePermissions(directory).equals(Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)), "QUIC PEM directory is owner-only");
        Path link = Path.of("quic-link");
        Files.createSymbolicLink(link, directory);
        try { Http3Support.privateDirectory(link); check(false, "symlink PEM directory rejected"); }
        catch (IOException expected) { check(true, "symlink PEM directory rejected"); }
        Server missing = new Server();
        try {
            Http3Support.createConnector(missing, new SslContextFactory.Server(), "127.0.0.1", 8443, "unused-quic");
            check(false, "missing optional QUIC dependencies fail explicitly");
        } catch (IllegalStateException expected) {
            check(expected.getMessage().contains("HTTP/3 requires matching"), "missing optional QUIC dependencies fail explicitly");
            check(missing.getConnectors().length == 0 && !Files.exists(Path.of("unused-quic")), "failed QUIC setup leaves no half-configured listener or key export");
        } finally { missing.destroy(); }

        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        server.setHandler(successful());
        AdvertisementConnector advertised = new AdvertisementConnector(server);
        Http3Support.advertise(server, advertised);
        Handler advertisement = server.getHandler();
        server.setHandler(new Handler.Wrapper(advertisement) {
            public boolean handle(Request request, Response response, Callback callback) throws Exception {
                boolean secure = request.getHeaders().get("X-Plain") == null;
                return super.handle(new Request.Wrapper(request) {
                    public boolean isSecure() { return secure; }
                }, response, callback);
            }
        });
        try {
            server.start();
            check(!connector.getResponse(wire("/", "")).contains("Alt-Svc"), "unstarted UDP listener is never advertised");
            advertised.start();
            check(connector.getResponse(wire("/", "")).contains("Alt-Svc: h3=\":8443\"; ma=60"), "direct secure requests receive same-host HTTP/3 advertisement");
            check(!connector.getResponse(wire("/", "X-Plain: 1\r\n")).contains("Alt-Svc"), "plain HTTP is not advertised as secure HTTP/3");
            check(!connector.getResponse(wire("/", "X-I2P-DestHash: client\r\n")).contains("Alt-Svc"), "I2P tunnel clients are not sent to direct UDP");
            check(!connector.getResponse(wire("/", "").replace("localhost:7658", "example.i2p")).contains("Alt-Svc"), "I2P hostnames are not sent to direct UDP");
        } finally { advertised.stop(); server.stop(); server.destroy(); }
    }

    private static void retryTokens() throws Exception {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte)7);
        long[] clock = {1_000_000};
        QuicTokenManager manager = new QuicTokenManager(key, () -> clock[0]);
        InetSocketAddress peer = new InetSocketAddress("127.0.0.1", 12345);
        byte[] cid = new byte[20];
        for (int i = 0; i < cid.length; i++) cid[i] = (byte)i;
        byte[] token = manager.mint(peer, cid, cid.length);
        check(token.length <= 48, "authenticated Retry token fits the native QUIC buffer");
        check(Arrays.equals(manager.validate(peer, token, token.length), cid), "valid Retry token returns the original connection ID");
        check(manager.validate(new InetSocketAddress("127.0.0.2", 12345), token, token.length) == null, "Retry token is bound to client IP");
        check(manager.validate(new InetSocketAddress("127.0.0.1", 12346), token, token.length) == null, "Retry token is bound to client UDP port");
        boolean rejected = true;
        for (int i = 0; i < token.length; i++) {
            byte[] tampered = token.clone();
            tampered[i] ^= 1;
            rejected &= manager.validate(peer, tampered, tampered.length) == null;
        }
        check(rejected, "every single-byte token modification is rejected");
        byte[] otherKey = key.clone(); otherKey[0] ^= 1;
        check(new QuicTokenManager(otherKey, () -> clock[0]).validate(peer, token, token.length) == null,
              "one listener's Retry token cannot authenticate to another listener");
        clock[0] += 59000;
        check(Arrays.equals(manager.validate(peer, token, token.length), cid), "Retry token remains valid within its lifetime");
        clock[0] += 1001;
        check(manager.validate(peer, token, token.length) == null, "expired Retry tokens are rejected");
        clock[0] = 999999;
        check(manager.validate(peer, token, token.length) == null, "tokens outside the allowed future window are rejected");
        boolean bounded = true;
        for (int length = -1; length <= 100; length++)
            bounded &= manager.validate(peer, token, length) == null || length == token.length;
        check(bounded, "malformed token lengths cannot bypass validation or access outside the buffer");
        InetSocketAddress ipv6 = new InetSocketAddress("::1", 12345);
        byte[] six = manager.mint(ipv6, cid, cid.length);
        check(Arrays.equals(manager.validate(ipv6, six, six.length), cid), "IPv6 addresses support authenticated Retry");
        check(manager.validate(peer, six, six.length) == null, "IPv4 and IPv6 Retry identities remain distinct");
    }

    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        properties.setProperty("router.enablePlugins", "false");
        RouterContext context = new RouterContext(null, properties);
        try {
        rates();
        bodyAndDrain();
        logging();
        metadata(context);
        consoleShutdown(context);
        http3Policy();
        retryTokens();
        } finally { context.logManager().shutdown(); }
        System.out.println("ASYNC_WEB_SERVER_CHECKS=" + checks + "; FAILURES=" + failures);
        System.exit(failures == 0 ? 0 : 1);
    }
}
