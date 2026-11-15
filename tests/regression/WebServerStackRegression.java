package net.i2p.router.web;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.spi.AbstractSelectableChannel;
import java.nio.channels.spi.SelectorProvider;
import java.nio.file.Path;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.deploy.DeploymentManager;
import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.ee8.servlet.ServletContextHandler;
import org.eclipse.jetty.ee8.servlet.ServletHolder;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.NetworkConnectionLimit;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.server.handler.QoSHandler;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.util.BufferUtil;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.resource.ResourceFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.eclipse.jetty.xml.XmlConfiguration;

import net.i2p.I2PAppContext;
import net.i2p.servlet.util.ServletUtil;
import net.i2p.util.PortMapper;

/** Real HTTP and lifecycle regressions; no network sockets are opened. */
public class WebServerStackRegression {
    private static int checks, failures;

    private static void check(boolean ok, String message) {
        checks++;
        if (!ok) {
            failures++;
            System.out.println("FAIL: " + message);
        }
    }

    private static void await(BooleanSupplier condition, String message) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline)
            Thread.sleep(5);
        if (!condition.getAsBoolean())
            throw new AssertionError(message);
    }

    private static String wire(String method, String host, String extra) {
        return method + " / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n" +
               extra + "Content-Length: 0\r\n\r\n";
    }

    private static int status(String response) {
        return Integer.parseInt(response.substring(9, 12));
    }

    private static void originCase(LocalConnector connector, String method, String host,
                                   String headers, int expected, String label) throws Exception {
        int actual = status(connector.getResponse(wire(method, host, headers), 5, TimeUnit.SECONDS));
        check(actual == expected, label + " (" + method + ", status " + actual + ")");
    }

    private static void origins(boolean servlet) throws Exception {
        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        if (servlet) {
            ServletContextHandler context = new ServletContextHandler();
            context.setContextPath("/");
            context.addServlet(new ServletHolder(new HttpServlet() {
                @Override
                protected void service(HttpServletRequest request, HttpServletResponse response) {
                    if ("h3".equals(request.getHeader("X-Test-Protocol"))) {
                        request = new HttpServletRequestWrapper(request) {
                            public String getProtocol() { return "HTTP/3.0"; }
                            public String getHeader(String name) { return name.equalsIgnoreCase("Host") ? null : super.getHeader(name); }
                        };
                    }
                    if ("1".equals(request.getHeader("X-Test-Secure"))) {
                        request = new HttpServletRequestWrapper(request) {
                            @Override
                            public boolean isSecure() { return true; }
                        };
                    }
                    response.setStatus(ServletUtil.allowOrigin(request) ? 204 : 403);
                }
            }), "/*");
            server.setHandler(context.getCoreContextHandler());
        } else {
            server.setHandler(new Handler.Abstract() {
                public boolean handle(Request request, Response response, Callback callback) {
                    if ("1".equals(request.getHeaders().get("X-Test-Secure"))) {
                        request = new Request.Wrapper(request) {
                            @Override
                            public boolean isSecure() { return true; }
                        };
                    }
                    if ("h3".equals(request.getHeaders().get("X-Test-Protocol"))) {
                        HttpURI uri = HttpURI.from((request.isSecure() ? "https://" : "http://") + request.getHeaders().get("Host") + "/");
                        HttpFields fields = HttpFields.build(request.getHeaders()).remove("Host").asImmutable();
                        request = new Request.Wrapper(request) {
                            public HttpURI getHttpURI() { return uri; }
                            public HttpFields getHeaders() { return fields; }
                        };
                    }
                    response.setStatus(ServletUtil.allowOrigin(request) ? 204 : 403);
                    callback.succeeded();
                    return true;
                }
            });
        }
        try {
            server.start();
            String label = servlet ? "servlet: " : "core: ";
            originCase(connector, "POST", "localhost:7657", "X-Test-Protocol: h3\r\nOrigin: http://localhost:7657\r\n", 204,
                       label + "authority without Host supports same-origin writes");
            originCase(connector, "POST", "localhost:7657", "X-Test-Protocol: h3\r\nOrigin: http://evil.example\r\n", 403,
                       label + "authority without Host rejects cross-origin writes");
            for (String method : new String[] {"POST", "PUT", "PATCH", "DELETE", "PROPFIND"}) {
                originCase(connector, method, "localhost:7657", "", 204, label + "clients without Origin work");
                originCase(connector, method, "localhost:7657", "Sec-Fetch-Site: cross-site\r\n", 403, label + "cross-site browser writes without Origin rejected");
                originCase(connector, method, "localhost:7657", "Origin: http://localhost:7657\r\n", 204, label + "same origin works");
                originCase(connector, method, "localhost:7657", "Origin: http://evil.example\r\n", 403, label + "cross origin rejected");
                originCase(connector, method, "localhost:7657", "Origin: null\r\n", 403, label + "opaque origin rejected");
            }
            for (String method : new String[] {"GET", "HEAD", "OPTIONS", "TRACE"})
                originCase(connector, method, "localhost:7657", "Origin: http://evil.example\r\n", 204, label + "safe methods can be read");
            String[][] valid = {
                {"localhost", "http://localhost:80"}, {"localhost:80", "http://localhost"},
                {"LOCALHOST:7657", "HTTP://localhost:7657"},
                {"127.0.0.1:7657", "http://127.0.0.1:7657"},
                {"[::1]", "http://[::1]:80"}, {"[::1]:80", "http://[::1]"},
                {"[::1]:7657", "http://[::1]:7657"}
            };
            for (String[] pair : valid)
                originCase(connector, "POST", pair[0], "Origin: " + pair[1] + "\r\n", 204, label + "normalized origin " + pair[1]);
            for (String host : new String[] {"localhost", "localhost:443", "[::1]", "[::1]:443"}) {
                String origin = host.startsWith("[") ? "https://[::1]" : "https://localhost";
                originCase(connector, "POST", host, "X-Test-Secure: 1\r\nOrigin: " + origin + "\r\n", 204, label + "HTTPS default port");
            }
            for (String origin : new String[] {
                "", "NULL", "http://localhost:7658", "https://localhost:7657", "http://localhost.evil:7657",
                "http://user@localhost:7657", "http://localhost:7657/", "http://localhost:7657/path",
                "http://localhost:7657?x", "http://localhost:7657#x", "http://localhost:",
                "http://localhost:0", "http://localhost:65536", "http://localhost:-1", "http://[::1",
                "file://localhost:7657", "http://localhost:7657 http://evil.example",
                "http://localhost:7657,http://evil.example"
            })
                originCase(connector, "POST", "localhost:7657", "Origin: " + origin + "\r\n", 403, label + "invalid origin " + origin);
            for (String pair : new String[] {
                "Origin: http://localhost:7657\r\nOrigin: http://evil.example\r\n",
                "Origin: http://evil.example\r\nOrigin: http://localhost:7657\r\n",
                "Origin: http://localhost:7657\r\nOrigin: http://localhost:7657\r\n"
            })
                originCase(connector, "POST", "localhost:7657", pair, 403, label + "multiple origins rejected");
            String noHost = "POST / HTTP/1.0\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n\r\n";
            check(status(connector.getResponse(noHost)) == 403, label + "Origin without Host rejected");
        } finally {
            server.stop();
            server.destroy();
        }
    }

    private static void hosts() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("routerconsole.redirectToHTTPS", "true");
        I2PAppContext context = new I2PAppContext(properties);
        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        HostCheckHandler hostCheck = new HostCheckHandler(context);
        hostCheck.setListenHosts(Set.of("0.0.0.0", "Console.Example"));
        AtomicInteger calls = new AtomicInteger();
        hostCheck.setHandler(new Handler.Abstract() {
            public boolean handle(Request request, Response response, Callback callback) {
                calls.incrementAndGet();
                response.setStatus(204);
                callback.succeeded();
                return true;
            }
        });
        server.setHandler(hostCheck);
        try {
            server.start();
            for (String host : new String[] {"localhost:7657", "LOCALHOST:7657", "127.0.0.1:7657",
                                             "[::1]:7657", "192.168.1.3:7657", "console.example:7657", "CONSOLE.EXAMPLE:7657"})
                originCase(connector, "GET", host, "", 204, "allowed console host " + host);
            originCase(connector, "GET", "evil.example:7657", "", 403, "wildcard listener keeps hostname protection");
            for (String request : new String[] {
                "GET http://evil.example/ HTTP/1.1\r\nHost: localhost:7657\r\nConnection: close\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: localhost:7657\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: localhost:7657\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
            }) {
                int code = status(connector.getResponse(request));
                check(code == 400 || code == 403, "ambiguous authority or request framing rejected");
            }
            originCase(connector, "POST", "localhost:7657", "Origin: null\r\n", 403, "console rejects opaque origins before application");
            int before = calls.get();
            originCase(connector, "DELETE", "localhost:7657", "Origin: http://evil.example\r\n", 403, "console protects non-POST writes");
            check(calls.get() == before, "rejected requests do not reach the application");
            server.stop();
            hostCheck.setListenHosts(Collections.emptySet());
            server.start();
            originCase(connector, "GET", "evil.example:7657", "", 403, "empty host set retains protection");
            originCase(connector, "GET", "localhost:7657", "", 204, "empty host set permits local access");
            context.portMapper().register(PortMapper.SVC_HTTPS_CONSOLE, 8443);
            String redirect = connector.getResponse("GET /config?x=1 HTTP/1.1\r\nHost: [::1]:7657\r\nConnection: close\r\n\r\n");
            check(status(redirect) == 307 && redirect.contains("Location: https://[::1]:8443/config?x=1\r\n"),
                  "HTTPS redirect keeps IPv6 authority, path and query");
        } finally {
            server.stop();
            server.destroy();
            context.logManager().shutdown();
        }
    }

    private static void chunkFraming() throws Exception {
        Server server = new Server();
        LocalConnector connector = new LocalConnector(server);
        server.addConnector(connector);
        server.setHandler(new Handler.Abstract() {
            public boolean handle(Request request, Response response, Callback callback) {
                Content.Source.consumeAll(request, Callback.from(
                    () -> response.write(true, BufferUtil.toBuffer("consumed"), callback),
                    failure -> Response.writeError(request, response, callback, 400)));
                return true;
            }
        });
        try {
            server.start();
            String headers = "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            check(status(connector.getResponse(headers + "3;name=\"safe\"\r\nabc\r\n0\r\n\r\n")) == 200,
                  "valid quoted chunk extensions are consumed");
            for (String body : new String[] {"3;!\nabc\r\n0\r\n\r\n", "3;name=\"unterminated\r\nabc\r\n0\r\n\r\n"})
                check(status(connector.getResponse(headers + body)) == 400,
                      "malformed chunk extension terminators are rejected");
        } finally {
            server.stop();
            server.destroy();
        }
    }

    private static XmlConfiguration xml(Path root, String file) throws Exception {
        return new XmlConfiguration(ResourceFactory.root().newResource(root.resolve("installer/resources/eepsite/" + file)));
    }

    private static void workerBurst(QueuedThreadPool pool) throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        int tasks = pool.getMaxThreads() + 128;
        CountDownLatch done = new CountDownLatch(tasks);
        boolean accepted = true;
        pool.start();
        try {
            for (int i = 0; i < tasks; i++) {
                try {
                    pool.execute(() -> {
                        try { release.await(); }
                        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                        finally { done.countDown(); }
                    });
                } catch (RejectedExecutionException rejected) {
                    accepted = false;
                    done.countDown();
                }
            }
            check(accepted, "internal task bursts are queued without rejection");
        } finally {
            release.countDown();
            check(done.await(5, TimeUnit.SECONDS), "all accepted internal tasks complete");
            pool.stop();
        }
    }

    private static class Channel extends AbstractSelectableChannel {
        Channel() { super(SelectorProvider.provider()); }
        public int validOps() { return SelectionKey.OP_READ; }
        protected void implCloseSelectableChannel() {}
        protected void implConfigureBlocking(boolean block) {}
    }

    private static class Pending {
        final Response response;
        final Callback callback;
        Pending(Response response, Callback callback) { this.response = response; this.callback = callback; }
        void complete() { response.write(true, BufferUtil.toBuffer("done"), callback); }
    }

    private static class HoldingHandler extends Handler.Abstract {
        final BlockingQueue<Pending> pending = new LinkedBlockingQueue<>();
        final AtomicInteger calls = new AtomicInteger();
        public boolean handle(Request request, Response response, Callback callback) {
            calls.incrementAndGet();
            if (request.getHttpURI().getPath().equals("/fast")) {
                response.write(true, BufferUtil.toBuffer("fast"), callback);
            } else {
                pending.add(new Pending(response, callback));
            }
            return true;
        }
        Pending next() throws Exception {
            Pending next = pending.poll(5, TimeUnit.SECONDS);
            if (next == null) throw new AssertionError("application request did not arrive");
            return next;
        }
    }

    private static void admission(Path root, Path fixtures) throws Exception {
        XmlConfiguration config = xml(root, "jetty.xml");
        Server server = (Server) config.configure();
        QueuedThreadPool pool = (QueuedThreadPool) server.getThreadPool();
        try {
            workerBurst(pool);
            ServerConnector http = (ServerConnector) server.getConnectors()[0];
            check(http.getSelectorManager().getSelectorCount() == 1, "HTTP connector leases one selector");
            check(http.getIdleTimeout() == 120000, "HTTP idle retention is bounded");
            XmlConfiguration ssl = xml(root, "jetty-ssl.xml");
            ssl.getIdMap().putAll(config.getIdMap());
            try {
                ssl.configure();
                check(true, "HTTPS template configures successfully");
                ServerConnector https = (ServerConnector) server.getConnectors()[1];
                check(https.getSelectorManager().getSelectorCount() == 1, "HTTPS connector leases one selector");
                check(https.getIdleTimeout() == 120000, "HTTPS idle retention is bounded");
                SslContextFactory.Server tls = (SslContextFactory.Server) ssl.getIdMap().get("sslContextFactory");
                tls.start();
                try {
                    check(Set.copyOf(Arrays.asList(tls.getSelectedProtocols())).equals(Set.of("TLSv1.2", "TLSv1.3")),
                          "HTTPS context enables only TLS 1.2 and 1.3");
                    check(Arrays.stream(tls.getSelectedCipherSuites()).noneMatch(cipher ->
                          cipher.contains("_NULL_") || cipher.contains("_anon_") || cipher.contains("_RC4_") ||
                          cipher.contains("_DES_") || cipher.contains("_3DES_") || cipher.startsWith("TLS_RSA_")),
                          "HTTPS context excludes obsolete cipher suites");
                } finally { tls.stop(); }
                check(https.getConnectionFactory(HttpConnectionFactory.class).getHttpConfiguration()
                          .getCustomizer(SecureRequestCustomizer.class) != null,
                      "HTTPS marks servlet requests secure and applies SNI checks");
            } catch (Exception invalidTLS) {
                check(false, "HTTPS template initializes: " + invalidTLS.getClass().getSimpleName());
            }
            NetworkConnectionLimit connections = server.getBean(NetworkConnectionLimit.class);
            check(connections != null && connections.getMaxNetworkConnectionCount() == 256, "global connection cap configured");
            Object configuredLimit = config.getIdMap().get("RequestLimit");
            check(configuredLimit instanceof QoSHandler, "shipped handler tree limits HTTP requests asynchronously");
            if (!(configuredLimit instanceof QoSHandler)) return;
            QoSHandler limit = (QoSHandler) configuredLimit;
            check(limit.getMaxRequestCount() == 12 && limit.getMaxSuspendedRequestCount() == 64 &&
                  limit.getMaxSuspend().equals(Duration.ofSeconds(10)), "request admission has finite defaults");
            // Keep the actual configured pool, limits and handler. Replace only
            // network/deployment/file-logging I/O with in-memory test fixtures.
            server.setConnectors(new Connector[0]);
            for (DeploymentManager deployment : server.getBeans(DeploymentManager.class))
                server.removeBean(deployment);
            server.setRequestLog(null);
            LocalConnector connector = new LocalConnector(server);
            LocalConnector second = new LocalConnector(server);
            server.addConnector(connector);
            server.addConnector(second);
            HoldingHandler application = new HoldingHandler();
            limit.setHandler(application);
            server.start();
            List<Channel> channels = new ArrayList<>();
            for (int i = 0; i < 256; i++) {
                Channel channel = new Channel();
                channels.add(channel);
                connections.onAccepting(channel);
                connections.onAccepted(channel);
            }
            check(!connector.isAccepting() && !second.isAccepting(), "connection saturation pauses all connectors");
            connections.onClosed(channels.remove(0));
            check(connector.isAccepting() && second.isAccepting(), "closing a connection restores admission");
            for (Channel channel : channels) {
                connections.onClosed(channel);
                channel.close();
            }
            List<LocalConnector.LocalEndPoint> clients = new ArrayList<>();
            List<Pending> active = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                clients.add(connector.executeRequest("GET /hold HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n"));
                active.add(application.next());
            }
            for (int i = 0; i < 64; i++)
                clients.add(connector.executeRequest("GET /wait HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n"));
            await(() -> limit.getSuspendedRequestCount() == 64, "requests did not suspend");
            check(application.calls.get() == 12, "only admitted requests reach the application");
            CountDownLatch ioTask = new CountDownLatch(1);
            pool.execute(ioTask::countDown);
            check(ioTask.await(2, TimeUnit.SECONDS), "suspended requests leave workers free for I/O tasks");
            long before = System.nanoTime();
            String overflow = connector.getResponse("GET /overflow HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n", 5, TimeUnit.SECONDS);
            check(status(overflow) == 503, "full request queue rejects overflow with 503");
            System.out.println("OVERFLOW_RESPONSE_MILLIS=" + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before));
            active.remove(0).complete();
            Pending resumed = application.next();
            check(application.calls.get() == 13, "completing one request resumes exactly one waiter");
            resumed.complete();
            for (Pending request : active) request.complete();
            for (int i = 1; i < 64; i++) application.next().complete();
            boolean complete = true;
            for (LocalConnector.LocalEndPoint client : clients) {
                String response = client.getResponse(false, 5, TimeUnit.SECONDS);
                complete &= status(response) == 200 && response.contains("done");
            }
            check(complete, "all admitted and queued clients complete successfully");
            await(() -> limit.getSuspendedRequestCount() == 0, "queue did not drain");

            // Exercise failure and expiry independently, accelerating only the
            // timeout so the regression does not wait ten seconds per run.
            limit.setMaxSuspend(Duration.ofMillis(150));
            active.clear();
            for (int i = 0; i < 12; i++) {
                connector.executeRequest("GET /hold HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n");
                active.add(application.next());
            }
            LocalConnector.LocalEndPoint waiter = connector.executeRequest("GET /wait HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n");
            await(() -> limit.getSuspendedRequestCount() == 1, "failure test did not suspend");
            active.remove(0).callback.failed(new IOException("controlled application failure"));
            application.next().complete();
            check(status(waiter.getResponse(false, 5, TimeUnit.SECONDS)) == 200, "failed application releases its admission slot");
            connector.executeRequest("GET /hold HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n");
            active.add(application.next());
            int calls = application.calls.get();
            String expired = connector.getResponse("GET /expired HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n", 5, TimeUnit.SECONDS);
            check(status(expired) == 503 && calls == application.calls.get(), "expired waiter returns 503 without calling application");
            for (Pending request : active) request.complete();
            await(() -> limit.getSuspendedRequestCount() == 0, "expired wait retained a slot");
            check(status(connector.getResponse("GET /fast HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n")) == 200, "server recovers after overload and failures");
            server.stop();
            server.start();
            check(status(connector.getResponse("GET /fast HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n\r\n")) == 200, "configured request limiter survives restart");
            server.stop();
            Path docroot = Path.of("eepsite/docroot");
            Path shipped = fixtures.resolve("installer/resources/eepsite/docroot");
            try (Stream<Path> files = Files.walk(shipped)) {
                for (Path file : (Iterable<Path>) files.filter(Files::isRegularFile)::iterator) {
                    Path target = docroot.resolve(shipped.relativize(file));
                    Files.createDirectories(target.getParent());
                    Files.copy(file, target);
                }
            }
            Files.createDirectories(docroot.resolve("files"));
            Files.writeString(docroot.resolve("files/test.txt"), "public-file-bytes");
            Files.writeString(docroot.resolve("large.txt"), "public-static-file-bytes\n".repeat(4096));
            ServletContextHandler site = (ServletContextHandler) xml(fixtures, "contexts/base-context.xml").configure();
            ContextHandlerCollection contexts = (ContextHandlerCollection) config.getIdMap().get("Contexts");
            contexts.addHandler(site.getCoreContextHandler());
            limit.setHandler(contexts);
            XmlConfiguration gzip = new XmlConfiguration(ResourceFactory.root().newResource(
                    fixtures.resolve("installer/resources/eepsite-jetty9.3/jetty-gzip.xml")));
            gzip.getIdMap().putAll(config.getIdMap());
            gzip.configure();
            server.start();
            String base = " HTTP/1.1\r\nHost: site.i2p\r\nConnection: close\r\n";
            String page = connector.getResponse("GET /help/" + base + "\r\n");
            check(status(page) == 200 && page.contains("I2P Anonymous Webserver"), "shipped welcome page works through gzip and request admission");
            String file = connector.getResponse("GET /files/test.txt" + base + "\r\n");
            check(status(file) == 200 && file.endsWith("public-file-bytes"), "static file bytes survive request admission");
            check(file.contains("X-Content-Type-Options: nosniff") && file.contains("Referrer-Policy: no-referrer"), "static response privacy headers survive request admission");
            check(file.contains("Cache-Control: max-age=3600,public"), "static cache policy survives request admission");
            String head = connector.getResponse("HEAD /files/test.txt" + base + "\r\n");
            check(status(head) == 200 && !head.contains("public-file-bytes"), "HEAD remains body-free through request admission");
            String range = connector.getResponse("GET /files/test.txt" + base + "Range: bytes=0-5\r\n\r\n");
            check(status(range) == 206 && range.endsWith("public"), "partial downloads work through request admission");
            String compressed = connector.getResponse("GET /large.txt" + base + "Accept-Encoding: gzip\r\n\r\n");
            check(status(compressed) == 200 && compressed.contains("Content-Encoding: gzip\r\n"), "large static responses still compress");
            String listing = connector.getResponse("GET /files/" + base + "\r\n");
            check(status(listing) == 403 && !listing.contains("test.txt"), "directory listing protection survives request admission");
            String missing = connector.getResponse("GET /missing" + base + "\r\n");
            check(status(missing) == 404, "custom error responses work through request admission");
        } finally {
            server.stop();
            server.destroy();
        }
    }

    public static void main(String[] args) throws Exception {
        check(Server.getVersion().equals("12.0.41"), "regression runs against the pinned patched Jetty release");
        origins(false);
        origins(true);
        hosts();
        chunkFraming();
        admission(Path.of(args[0]).toAbsolutePath(), Path.of(args[1]).toAbsolutePath());
        System.out.println("WEB_SERVER_STACK_CHECKS=" + checks + "; FAILURES=" + failures);
        System.exit(failures == 0 ? 0 : 1);
    }
}
