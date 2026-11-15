package net.i2p.jetty;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http3.client.HTTP3Client;
import org.eclipse.jetty.http3.client.transport.HttpClientTransportOverHTTP3;
import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.quic.client.ClientQuicConfiguration;
import org.eclipse.jetty.server.AbstractNetworkConnector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NetworkConnectionLimit;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.QoSHandler;
import org.eclipse.jetty.util.BufferUtil;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import net.i2p.I2PAppContext;
import net.i2p.router.web.HostCheckHandler;

/** Live loopback TCP/TLS/UDP acceptance. Requires the optional native HTTP/3 runtime. */
public class LiveWebServerRegression {
    private static int checks, failures;
    private static void check(boolean ok, String message) {
        checks++;
        if (!ok) { failures++; System.out.println("FAIL: " + message); }
    }

    // This trust manager is confined to an ephemeral local test certificate.
    private static SSLContext trustTestCertificate() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        }}, new SecureRandom());
        return context;
    }

    private static HttpResponse<String> send(HttpClient client, String url, String method, String origin, String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10));
        if (origin != null) request.header("Origin", origin);
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static org.eclipse.jetty.client.HttpClient nativeClient() throws Exception {
        SslContextFactory.Client tls = new SslContextFactory.Client();
        tls.setTrustAll(true);
        tls.setEndpointIdentificationAlgorithm(null);
        HTTP3Client lowLevel = new HTTP3Client(new ClientQuicConfiguration(tls, null));
        lowLevel.getHTTP3Configuration().setStreamIdleTimeout(10000);
        org.eclipse.jetty.client.HttpClient client = new org.eclipse.jetty.client.HttpClient(new HttpClientTransportOverHTTP3(lowLevel));
        client.start();
        return client;
    }

    private static void probe(String[] urls) throws Exception {
        org.eclipse.jetty.client.HttpClient client = nativeClient();
        try {
            for (int i = 1; i < urls.length; i++) {
                var response = client.newRequest(urls[i]).timeout(10, TimeUnit.SECONDS).send();
                check(response.getStatus() == 200 && response.getVersion() == HttpVersion.HTTP_3,
                      "packaged application serves HTTP/3: " + urls[i]);
                check(response.getContentAsString().contains("I2P"), "packaged HTTP/3 application returns its page");
                var rejected = client.POST(urls[i]).headers(headers -> headers.put("Origin", "https://evil.example"))
                        .timeout(10, TimeUnit.SECONDS).send();
                // Origin enforcement is a console boundary; hosted sites own their application origin policy.
                if (i == 1) check(rejected.getStatus() == 403, "packaged console rejects cross-origin writes over QUIC");
                if (i == 1) {
                    URI origin = URI.create(urls[i]);
                    var accepted = client.POST(urls[i]).headers(headers -> headers.put("Origin", origin.getScheme() + "://" + origin.getRawAuthority()))
                            .timeout(10, TimeUnit.SECONDS).send();
                    check(accepted.getStatus() == 200, "packaged console accepts same-origin writes over QUIC");
                }
            }
        } finally { client.stop(); }
        System.out.println("LIVE_WEB_SERVER_CHECKS=" + checks + "; FAILURES=" + failures);
    }

    public static void main(String[] args) throws Exception {
        if (args[0].equals("--probe")) { probe(args); System.exit(failures == 0 ? 0 : 1); }
        I2PAppContext context = I2PAppContext.getGlobalContext();
        QueuedThreadPool threads = new QueuedThreadPool(24, 6, 60000);
        threads.setReservedThreads(1);
        Server server = new Server(threads);
        SslContextFactory.Server tls = new SslContextFactory.Server();
        tls.setKeyStorePath(Path.of(args[0]).toAbsolutePath().toString());
        tls.setKeyStorePassword("changeit");
        tls.setKeyManagerPassword("myKeyPassword");
        tls.setIncludeProtocols("TLSv1.3", "TLSv1.2");
        HttpConfiguration plain = new HttpConfiguration();
        plain.setSendServerVersion(false);
        plain.setMinRequestDataRate(16);
        ServerConnector http = new ServerConnector(server, 1, 1, new HttpConnectionFactory(plain));
        http.setHost("127.0.0.1"); http.setPort(0); http.setIdleTimeout(10000);
        server.addConnector(http);
        HttpConfiguration secure = new HttpConfiguration(plain);
        secure.addCustomizer(new SecureRequestCustomizer());
        ServerConnector https = new ServerConnector(server, 1, 1,
                new SslConnectionFactory(tls, "http/1.1"), new HttpConnectionFactory(secure));
        https.setHost("127.0.0.1"); https.setPort(0); https.setIdleTimeout(10000);
        server.addConnector(https);
        QoSHandler admission = new QoSHandler(new Handler.Abstract() {
            public boolean handle(Request request, Response response, Callback callback) {
                response.getHeaders().put("Content-Type", "text/plain;charset=utf-8");
                Content.Source.consumeAll(request, Callback.from(
                    () -> response.write(true, BufferUtil.toBuffer("live-i2p-web-stack"), callback),
                    failure -> Response.writeError(request, response, callback, failure)));
                return true;
            }
        });
        admission.setMaxRequestCount(12);
        admission.setMaxSuspendedRequestCount(64);
        admission.setMaxSuspend(Duration.ofSeconds(2));
        HostCheckHandler hosts = new HostCheckHandler(context);
        hosts.setListenHosts(Set.of("localhost"));
        hosts.setHandler(admission);
        server.setHandler(WebServerPolicy.protect(hosts, 64, 128, 1024));
        server.setStopTimeout(5000);
        server.addBean(new NetworkConnectionLimit(64, http, https));
        // Reserve the ephemeral TCP TLS port first, then use the same UDP port.
        https.open();
        AbstractNetworkConnector quic = Http3Support.createConnector(server, tls, "127.0.0.1", https.getLocalPort(), "quic-server-private");
        server.addConnector(quic);
        Http3Support.advertise(server, quic);
        org.eclipse.jetty.client.HttpClient h3 = null;
        try {
            server.start();
            String base = "http://localhost:" + http.getLocalPort();
            String sslBase = "https://localhost:" + https.getLocalPort();
            HttpClient client = HttpClient.newBuilder().sslContext(trustTestCertificate()).connectTimeout(Duration.ofSeconds(5))
                    .version(HttpClient.Version.HTTP_1_1).build();
            HttpResponse<String> first = send(client, base + "/", "GET", null, null);
            check(first.statusCode() == 200 && first.body().equals("live-i2p-web-stack"), "live TCP HTTP response");
            check(first.headers().firstValue("Server").isEmpty(), "live TCP response suppresses server version");
            check(first.headers().firstValue("X-Content-Type-Options").orElse("").equals("nosniff"), "live response has MIME protection");
            check(first.headers().firstValue("Referrer-Policy").orElse("").equals("no-referrer"), "live response suppresses referrers");
            check(send(client, base + "/", "POST", "http://evil.example", "x").statusCode() == 403, "live cross-origin write denied");
            check(send(client, base + "/", "POST", "null", "x").statusCode() == 403, "live opaque-origin write denied");
            check(send(client, base + "/", "POST", base, "small").statusCode() == 200, "live same-origin write accepted");
            check(send(client, base + "/", "POST", base, "x".repeat(1025)).statusCode() == 413, "live oversized request body denied");
            HttpResponse<String> secured = send(client, sslBase + "/", "GET", null, null);
            check(secured.statusCode() == 200, "live HTTPS response");
            check(secured.headers().firstValue("Alt-Svc").orElse("").contains("h3=\":" + quic.getLocalPort() + "\""), "HTTPS advertises the running UDP listener");
            for (String protocol : new String[] {"TLSv1.2", "TLSv1.3"}) {
                try (SSLSocket socket = (SSLSocket) trustTestCertificate().getSocketFactory().createSocket("localhost", https.getLocalPort())) {
                    socket.setEnabledProtocols(new String[] {protocol});
                    socket.startHandshake();
                    check(socket.getSession().getProtocol().equals(protocol), "real " + protocol + " handshake");
                }
            }
            h3 = nativeClient();
            org.eclipse.jetty.client.ContentResponse answer = h3.newRequest("https://127.0.0.1:" + https.getLocalPort() + "/").timeout(10, TimeUnit.SECONDS).send();
            check(answer.getStatus() == 200 && answer.getVersion() == HttpVersion.HTTP_3, "real QUIC handshake negotiates HTTP/3");
            check(answer.getContentAsString().equals(first.body()), "HTTP/3 and TCP return identical application bytes");
            check(((Number)quic.getClass().getMethod("getOpenSessionCount").invoke(quic)).intValue() == 1,
                  "native QUIC session admission is accounted");
            var post = h3.POST("https://127.0.0.1:" + https.getLocalPort() + "/")
                    .headers(headers -> headers.put("Origin", "https://127.0.0.1:" + https.getLocalPort()))
                    .timeout(10, TimeUnit.SECONDS).send();
            check(post.getStatus() == 200, "same-origin HTTP/3 POST works without an HTTP/1 Host field");
            org.eclipse.jetty.client.ContentResponse tunnel = h3.newRequest("https://127.0.0.1:" + https.getLocalPort() + "/")
                    .headers(headers -> headers.put("X-I2P-DestHash", "test-client")).timeout(10, TimeUnit.SECONDS).send();
            check(tunnel.getHeaders().get("Alt-Svc") == null, "HTTP/3 does not advertise direct UDP to I2P tunnel clients");
            List<CompletableFuture<HttpResponse<String>>> flood = new ArrayList<>();
            var senders = Executors.newFixedThreadPool(16);
            try {
            for (int i = 0; i < 400; i++) {
                HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/")).timeout(Duration.ofSeconds(10)).build();
                flood.add(CompletableFuture.supplyAsync(() -> {
                    try { return client.send(request, HttpResponse.BodyHandlers.ofString()); }
                    catch (Exception failure) { throw new RuntimeException(failure); }
                }, senders));
            }
            int throttled = 0;
            for (CompletableFuture<HttpResponse<String>> request : flood)
                if (request.get(15, TimeUnit.SECONDS).statusCode() == 429) throttled++;
            check(throttled > 0, "live burst is rate limited without exhausting worker tasks");
            Thread.sleep(1100);
            check(send(client, base + "/", "GET", null, null).statusCode() == 200, "live server recovers after rate-limit burst");
            System.out.println("HTTP_PORT=" + http.getLocalPort() + "; TLS_AND_QUIC_PORT=" + https.getLocalPort());
            System.out.println("LIVE_THROTTLED_REQUESTS=" + throttled);
            } finally { senders.shutdownNow(); }
        } finally {
            if (h3 != null) h3.stop();
            server.stop(); server.destroy(); context.logManager().shutdown();
        }
        System.out.println("LIVE_WEB_SERVER_CHECKS=" + checks + "; FAILURES=" + failures);
        System.exit(failures == 0 ? 0 : 1);
    }
}
