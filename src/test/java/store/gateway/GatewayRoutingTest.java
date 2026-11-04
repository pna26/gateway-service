package store.gateway;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Sobe o gateway de verdade apontando para um servidor HTTP falso que faz o papel
 * do Auth (/auth/solve) e do Account (/accounts ecoa o header id-account).
 * Cache desligado: aqui testamos roteamento e autorização.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "store.gateway.cache.enabled=false"
})
@AutoConfigureWebTestClient
class GatewayRoutingTest {

    private static final HttpServer stub = startStub();

    @Autowired
    private WebTestClient client;

    @DynamicPropertySource
    static void routes(DynamicPropertyRegistry registry) {
        final String base = "http://localhost:" + stub.getAddress().getPort();
        registry.add("AUTH_URI", () -> base);
        registry.add("ACCOUNT_URI", () -> base);
        registry.add("EXCHANGE_URI", () -> base);
    }

    @AfterAll
    static void stop() {
        stub.stop(0);
    }

    private static HttpServer startStub() {
        try {
            final HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            server.createContext("/auth/solve", ex -> {
                final String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                if (body.contains("\"token\":\"jwt-ok\"")) {
                    send(ex, 200, "{\"idAccount\":\"42\"}");
                } else {
                    send(ex, 401, "");
                }
            });
            server.createContext("/auth/login", ex -> send(ex, 200, "login"));
            server.createContext("/accounts", ex -> send(ex, 200,
                "{\"path\":\"" + ex.getRequestURI().getPath() + "\",\"idAccount\":\""
                    + ex.getRequestHeaders().getFirst("id-account") + "\"}"));
            server.createContext("/exchange", ex -> send(ex, 200,
                "{\"path\":\"" + ex.getRequestURI().getPath() + "\"}"));
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) ex.getResponseBody().write(bytes);
        ex.close();
    }

    @BeforeEach
    void longerTimeout() {
        client = client.mutate().responseTimeout(java.time.Duration.ofSeconds(10)).build();
    }

    @Test
    void healthCheckDoGateway() {
        client.get().uri("/health-check").exchange()
            .expectStatus().isOk()
            .expectBody().jsonPath("$.hostname").exists();
    }

    @Test
    void loginEhAberto() {
        client.post().uri("/auth/login").exchange()
            .expectStatus().isOk()
            .expectBody(String.class).isEqualTo("login");
    }

    @Test
    void accountsSemTokenDa401() {
        client.get().uri("/accounts").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void accountsComTokenInvalidoDa401() {
        client.get().uri("/accounts").cookie("__store_jwt_token", "jwt-ruim")
            .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void accountsComTokenValidoRecebeIdAccount() {
        client.get().uri("/accounts").cookie("__store_jwt_token", "jwt-ok")
            .exchange()
            .expectStatus().isOk()
            .expectBody().jsonPath("$.idAccount").isEqualTo("42");
    }

    @Test
    void idAccountForjadoPeloClienteEhDescartado() {
        // sem token: o header forjado não abre a rota
        client.get().uri("/accounts").header("id-account", "999")
            .exchange().expectStatus().isUnauthorized();
        // com token: o serviço recebe o id do token, não o forjado
        client.get().uri("/accounts").header("id-account", "999").cookie("__store_jwt_token", "jwt-ok")
            .exchange()
            .expectStatus().isOk()
            .expectBody().jsonPath("$.idAccount").isEqualTo("42");
    }

    @Test
    void exchangesEhApelidoDeExchange() {
        client.get().uri("/exchanges/USD/BRL").cookie("__store_jwt_token", "jwt-ok")
            .exchange()
            .expectStatus().isOk()
            .expectBody().jsonPath("$.path").isEqualTo("/exchange/USD/BRL");
    }

}
