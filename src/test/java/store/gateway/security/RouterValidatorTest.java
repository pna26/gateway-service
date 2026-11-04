package store.gateway.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

class RouterValidatorTest {

    private final RouterValidator validator = new RouterValidator();

    private boolean secured(HttpMethod method, String path) {
        return validator.isSecured.test(MockServerHttpRequest.method(method, path).build());
    }

    @Test
    void rotasAbertasDoContrato() {
        assertFalse(secured(HttpMethod.POST, "/auth/register"));
        assertFalse(secured(HttpMethod.POST, "/auth/login"));
        assertFalse(secured(HttpMethod.GET, "/auth/logout"));
        assertFalse(secured(HttpMethod.POST, "/auth/login/"));
    }

    @Test
    void metodoErradoExigeToken() {
        assertTrue(secured(HttpMethod.GET, "/auth/login"));
        assertTrue(secured(HttpMethod.DELETE, "/auth/register"));
    }

    @Test
    void restoExigeToken() {
        assertTrue(secured(HttpMethod.GET, "/auth/me"));
        assertTrue(secured(HttpMethod.POST, "/auth/solve"));
        assertTrue(secured(HttpMethod.GET, "/accounts"));
        assertTrue(secured(HttpMethod.POST, "/accounts"));
        assertTrue(secured(HttpMethod.GET, "/exchange/USD/BRL"));
        assertTrue(secured(HttpMethod.POST, "/auth/login/extra"));
        assertTrue(secured(HttpMethod.POST, "/auth/loginx"));
    }

    @Test
    void curingaCasaSubcaminhos() {
        final RouterValidator.Endpoint deep = RouterValidator.Endpoint.parse("ANY /public/**");
        assertTrue(deep.matches("GET", "/public"));
        assertTrue(deep.matches("POST", "/public/a/b"));
        assertFalse(deep.matches("GET", "/publicx"));
    }

}
