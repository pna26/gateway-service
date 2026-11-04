package store.gateway.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.ConnectException;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

class AuthorizationFilterTest {

    private AuthClient authClient;
    private TokenCache tokenCache;
    private AuthorizationFilter filter;
    private AtomicReference<ServerWebExchange> forwarded;
    private GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        authClient = mock(AuthClient.class);
        tokenCache = mock(TokenCache.class);
        when(tokenCache.get(any())).thenReturn(Mono.empty());
        when(tokenCache.put(any(), any())).thenReturn(Mono.empty());
        filter = new AuthorizationFilter(new RouterValidator(), authClient, tokenCache);
        forwarded = new AtomicReference<>();
        chain = exchange -> {
            forwarded.set(exchange);
            return Mono.empty();
        };
    }

    private MockServerWebExchange get(String path, String token) {
        final MockServerHttpRequest.BaseBuilder<?> b = MockServerHttpRequest.get(path);
        if (token != null) b.cookie(new HttpCookie(AuthorizationFilter.AUTH_COOKIE_TOKEN, token));
        return MockServerWebExchange.from(b);
    }

    @Test
    void rotaAbertaPassaSemToken() {
        final MockServerWebExchange ex = MockServerWebExchange.from(MockServerHttpRequest.post("/auth/login"));
        filter.filter(ex, chain).block();
        assertEquals(ex, forwarded.get());
        verify(authClient, never()).solve(any());
    }

    @Test
    void semCookieDa401() {
        final MockServerWebExchange ex = get("/accounts", null);
        filter.filter(ex, chain).block();
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getResponse().getStatusCode());
        assertNull(forwarded.get());
    }

    @Test
    void tokenValidoRepassaIdAccountEGravaNoCache() {
        when(authClient.solve("jwt-ok")).thenReturn(Mono.just("42"));
        filter.filter(get("/accounts", "jwt-ok"), chain).block();
        assertEquals("42", forwarded.get().getRequest().getHeaders().getFirst("id-account"));
        verify(tokenCache).put("jwt-ok", "42");
    }

    @Test
    void cacheHitNaoChamaOAuth() {
        when(tokenCache.get("jwt-ok")).thenReturn(Mono.just("42"));
        filter.filter(get("/accounts", "jwt-ok"), chain).block();
        assertEquals("42", forwarded.get().getRequest().getHeaders().getFirst("id-account"));
        verify(authClient, never()).solve(any());
    }

    @Test
    void tokenInvalidoDa401() {
        when(authClient.solve("jwt-ruim")).thenReturn(Mono.error(new AuthClient.InvalidTokenException()));
        final MockServerWebExchange ex = get("/accounts", "jwt-ruim");
        filter.filter(ex, chain).block();
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getResponse().getStatusCode());
        assertNull(forwarded.get());
        verify(tokenCache, never()).put(any(), any());
    }

    @Test
    void authForaDa503() {
        when(authClient.solve("jwt-ok")).thenReturn(Mono.error(new ConnectException("refused")));
        final MockServerWebExchange ex = get("/accounts", "jwt-ok");
        filter.filter(ex, chain).block();
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, ex.getResponse().getStatusCode());
        assertNull(forwarded.get());
    }

}
