package store.gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Filtro global de autorização.
 *
 * 1. rota aberta (RouterValidator)  -> segue sem token;
 * 2. sem cookie __store_jwt_token   -> 401;
 * 3. token no cache (Redis)         -> usa o id em cache;
 * 4. senão, POST /auth/solve        -> 401 se inválido, 503 se o Auth estiver fora;
 * 5. repassa o id no header id-account para o serviço de destino.
 *
 * O header id-account enviado pelo cliente já foi removido pelo default-filter
 * RemoveRequestHeader (application.yaml), que roda antes deste filtro.
 */
@Component
public class AuthorizationFilter implements GlobalFilter, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationFilter.class);

    public static final String AUTH_COOKIE_TOKEN = "__store_jwt_token";
    public static final String HEADER_ID_ACCOUNT = "id-account";

    // depois dos default-filters (ordens 1, 2, ...) e antes do roteamento
    public static final int ORDER = 100;

    private final RouterValidator routerValidator;
    private final AuthClient authClient;
    private final TokenCache tokenCache;

    public AuthorizationFilter(RouterValidator routerValidator, AuthClient authClient, TokenCache tokenCache) {
        this.routerValidator = routerValidator;
        this.authClient = authClient;
        this.tokenCache = tokenCache;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final ServerHttpRequest request = exchange.getRequest();

        if (!routerValidator.isSecured.test(request)) {
            logger.debug("rota aberta: {} {}", request.getMethod(), request.getURI().getPath());
            return chain.filter(exchange);
        }

        final HttpCookie cookie = request.getCookies().getFirst(AUTH_COOKIE_TOKEN);
        final String jwt = cookie == null ? null : cookie.getValue().trim();
        if (jwt == null || jwt.isEmpty()) {
            logger.debug("sem cookie: {} {}", request.getMethod(), request.getURI().getPath());
            return reject(exchange, HttpStatus.UNAUTHORIZED);
        }

        // os erros tratados aqui são só os da validação do token; erros do
        // serviço de destino (depois do chain.filter) seguem o fluxo normal
        return resolve(jwt)
            .flatMap(result -> result.idAccount() != null
                ? chain.filter(withIdAccount(exchange, result.idAccount()))
                : reject(exchange, result.status()));
    }

    private Mono<Resolution> resolve(String jwt) {
        return tokenCache.get(jwt)
            .switchIfEmpty(Mono.defer(() -> authClient.solve(jwt)
                .flatMap(id -> tokenCache.put(jwt, id).thenReturn(id))))
            .map(Resolution::ok)
            .onErrorResume(AuthClient.InvalidTokenException.class,
                e -> Mono.just(Resolution.fail(HttpStatus.UNAUTHORIZED)))
            .onErrorResume(e -> {
                logger.error("auth indisponível: {}", e.toString());
                return Mono.just(Resolution.fail(HttpStatus.SERVICE_UNAVAILABLE));
            });
    }

    private record Resolution(String idAccount, HttpStatus status) {
        static Resolution ok(String idAccount) { return new Resolution(idAccount, null); }
        static Resolution fail(HttpStatus status) { return new Resolution(null, status); }
    }

    private static ServerWebExchange withIdAccount(ServerWebExchange exchange, String idAccount) {
        return exchange.mutate()
            .request(exchange.getRequest().mutate()
                .headers(h -> h.set(HEADER_ID_ACCOUNT, idAccount))
                .build())
            .build();
    }

    private static Mono<Void> reject(ServerWebExchange exchange, HttpStatus status) {
        if (exchange.getResponse().isCommitted()) return Mono.empty();
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

}
