package store.gateway.security;

import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

/**
 * Cliente do Auth: troca o JWT pelo id da conta chamando POST /auth/solve.
 */
@Component
public class AuthClient {

    private static final ParameterizedTypeReference<Map<String, String>> MAP_TYPE =
        new ParameterizedTypeReference<>() {};

    private final WebClient webClient;
    private final Duration timeout;

    public AuthClient(
        WebClient.Builder builder,
        @Value("${store.gateway.auth.uri:http://auth:8080}") String authUri,
        @Value("${store.gateway.auth.timeout:3s}") Duration timeout
    ) {
        this.webClient = builder.baseUrl(authUri).build();
        this.timeout = timeout;
    }

    /**
     * @return o id da conta dono do token; {@link InvalidTokenException} se o
     *         Auth recusar o token (4xx); outro erro se o Auth estiver fora.
     */
    public Mono<String> solve(String jwt) {
        return webClient.post()
            .uri("/auth/solve")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(Map.of("token", jwt))
            .retrieve()
            // o auth responde 401 para token inválido/expirado: continua 401 no gateway
            .onStatus(HttpStatusCode::is4xxClientError,
                response -> Mono.error(new InvalidTokenException()))
            .bodyToMono(MAP_TYPE)
            .timeout(timeout)
            .flatMap(body -> {
                final String id = body.get("idAccount");
                return id == null || id.isBlank()
                    ? Mono.error(new InvalidTokenException())
                    : Mono.just(id);
            });
    }

    public static class InvalidTokenException extends RuntimeException {
        public InvalidTokenException() {
            super("Invalid token", null, false, false);
        }
    }

}
