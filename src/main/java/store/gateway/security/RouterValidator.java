package store.gateway.security;

import java.util.List;
import java.util.function.Predicate;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

/**
 * Lista das rotas abertas (que não exigem o cookie JWT).
 * Cada entrada é "MÉTODO /caminho"; o método ANY casa com qualquer verbo e o
 * sufixo /** casa com qualquer subcaminho.
 */
@Component
public class RouterValidator {

    public static final List<String> OPEN_API_ENDPOINTS = List.of(
        "POST /auth/register",
        "POST /auth/login",
        "GET /auth/logout"
    );

    private final List<Endpoint> openEndpoints = OPEN_API_ENDPOINTS.stream()
        .map(Endpoint::parse)
        .toList();

    public final Predicate<ServerHttpRequest> isSecured = request -> openEndpoints
        .stream()
        .noneMatch(e -> e.matches(request.getMethod().name(), request.getURI().getPath()));

    record Endpoint(String method, String path, boolean deep) {

        static Endpoint parse(String spec) {
            final String[] parts = spec.trim().split("\\s+");
            final String path = parts[1];
            final boolean deep = path.endsWith("/**");
            return new Endpoint(parts[0], deep ? path.substring(0, path.length() - 3) : path, deep);
        }

        boolean matches(String requestMethod, String requestPath) {
            final boolean methodOk = "ANY".equalsIgnoreCase(method) || method.equalsIgnoreCase(requestMethod);
            if (!methodOk) return false;
            // "/auth/login/" é tratado igual a "/auth/login"
            final String normalized = requestPath.length() > 1 && requestPath.endsWith("/")
                ? requestPath.substring(0, requestPath.length() - 1)
                : requestPath;
            return deep
                ? normalized.equals(path) || normalized.startsWith(path + "/")
                : normalized.equals(path);
        }
    }

}
