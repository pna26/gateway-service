package store.gateway.security;

import java.util.List;

import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Bottleneck: autenticação e autorização (RBAC).
 *
 * O AuthorizationFilter já garantiu QUEM é o usuário (token válido); aqui se
 * decide O QUE ele pode fazer, pelo papel que veio no JWT:
 *
 * | rota escolhida | USER                             | ADMIN |
 * |----------------|----------------------------------|-------|
 * | account        | só GET /accounts/{o próprio id}  | tudo  |
 * | demais (auth, exchange, ...) | tudo (basta estar autenticado) | tudo |
 *
 * Decisões:
 * - a regra olha a ROTA que o gateway escolheu, não o texto da URL: variações
 *   como "/accounts;x=1" ou "//accounts" caem na mesma rota e na mesma regra;
 * - no account vale "negado por padrão": qualquer coisa fora da única exceção
 *   do USER (inclusive rotas novas que o account ganhar) exige ADMIN;
 * - o id é comparado já decodificado e sem parâmetros de segmento.
 */
@Component
public class AccessPolicy {

    static final String ACCOUNT_ROUTE = "account";

    private final Counter allowed;
    private final Counter denied;

    public AccessPolicy(MeterRegistry registry) {
        this.allowed = counter(registry, "allow");
        this.denied = counter(registry, "deny");
    }

    private static Counter counter(MeterRegistry registry, String result) {
        return Counter.builder("gateway.rbac.decision")
            .description("Decisoes do RBAC nas rotas autenticadas (allow, deny)")
            .tag("result", result)
            .register(registry);
    }

    public boolean allows(ServerWebExchange exchange, Identity who) {
        final boolean ok = decide(exchange, who);
        (ok ? allowed : denied).increment();
        return ok;
    }

    private static boolean decide(ServerWebExchange exchange, Identity who) {
        if (who.isAdmin()) return true;
        final Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (route == null || !ACCOUNT_ROUTE.equals(route.getId())) return true;
        return HttpMethod.GET.equals(exchange.getRequest().getMethod())
            && isOwnAccount(exchange.getRequest().getPath().pathWithinApplication(), who.idAccount());
    }

    /** true só para exatamente /accounts/{idAccount}. */
    static boolean isOwnAccount(PathContainer path, String idAccount) {
        final List<PathContainer.PathSegment> segments = path.elements().stream()
            .filter(PathContainer.PathSegment.class::isInstance)
            .map(PathContainer.PathSegment.class::cast)
            .filter(s -> !s.value().isEmpty())
            .toList();
        return segments.size() == 2
            && segments.stream().allMatch(s -> s.parameters().isEmpty())
            && "accounts".equals(segments.get(0).valueToMatch())
            && idAccount != null
            && idAccount.equals(segments.get(1).valueToMatch());
    }

}
