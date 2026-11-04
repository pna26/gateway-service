package store.gateway.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import reactor.core.publisher.Mono;

/**
 * Bottleneck: cache (Redis).
 *
 * Sem cache, TODA requisição autenticada faz uma chamada HTTP ao Auth
 * (POST /auth/solve) para validar o JWT. Aqui guardamos no Redis o resultado
 * (hash do token -> id da conta) por alguns minutos, compartilhado entre todas
 * as réplicas do gateway. Assim o Auth só é chamado no primeiro acesso de cada
 * token (cache miss).
 *
 * Decisões:
 * - a chave é o SHA-256 do token, nunca o token em si;
 * - o TTL nunca passa do "exp" do JWT (token expirado não fica no cache);
 * - se o Redis cair, o gateway continua funcionando chamando o Auth (fail-open
 *   só do cache, a validação continua obrigatória).
 */
@Component
public class TokenCache {

    private static final Logger logger = LoggerFactory.getLogger(TokenCache.class);
    private static final String PREFIX = "gateway:token:";
    private static final Pattern EXP = Pattern.compile("\"exp\"\\s*:\\s*(\\d+)");

    private final ReactiveStringRedisTemplate redis;
    private final boolean enabled;
    private final Duration ttl;
    private final Counter hits;
    private final Counter misses;
    private final Counter errors;

    public TokenCache(
        ReactiveStringRedisTemplate redis,
        MeterRegistry registry,
        @Value("${store.gateway.cache.enabled:true}") boolean enabled,
        @Value("${store.gateway.cache.ttl:5m}") Duration ttl
    ) {
        this.redis = redis;
        this.enabled = enabled;
        this.ttl = ttl;
        this.hits = counter(registry, "hit");
        this.misses = counter(registry, "miss");
        this.errors = counter(registry, "error");
    }

    private static Counter counter(MeterRegistry registry, String result) {
        // hit = resolvido pelo Redis; miss = precisou chamar o Auth;
        // error = Redis fora (o gateway segue sem cache)
        return Counter.builder("gateway.token.cache")
            .description("Resolucao do token pelo cache Redis, por resultado (hit, miss, error)")
            .tag("result", result)
            .register(registry);
    }

    /** id da conta em cache para o token, ou vazio (miss, cache desligado ou Redis fora). */
    public Mono<String> get(String jwt) {
        if (!enabled) return Mono.empty();
        return redis.opsForValue().get(key(jwt))
            .doOnNext(id -> hits.increment())
            .switchIfEmpty(Mono.defer(() -> {
                misses.increment();
                return Mono.empty();
            }))
            .onErrorResume(e -> {
                errors.increment();
                logger.warn("redis indisponível, seguindo sem cache: {}", e.getMessage());
                return Mono.empty();
            });
    }

    /** guarda token -> id com TTL = min(ttl configurado, tempo até o exp do JWT). */
    public Mono<Void> put(String jwt, String idAccount) {
        if (!enabled) return Mono.empty();
        final Duration effective = effectiveTtl(jwt, Instant.now());
        if (effective.isZero() || effective.isNegative()) return Mono.empty();
        return redis.opsForValue().set(key(jwt), idAccount, effective)
            .then()
            .onErrorResume(e -> {
                errors.increment();
                logger.warn("não consegui gravar no redis: {}", e.getMessage());
                return Mono.empty();
            });
    }

    Duration effectiveTtl(String jwt, Instant now) {
        final Long exp = expiration(jwt);
        if (exp == null) return ttl;
        final Duration untilExp = Duration.between(now, Instant.ofEpochSecond(exp));
        return untilExp.compareTo(ttl) < 0 ? untilExp : ttl;
    }

    /** lê o "exp" do payload; o token já foi validado pelo Auth antes de chegar aqui. */
    static Long expiration(String jwt) {
        try {
            final String[] parts = jwt.split("\\.");
            if (parts.length < 2) return null;
            final String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            final Matcher m = EXP.matcher(payload);
            return m.find() ? Long.valueOf(m.group(1)) : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static String key(String jwt) {
        try {
            final byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(jwt.getBytes(StandardCharsets.UTF_8));
            return PREFIX + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
