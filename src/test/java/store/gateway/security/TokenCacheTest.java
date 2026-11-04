package store.gateway.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class TokenCacheTest {

    private static String jwtWithExp(long exp) {
        final Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        final String header = enc.encodeToString("{\"alg\":\"HS256\"}".getBytes(StandardCharsets.UTF_8));
        final String payload = enc.encodeToString(
            ("{\"jti\":\"42\",\"sub\":\"Ana\",\"exp\":" + exp + "}").getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".assinatura";
    }

    private final TokenCache cache = new TokenCache(
        mock(ReactiveStringRedisTemplate.class), new SimpleMeterRegistry(), true, Duration.ofMinutes(5));

    @Test
    void chaveEhHashENaoOToken() {
        final String jwt = jwtWithExp(1);
        final String key = TokenCache.key(jwt);
        assertTrue(key.startsWith("gateway:token:"));
        assertFalse(key.contains(jwt));
        assertEquals(TokenCache.key(jwt), key);
        assertEquals("gateway:token:".length() + 64, key.length());
    }

    @Test
    void leExpDoPayload() {
        assertEquals(1_900_000_000L, TokenCache.expiration(jwtWithExp(1_900_000_000L)));
        assertNull(TokenCache.expiration("lixo"));
        assertNull(TokenCache.expiration("a.%%%.c"));
    }

    @Test
    void ttlNuncaPassaDoExp() {
        final Instant now = Instant.ofEpochSecond(1_000_000);
        // expira em 60 s: TTL = 60 s, e não os 5 min configurados
        assertEquals(Duration.ofSeconds(60), cache.effectiveTtl(jwtWithExp(1_000_060), now));
        // expira em 1 h: TTL = 5 min
        assertEquals(Duration.ofMinutes(5), cache.effectiveTtl(jwtWithExp(1_003_600), now));
        // já expirado: TTL negativo (não grava)
        assertTrue(cache.effectiveTtl(jwtWithExp(999_000), now).isNegative());
        // sem exp: usa o configurado
        assertEquals(Duration.ofMinutes(5), cache.effectiveTtl("a.b.c", now));
    }

}
