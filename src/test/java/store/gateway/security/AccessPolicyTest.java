package store.gateway.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.http.server.PathContainer;

class AccessPolicyTest {

    private static boolean own(String path, String id) {
        return AccessPolicy.isOwnAccount(PathContainer.parsePath(path), id);
    }

    @Test
    void soExatamenteAPropriaConta() {
        assertTrue(own("/accounts/42", "42"));
        assertTrue(own("/accounts/42/", "42"));
        assertTrue(own("/accounts/%34%32", "42"));   // "42" codificado
        assertFalse(own("/accounts/43", "42"));
        assertFalse(own("/accounts", "42"));
        assertFalse(own("/accounts/42/x", "42"));
        assertFalse(own("/accounts/42;x=1", "42"));
        assertFalse(own("/accounts/42", null));
        assertFalse(own("/outra/42", "42"));
    }

    @Test
    void papelNuloOuVazioViraUser() {
        assertFalse(new Identity("42", null).isAdmin());
        assertFalse(new Identity("42", "").isAdmin());
        assertFalse(new Identity("42", "admin").isAdmin()); // sensível a maiúsculas
        assertTrue(new Identity("42", "ADMIN").isAdmin());
    }

}
