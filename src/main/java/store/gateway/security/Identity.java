package store.gateway.security;

/**
 * Quem fez a requisição, segundo o Auth (POST /auth/solve): id da conta e papel.
 * Token sem papel (emitido antes do RBAC) vale USER: na dúvida, o menor acesso.
 */
public record Identity(String idAccount, String role) {

    public static final String USER = "USER";
    public static final String ADMIN = "ADMIN";

    public Identity {
        role = role == null || role.isBlank() ? USER : role;
    }

    public boolean isAdmin() {
        return ADMIN.equals(role);
    }

}
