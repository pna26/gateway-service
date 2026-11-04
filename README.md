# gateway-service

API gateway da plataforma **pna26** (Spring Cloud Gateway / WebFlux, Java 25).

- Roteia `/auth/**`, `/accounts/**` e `/exchange/**` (e o apelido `/exchanges/**`).
- Exige o cookie `__store_jwt_token` em toda rota que não seja `POST /auth/register`,
  `POST /auth/login` ou `GET /auth/logout`; valida no Auth (`POST /auth/solve`) e repassa o id no
  header `id-account` (o `id-account` enviado pelo cliente é descartado).
- Cache do token no Redis, compartilhado entre as réplicas (chave = SHA-256 do JWT, TTL ≤ `exp`).
- `GET /health-check` responde o hostname da réplica; métricas em `/gateway/actuator/prometheus`.

Documentação completa: https://pna26.github.io/platform/servicos/gateway/

## Rodar

```bash
./mvnw verify                      # build + 20 testes
docker build -t gateway-service .  # depois do mvn package
```

A plataforma inteira (Nginx, gateway, auth, account, Redis, Postgres) sobe pelo
[pna26/platform](https://github.com/pna26/platform), onde este repositório é um submódulo.

## Variáveis

| Variável | Padrão |
|---|---|
| `AUTH_URI` / `ACCOUNT_URI` / `EXCHANGE_URI` | `http://auth:8080` / `http://account:8080` / `http://exchange:8080` |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` |
| `TOKEN_CACHE_ENABLED` / `TOKEN_CACHE_TTL` | `true` / `5m` |
| `AUTH_TIMEOUT` | `3s` |
| `CORS_ALLOWED_ORIGINS` | `http://localhost,http://localhost:3000,http://localhost:8080` |

## CI/CD

`.github/workflows/ci.yaml` chama o pipeline reutilizável
`pna26/platform/.github/workflows/service.yaml`: build e testes, Trivy (código e imagem), push
multi-arch para `ghcr.io/pna26/gateway-service` e deploy no EKS (`k8s/k8s.yaml`).
