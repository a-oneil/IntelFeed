# Frontend JWT Refresh Flow

Sequence of token handling in `frontend/src/api/client.ts`. Concurrent refresh
attempts are deduplicated through a single shared promise (`doRefresh`), and a
hard logout happens only when the refresh endpoint itself rejects the refresh
token with 401/403.

```mermaid
sequenceDiagram
    participant C as Component / hook
    participant RI as Request interceptor
    participant A as API endpoint
    participant RP as doRefresh() (shared promise)
    participant AS as authStore

    C->>RI: api.get(/entries)
    alt access token valid (>5 min to exp)
        RI->>A: request + Bearer access token
    else expiring soon or missing
        RI->>RP: await refresh
        RP->>A: POST /auth/refresh (refresh token)
        alt refresh OK
            A-->>RP: new access + refresh tokens
            RP->>AS: setTokens()
            RI->>A: request + new Bearer token
        else 401/403 from refresh
            RP->>AS: logout() (hard logout)
        else network error
            Note over RP,AS: session kept — no logout
        end
    end

    A-->>C: response

    rect rgba(200,200,200,0.15)
        Note over C,AS: Response interceptor fallback
        A-->>C: 401 on a normal request
        C->>RP: await refresh (once, _retry flag)
        RP-->>C: new token → retry original request
        Note over C: 429 is rejected immediately, never retried
    end
```
