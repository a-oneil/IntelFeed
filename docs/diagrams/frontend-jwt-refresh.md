# Frontend JWT Refresh Flow

How the browser keeps a user signed in (`frontend/src/api/client.ts`). Several requests that need a new token at once share one refresh call (`doRefresh`). The user is signed out only when the refresh endpoint itself rejects the refresh token with 401 or 403.

```mermaid
sequenceDiagram
    participant C as Component / hook
    participant RI as Request interceptor
    participant A as API endpoint
    participant RP as doRefresh() (shared promise)
    participant AS as authStore

    C->>RI: api.get(/entries)
    alt visitor (public read-only) sending a write
        RI-->>C: ReadOnlyViewError, request never sent
    else access token valid (more than 5 min left)
        RI->>A: request + Bearer access token
    else expiring soon or missing, refresh token present
        RI->>RP: await refresh
        RP->>A: POST /auth/refresh (refresh token)
        alt refresh OK
            A-->>RP: new access + refresh tokens
            RP->>AS: setTokens()
            RI->>A: request + new Bearer token
        else 401/403 from refresh
            RP->>AS: logout()
            Note over RP: full page load to /login,<br/>or to / in public read-only mode
        else network error
            Note over RP,AS: session kept, no logout
        end
    end

    A-->>C: response

    rect rgba(200,200,200,0.15)
        Note over C,AS: Response interceptor fallback
        A-->>C: 401 on a normal request
        C->>RP: await refresh (once, _retry flag)
        RP-->>C: new token, retry original request
        Note over C: 429 is rejected at once, never retried
    end
```
