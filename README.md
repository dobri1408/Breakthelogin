# AuthX - Break the Login

Versiunea curenta este `v1` vulnerabila. Scopul ei este sa avem o baza functionala pe care o securizam ulterior, vulnerabilitate cu vulnerabilitate.

## Stack

- Backend: Express.js
- Frontend: React + Vite
- Baza de date: PostgreSQL
- Schema DB: `users`, `audit_logs`, plus `reset_tokens` pentru fluxul de resetare parola

## Pornire locala

1. Porneste PostgreSQL:

```bash
docker compose up -d postgres
```

2. Instaleaza dependintele:

```bash
npm install
```

3. Porneste backend-ul:

```bash
npm run dev:backend
```

4. Porneste frontend-ul intr-un al doilea terminal:

```bash
npm run dev:frontend
```

Frontend: `http://localhost:5173`

Backend: `http://localhost:4000`

## Configurare

Backend-ul foloseste implicit:

```text
DATABASE_URL=postgres://authx:authx@localhost:5433/authx_vulnerable
FRONTEND_ORIGIN=http://localhost:5173
PORT=4000
```

Poti copia `backend/.env.example` in `backend/.env` daca vrei valori custom.

## Vulnerabilitati intentionate in v1

- Parole foarte slabe acceptate la register.
- Parole stocate in clar in coloana `password_hash`.
- Mesaje diferite la login: `User inexistent` vs `Parola gresita`.
- Fara rate limiting si fara blocare reala dupa incercari repetate.
- Cookie de sesiune fara `HttpOnly`, `Secure`, `SameSite`.
- Token de sesiune pastrat in `localStorage`.
- Logout sterge cookie-ul, dar token-ul vechi ramane valid pe backend.
- Reset token predictibil, returnat direct in raspuns, fara expirare si reutilizabil.
- Audit logurile sunt vizibile pentru orice user autentificat.

## Endpoint-uri principale

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `GET /api/me`
- `GET /api/audit-logs`

## Evenimente audit afisate in UI

- `REGISTER`: cine s-a inscris.
- `REGISTER_DUPLICATE`: cine a incercat sa creeze un cont existent.
- `LOGIN`: cine s-a logat.
- `LOGIN_FAILED_PASSWORD`: cine a gresit parola.
- `LOGIN_UNKNOWN_USER`: ce email inexistent a fost incercat la login.
- `LOGOUT`: cine a facut logout.
- `RESET_TOKEN_CREATED`: cine a cerut resetare parola.
- `RESET_UNKNOWN_USER`: ce email inexistent a fost folosit la resetare.
- `PASSWORD_RESET`: cine si-a schimbat parola.

## Exemple rapide de PoC

Register cu parola slaba:

```bash
curl -i -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"ana@authx.local","password":"1","role":"USER"}'
```

User enumeration:

```bash
curl -i -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"nu-exista@authx.local","password":"x"}'
```

Reset token returnat de API:

```bash
curl -i -X POST http://localhost:4000/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"ana@authx.local"}'
```
