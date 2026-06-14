# Node Authentication Backend

Express authentication API for RecallOps.

```powershell
npm install
npm run dev
```

Production:

```powershell
$env:NODE_ENV="production"
npm start
```

Configure `.env` from `.env.example`. The JWT secret must match `backend/.env`.
