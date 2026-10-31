# Public deployment — Render

## One-service deployment
The Docker service serves the static dashboard and FastAPI API from one origin.
The browser calls relative `/api/...` paths, so no Vite server or CORS setup is needed.

## Deploy
1. Push the complete `agentshield-from-scratch` directory to a GitHub repository.
2. In Render, choose **New → Blueprint** and select that repository.
3. Render reads `render.yaml`; confirm creation of `agentshield-x-redline`.
4. Wait for the Docker build and `/health` health check.
5. Open the generated `https://<service-name>.onrender.com` URL.

## Admin key
Render generates `AGENTSHIELD_ADMIN_KEY` and `AGENTSHIELD_SIGNING_KEY`.
Keep both private. The dashboard asks for the admin key when a user attempts
management changes (policy/agent/tool changes and approval decisions). The key
is stored only in that browser tab's session storage. Do not put it in GitHub,
frontend source, screenshots or public documentation.

## Demo limitations
- The free Render service uses ephemeral storage at `/tmp/agentshield-data`.
  Demo policies, agents, approvals and audit history can reset when the service
  restarts or redeploys. Use a persistent disk (paid plan) or managed database
  before relying on long-term records.
- Gateway tool calls and scenario runs are synthetic simulations. They do not
  execute real external tools.
- This is a hackathon demonstration, not a production security gateway. Before
  production use, add proper user authentication/roles, rate limiting, CSRF
  protections for browser sessions, structured persistent storage, monitoring,
  backups and a security review.
