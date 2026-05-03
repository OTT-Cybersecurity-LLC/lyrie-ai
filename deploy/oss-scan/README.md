# Lyrie OSS-Scan Service

Free public repository scanner. Powers `lyrie.ai/research/scan`.

## Deploy

```bash
cd deploy/oss-scan
docker-compose up -d
```

## API

```bash
# Scan a public repo
curl -X POST http://localhost:3020/scan \
  -H "Content-Type: application/json" \
  -d '{"repoUrl": "https://github.com/org/repo"}'

# Health check
curl http://localhost:3020/health

# Rate limit info
curl http://localhost:3020/limits
```

## Abuse prevention
- HTTPS URLs only
- GitHub / GitLab / Bitbucket / Codeberg only
- Max repo size: 50MB
- Rate limit: 1 scan per IP per 5 minutes
- Shield check on URL before cloning (SSRF prevention)
- No credentials allowed in URL
