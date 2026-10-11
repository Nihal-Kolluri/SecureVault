# SecureVault

SecureVault is an encrypted digital vault application designed with robust security standards, cryptographic protections, and an audited lifecycle.

## Phase Progress Checklist

| Phase | Name | Branch | Status | Release Tag |
| :---: | :--- | :--- | :---: | :---: |
| **Phase 0** | Project Setup & Scaffold | `main` | ✅ Completed | `v0.0.0` |
| **Phase 1** | Authentication & Identity | `phase-1-auth` | ✅ Completed | `v0.1.0` |
| **Phase 2** | Multi-Factor Authentication (MFA) | `phase-2-mfa` | ✅ Completed | `v0.2.0` |
| **Phase 3** | Gateway, RBAC & Rate Limiting | `phase-3-gateway-rbac` | ✅ Completed | `v0.3.0` |
| **Phase 4** | Audit Logging & Monitoring | `phase-4-audit-logging` | ⏳ Pending | - |
| **Phase 5** | Frontend / User Interface | `phase-5-ui` | ⏳ Pending | - |
| **Phase 6** | End-to-End Integration & API | `phase-6-e2e-api` | ⏳ Pending | - |
| **Phase 7** | Deployment & Infrastructure | `phase-7-infra` | ⏳ Pending | - |
| **Phase 8** | Red Team Vulnerability Assessment | `vulnerable` (isolated) | ⏳ Pending | - |
| **Phase 9** | Blue Team Hardening & Verification | `phase-9-hardening` | ⏳ Pending | - |

## Security & Contribution Guidelines

- **Zero Secrets Policy**: Never commit credentials, private keys, `.env` files, or production secrets to Git. Only `.env.example` is tracked.
- **Pre-commit Scanning**: Pre-commit secret scanning is enforced automatically via `.githooks/pre-commit` and `scripts/secret-scan.js`.
- **Commit Convention**: Small, atomic commits using Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `security:`).
- **Branching Workflow**:
  - Feature branches: `phase-N-short-name`
  - Red Team: `vulnerable` (never merged into `main`)
  - Blue Team: `phase-9-hardening` (branched from `main`, one commit per fix referencing finding ID)

## Getting Started

### Prerequisites
- Node.js (v18+)
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/Nihal-Kolluri/SecureVault.git
cd SecureVault

# Configure git hooks
git config core.hooksPath .githooks

# Set up environment variables
cp .env.example .env
```

### Running Tests
```bash
npm test
```

### Running Secret Scan
```bash
npm run scan:secrets
```
