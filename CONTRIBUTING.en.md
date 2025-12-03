# 🤝 Contributing to AstraVault AI

Thank you for your interest in contributing to **AstraVault AI**.
This project is part of the BYLICKILABS technology suite and follows strict security and quality standards.

---

## 🧠 General Guidelines

- Write **clean, well-documented, and traceable code**.
- **Never commit sensitive data or API keys.**
- Follow **PEP8 and type-hinting** conventions.
- Run **all tests successfully** before submitting any Pull Request.

---

## ⚙️ Development Setup

```bash
git clone https://github.com/bylickilabs/AstraVaultAI.git

cd AstraVaultAI

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

---

## 🧩 Branching Strategy

| Branch | Purpose |
|--------|----------|
| `main` | Stable release builds |
| `develop` | Ongoing development |
| `feature/<name>` | New features |
| `fix/<name>` | Bug fixes |
| `security/<issue>` | Security updates |

---

## ✅ Pull Requests

1. Open or reference an existing issue.
2. Run local tests with `pytest`.
3. Use clear commit messages:
   ```
   [Feature] Added AI Anomaly Detection Module
   [Fix] Corrected file integrity validation
   ```
4. Provide a concise description of your changes.
5. All PRs are automatically analyzed by **GitHub CodeQL Security**.

---

## 📄 Code of Conduct

> All contributors must comply with the BYLICKILABS Code of Conduct.

---

## 📬 Contact

Questions about contributions or review processes:
**bylicki@mail.de**
