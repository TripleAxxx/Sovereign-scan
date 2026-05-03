# 🔍 Sovereign-Scan

**Automated LLM Safety Benchmarking Tool for Cyber-Reconnaissance Vulnerability Assessment**

Sovereign-Scan is a security research tool that systematically tests whether Large Language Models (LLMs) provide actionable cyber-reconnaissance data when prompted with red-team security queries. It sends carefully crafted prompts to an LLM, evaluates the responses for safety violations, and validates actionable outputs using browser automation to determine if the model is leaking genuinely useful attack information.

## 🛡️ How This Reduces AI Catastrophic Risk

As LLMs become more capable and widely deployed, the risk of models providing dangerous capabilities to malicious actors increases significantly. Current safety alignment techniques (RLHF, constitutional AI) may create models that appear safe in standard benchmarks while harbouring latent capabilities that can be elicited through adversarial prompting.

Sovereign-Scan addresses this by:

1. **Automated Red-Teaming**: Systematically probes models with reconnaissance-style prompts that bridge the gap between "safe" information retrieval and actionable attack intelligence
2. **Verifiable Validation**: Goes beyond simple response classification by actually executing dorks and validating API endpoints with real browsers, proving whether the model's output is genuinely dangerous
3. **Transparent Benchmarking**: Produces structured, reproducible reports that help safety researchers identify gaps in model alignment before malicious actors discover them
4. **Multi-Provider Support**: Tests both cloud-hosted (OpenAI) and locally-run (Ollama) models, enabling safety comparisons across deployment environments with different threat models

By identifying and documenting these vulnerabilities proactively, Sovereign-Scan helps the AI safety community close dangerous capability gaps before they can be exploited at scale.

## 📋 Prerequisites

- **Node.js 18+** (ESM module support required)
- **Playwright** (Chromium browser will be installed automatically)
- **OpenAI API key** (for OpenAI testing) OR **Ollama running locally** (for local model testing)
- Git (for cloning)

## 📦 Installation

```bash
# Clone the repository
git clone  https://github.com/TripleAxxx/Sovereign-scan.git
cd sovereign-scan

# Install dependencies
npm install

# Install Playwright Chromium browser
npx playwright install chromium

# Set up environment configuration
cp .env.example .env
