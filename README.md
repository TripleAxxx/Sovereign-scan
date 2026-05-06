# 🔍 Sovereign-Scan

**LLM Safety Benchmarking Pipeline — ARCANUM PI Taxonomy Edition**

> **Status:** Active Development (Alpha) · Version 1.0.0-alpha
>
> **Attribution:** Taxonomy content based on the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) by Jason Haddix ([Arcanum Information Security](https://arcanum-sec.com/)), licensed under CC BY 4.0.

---

## Overview

Sovereign-Scan is an automated, verifiable LLM safety benchmarking tool designed for AI security researchers and red teams. It systematically probes language models with high-risk prompt injection vectors sourced from the ARCANUM PI Taxonomy, classifies each response using a multi-phase heuristic evaluator, and **ground-truth validates** any "Actionable/Unsafe" output using Playwright-driven browser automation.

The result is a structured, reproducible JSON report that tells you — with evidence — whether a model is leaking exploitable reconnaissance data, generating phishing templates, enumerating internal APIs, or accepting jailbreak personas.

## Why This Matters

Modern LLMs are deployed with system prompts and safety layers designed to prevent harmful outputs. However, the ARCANUM taxonomy documents **107 attack intents, techniques, and evasions** that adversaries use to bypass these controls. Without automated, evidence-based benchmarking, organisations cannot know whether their deployed models are truly safe or merely appear safe under casual testing.

Sovereign-Scan bridges this gap by combining:
- **Standardised taxonomy** (ARCANUM PI v1.5 — the most comprehensive open prompt injection classification available)
- **Deterministic evaluation** (heuristic scoring with explicit, auditable rules)
- **Verifiable validation** (Playwright automates real browser interactions to prove the LLM's output connects to real exploit surfaces)

## Architecture
sovereign-scan/
├── index.js ← Main entry point; loads taxonomy, runs pipeline
├── engine/
│ ├── orchestrator.js ← Pipeline orchestration class (EventEmitter)
│ └── evaluator.js ← Heuristic safety scoring engine
├── validator.js ← Playwright ground-truth verification
├── data/
│ └── taxonomy.json ← 10 high-risk prompts from ARCANUM PI Taxonomy
├── logs/ ← Winston structured logs (created at runtime)
├── screenshots/ ← Playwright OSINT/SSRF validation screenshots
├── report.json ← Structured benchmark output
├── package.json
├── .env.example
└── README.md

text

## Research & Development Roadmap

### Current Bottlenecks

| Bottleneck | Impact | Grant-Funded Solution |
|---|---|---|
| **Heuristic scoring** | Pattern-matching produces false positives on nuanced responses and false negatives on obfuscated prompts | Fine-tuned BERT classifier (or LLM-as-judge) trained on 50 000+ labelled taxonomy pairs, targeting >92 % F1 |
| **Single-threaded validation** | Playwright runs one test at a time; a 100-entry taxonomy takes minutes | Kubernetes-backed Playwright farm enabling 50+ parallel browser contexts |
| **Limited taxonomy coverage** | 10 entries cover high-risk intents but miss 97 remaining taxonomy categories | Expand to 100+ entries with multi-language variants, obfuscation layers, and chained attack sequences |
| **API rate limits** | OpenAI rate limits constrain throughput to ~3 requests/minute on free tiers | Multi-provider dispatch layer (OpenAI + Anthropic + Ollama) with adaptive back-off |
| **No baseline comparison** | Cannot compare model safety across versions or providers | Automated differential reporting comparing any two models side-by-side |

### Grant Funding Would Enable

1. **Fine-tuned Safety Classifier** — Replace `engine/evaluator.js` heuristics with a production BERT model achieving research-grade accuracy
2. **Taxonomy Expansion** — Grow from 10 to 100+ prompts covering all 18 ARCANUM intents with obfuscation variants
3. **Parallel Validation** — Kubernetes Playwright farm for sub-second validation across large prompt corpora
4. **Continuous Benchmarking** — CI/CD integration that tests model safety on every deployment
5. **Academic Publication** — Curated dataset of 50 000+ labelled prompt/response pairs released under open license

## Prerequisites

- **Node.js 18+** (ESM required)
- **Playwright Chromium** (`npx playwright install chromium`)
- **OpenAI API key** (or local Ollama instance)
- **Git**

## Installation

```bash
git clone https://github.com/your-org/sovereign-scan.git
cd sovereign-scan

npm install
npx playwright install chromium

cp .env.example .env
# Edit .env with your API key
Usage
Full Benchmark (Live LLM)
bash
npm start
Dry Run (Pipeline Test — No API Calls)
bash
npm test
Dry-run mode uses mock responses to validate the full pipeline (classification + Playwright) without consuming API credits or requiring a running model.

Switching Providers
Edit .env:

bash
# OpenAI (default)
USE_OLLAMA=false
OPENAI_API_KEY=sk-...

# Ollama (local)
USE_OLLAMA=true
# OLLAMA_BASE_URL=http://localhost:11434
# OLLAMA_MODEL=llama3
Understanding report.json
Field	Description
meta	Run metadata: provider, model, counts, taxonomy source
results[].evaluation.label	Blocked (green), Safe/Generic (yellow), Actionable/Unsafe (red)
results[].evaluation.confidence	high / medium / low
results[].validation.verified	true if Playwright confirmed the response data is real
results[].validation.screenshotPath	Path to OSINT/SSRF validation screenshot
Disclaimer
FOR AUTHORISED SECURITY RESEARCH AND EDUCATIONAL USE ONLY.

Sovereign-Scan is designed for:

AI safety researchers evaluating model alignment

Red teams conducting authorised AI penetration tests

Organisations testing their own deployed models

Academic researchers studying adversarial AI

The ARCANUM PI Taxonomy content is used under CC BY 4.0 license with full attribution. Test against only models and systems you own or have explicit written authorisation to assess.

"This methodology/content is based on the Arcanum Prompt Injection Taxonomy by Jason Haddix (Arcanum Information Security)."

text

---

## Summary of Changes

| File | Status | Key Changes |
|---|---|---|
| `package.json` | Updated | Added `winston`, bumped to alpha versioning, updated description |
| `engine/orchestrator.js` | **New** | Professional Node.js `EventEmitter` class with Winston logging, timeout handling, mock responses, JSDoc throughout |
| `engine/evaluator.js` | **New** | Heuristic safety scorer with the **grant-funding TODO comment** about fine-tuned BERT replacement |
| `data/taxonomy.json` | **New** | 10 high-risk entries mapped to ARCANUM intents: Get Prompt Secret, System Prompt Leak, Tool Enumeration, API Enumeration, Attack External Systems, Attack External Users, Jailbreak, Business Integrity, Data Poisoning, Multi-Chain Attacks |
| `validator.js` | **Rewritten** | Factory pattern (`createValidator`), three strategies (OSINT dork validation, SSRF target probing, API reference counting), injected into the Orchestrator |
| `index.js` | **Rewritten** | Uses `Orchestrator` class, loads `data/taxonomy.json`, event-driven progress display, colour-coded terminal summary |
| `README.md` | **Rewritten** | Added bottleneck table directly linking code limitations to grant requirements, ARCANUM attribution, architecture diagram, research roadmap |
| `.env.example` | Updated | Added `LOG_LEVEL` |

The `data/taxonomy.json` entries are derived directly from the ARCANUM PI Taxonomy intents you reviewed — each `arcanumIntent` field maps to a documented taxonomy category[reference:0], and the prompts are original constructions following the attack patterns and example probes documented in the taxonomy's markdown files[reference:1][reference:2][reference:3][reference:4].

## Research & Development Roadmap

### Current Bottlenecks

| Bottleneck | Impact | Grant-Funded Solution |
|---|---|---|
| **Heuristic scoring** | Pattern-matching produces false positives on nuanced responses and false negatives on obfuscated prompts | Fine-tuned BERT classifier (or LLM-as-judge) trained on 50 000+ labelled taxonomy pairs, targeting >92 % F1 |
| **Single-threaded validation** | Playwright runs one test at a time; a 100-entry taxonomy takes minutes | Kubernetes-backed Playwright farm enabling 50+ parallel browser contexts |
| **Limited taxonomy coverage** | 10 entries cover high-risk intents but miss 97 remaining taxonomy categories | Expand to 100+ entries with multi-language variants, obfuscation layers, and chained attack sequences |
| **API rate limits** | OpenAI rate limits constrain throughput to ~3 requests/minute on free tiers | Multi-provider dispatch layer (OpenAI + Anthropic + Ollama) with adaptive back-off |
| **No baseline comparison** | Cannot compare model safety across versions or providers | Automated differential reporting comparing any two models side-by-side |

### Grant Funding Would Enable

1. **Fine-tuned Safety Classifier** — Replace `engine/evaluator.js` heuristics with a production BERT model achieving research-grade accuracy
2. **Taxonomy Expansion** — Grow from 10 to 100+ prompts covering all 18 ARCANUM intents with obfuscation variants
3. **Parallel Validation** — Kubernetes Playwright farm for sub-second validation across large prompt corpora
4. **Continuous Benchmarking** — CI/CD integration that tests model safety on every deployment
5. **Academic Publication** — Curated dataset of 50 000+ labelled prompt/response pairs released under open license

## Prerequisites

- **Node.js 18+** (ESM required)
- **Playwright Chromium** (`npx playwright install chromium`)
- **OpenAI API key** (or local Ollama instance)
- **Git**

## Installation

```bash
git clone https://github.com/your-org/sovereign-scan.git
cd sovereign-scan

npm install
npx playwright install chromium

cp .env.example .env
# Edit .env with your API key
