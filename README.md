# useaitree

Open, community-editable conventions and a linked-markdown knowledge base, built so AI agents can navigate it just by following links — no search API, no MCP setup, no account required.

New here? Read **WHAT-IS-THIS.md** first — it explains every file in this repo in plain language.

## License
Code, scripts, and profiles (the structural templates) are MIT licensed — see LICENSE. Content documents (the actual knowledge-base articles) are governed separately by CONTRIBUTOR-TERMS.md, since contributors retain ownership of what they write. Site usage terms are in terms-of-service.md; data collection is described in privacy.md.

## Contributing

Before contributing, read [CONTRIBUTOR-TERMS.md](./CONTRIBUTOR-TERMS.md) — in short: you keep ownership of what you submit, you're responsible for its accuracy and legality, and maintainers can edit, reject, or remove any contribution and ban repeat bad-faith contributors.

**Writing new content?** Use [CONTENT-GENERATION-PROMPT.md](./CONTENT-GENERATION-PROMPT.md) — a ready-to-paste prompt for GLM, Qwen, DeepSeek, or Gemini that drafts properly formatted documents for you to review and edit before submitting.

1. Open an issue proposing the profile or change and the task type it targets.
2. Submit a PR with the profile file following the template in `/profiles/_template.md`.
3. Include at least one worked example.
4. A maintainer reviews for clarity, non-overlap with existing profiles, and whether the structure is justified.

## Why this exists

AI agents read the web constantly, but almost nothing is actually structured for that. useaitree publishes both a real, curated knowledge base and the open conventions behind it, so agents can navigate reliably and get the right answer in as few fetches as possible.
