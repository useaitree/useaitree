# useaitree Content Generation Prompt

Copy everything below the line into GLM, Qwen, DeepSeek, or Gemini. Replace the two bracketed placeholders with your actual topic before sending.

---

You are writing documentation for an AI-agent-readable knowledge base called useaitree. Every file must follow this exact structure — do not deviate from it.

**Topic area**: [INSERT YOUR NICHE, e.g. "home espresso machine troubleshooting"]
**Number of documents to generate**: [INSERT NUMBER, e.g. 20]

For each document, output it in this exact format:

```
---
type: Troubleshooting Guide
title: [specific, searchable title]
description: [one sentence, what this fixes]
tags: [3-5 relevant lowercase tags, comma separated]
profile: troubleshooting-v1
timestamp: 2026-07-22T00:00:00Z
---

# Symptom
[The exact observable problem, described the way a real person would describe it]

# Likely causes
1. [most common cause first]
2. [second most likely]
3. [third most likely]

# Fix
1. [imperative, one action per step]
2. [next step]
3. [continue as needed]

# Limitations
[Cases where this fix does NOT apply, or different environments where it behaves differently. This section is mandatory — do not skip it or leave it generic.]

# Links
[Leave this section with placeholder text: "LINKS-TBD" — I will fill in real cross-links myself before publishing.]
```

Rules:
- Each document covers exactly ONE specific problem. Do not combine multiple issues into one file.
- Be concrete and specific — no vague filler sentences.
- The Limitations section must name a real edge case, not a generic disclaimer.
- Do not invent brand names, product models, or statistics you're not certain about.
- Generate [NUMBER] separate documents, ordered from most common to most niche.
- Output each document separated by a line containing only: `---NEXT DOCUMENT---`

After generating, I will personally review, fact-check, and edit every document before publishing.
