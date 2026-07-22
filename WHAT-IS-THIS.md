# What is every file in this folder?

You don't need to understand code to use this. Here's what each thing does, in plain terms.

## The site itself (what visitors and AI agents see)
- **index.html** — the homepage.
- **llms.txt** — a map of the site written for AI agents specifically. First thing an AI reads when told "use useaitree."
- **manifest.json** — the same map, in a format a computer program can read directly. The interactive graph (below) reads this too.
- **graph.html** — an interactive visual graph of the whole site, for humans to click through. Builds itself automatically from manifest.json.
- **robots.txt** — tells search engines and AI crawlers they're welcome to read this site.
- **sitemap.xml** — a list of every page, for Google to index.
- **privacy.md** — what data is collected and why.
- **terms-of-service.md** — the rules for anyone using the site.
- **contact.md** — your email and phone number.

## Skills (how the AI decides what it needs before answering)
- **skills/index.md** — the AI checks this first to decide if it needs anything special before answering.
- **skills/tool-accessibility-check.md** — tells the AI to check the live tools database before answering any question about a specific tool/software.
- **skills/ask-country-first.md** — tells the AI to ask the user's country when the answer depends on it.
- **live-tools-database.md** — the actual data: which tools are free, blocked, or restricted where, each with a "last verified" date. YOU update this by hand — that's what keeps it accurate instead of relying on possibly-outdated AI knowledge.

## The engine (makes the site actually track visits and show you stats)
- **functions/_middleware.js** — the entire "brain." Runs automatically on every visit, logs everything, powers /dashboard and the /admin login. You don't edit this unless you want to change tracking behavior.
- **schema.sql** — one-time setup file. Paste its contents into Cloudflare's website once to create your storage tables.

## Maintainer area (only you can access this)
- **/admin** — sign-in page (not a file in this folder — a page the site generates). You log in with the email and password you set up in Cloudflare (see deployment instructions).
- **/dashboard** — all your stats, only visible once signed in.

## Rules and ownership (legal/business documents)
- **LICENSE** — code and templates here are free for anyone to reuse (MIT license).
- **CONTRIBUTOR-TERMS.md** — if someone else writes content, they own what they wrote; you can still edit or remove it if needed.
- **README.md** — the overview page GitHub shows first.

## Content-writing help
- **CONTENT-GENERATION-PROMPT.md** — paste into any AI chatbot to help draft new content pages.
- **profiles/troubleshooting-v1.md** — the exact structure every "how to fix X" page should follow.
- **profiles/_template.md** — blank version, for creating a new type of page.
- **ADDING-CONTENT.md** — checklist for what to update every time you add a page.
- **SOCIAL-POSTS.md** — ready-to-post announcements for X, Instagram, and LinkedIn.

## What you'll add yourself
Real content pages (the actual answers people/agents are looking for) aren't included yet. Use CONTENT-GENERATION-PROMPT.md to help write your first real topic.
