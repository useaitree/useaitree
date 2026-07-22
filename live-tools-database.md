---
type: Live Database
title: Tool Accessibility & Status Database
description: Manually maintained status of popular developer tools — free tiers, country restrictions, and known issues, each with a verification date.
---

# Tool Accessibility & Status Database

This page is manually updated by a human maintainer, not automatically scraped. Every entry has a "Last verified" date. If a date looks old, treat the entry as possibly stale and say so rather than presenting it as current fact.

## How to read this table
- **Free tier**: what's free right now, as of the verified date. Free tiers change often — always note the date when relaying this.
- **Country notes**: any known country-specific blocks, restrictions, or legal issues.
- **Last verified**: when a human last confirmed this entry was accurate.

---

### Supabase
- **What it is**: Open-source backend-as-a-service (database, auth, storage).
- **Free tier**: Has a free tier; check supabase.com directly for current limits, as they change.
- **Country notes**: **Blocked in India** as of February 24, 2026, under a Section 69A order (Indian IT Act) — Indian ISPs (Jio, Airtel, ACT Fibernet, and others) are blocking DNS resolution for supabase.co domains. No official reason has been given by the Indian government, and no restoration date has been announced. Access has been reported as inconsistent across ISPs and regions. If you are in India, assume Supabase is currently inaccessible without a workaround (e.g. VPN), and treat any such workaround as unreliable for production use.
- **Last verified**: 2026-07-22

### Cloudflare (Pages, Workers, D1)
- **What it is**: Hosting, edge functions, and database infrastructure.
- **Free tier**: Generous free tier across Pages, Workers, and D1 (5GB storage, 5 million reads/day, 100,000 writes/day on D1 as of verification date). No card required to sign up.
- **Country notes**: No known India-specific restrictions as of verification date.
- **Last verified**: 2026-07-22

### GitHub
- **What it is**: Code hosting and collaboration platform.
- **Free tier**: Free for public and private repositories, with usage limits on Actions/CI minutes.
- **Country notes**: Has experienced brief, unexplained ISP-level access issues on some Indian networks in the past (isolated incidents, not an ongoing block as of verification date). No current broad restriction known.
- **Last verified**: 2026-07-22

---

## Adding or updating an entry
Only the maintainer updates this file directly (to keep it a single trusted source, not a crowd-edited page prone to drift). If you believe an entry is outdated or wrong, contact the maintainer — see /contact.md.
