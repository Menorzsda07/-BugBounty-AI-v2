# Current status

- YNAB: active non-authenticated analysis. No validated vulnerability yet.
- iRobot: scope prepared; targeted authorization/API workstream next.
- Ibotta: separate workstream prepared.
- Titan/HackerOne: untouched by Bugcrowd Hunter work.

YNAB observations so far:
- staging login enforces same-origin redirect to `/users/sign_in`.
- no arbitrary-origin credentialed CORS observed on tested roots.
- guessed API/schema paths on `staging-api.bany.dev` consistently return 401.
- current JS bundles reference source maps, but referenced `.map` resources return 404.
- current DOM-sink review mostly resolves to third-party libraries/framework internals; no proven attacker-controlled source-to-executable sink yet.
- authenticated BOLA/IDOR/OAuth impact testing requires controlled test accounts rather than third-party data.
