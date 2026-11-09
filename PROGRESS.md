# Project Progress

| Phase | Focus | Target | Done |
|-------|-------|--------|------|
| 1 | Plan and set up environment | Days 1-3 | ☐ |
| 2 | Build the lab | Weeks 1-2 | ☐ |
| 3 | Simulate attacks and capture data | Weeks 2-3 | ☐ |
| 4 | Write detections | Weeks 3-4 | ☐ |
| 5 | Document and write-ups | Weeks 4-5 | ☐ |
| 6 | Publish to GitHub and polish | Weeks 5-6 | ☐ |

## Final checklist
- [ ] Lab runs and logs reach the SIEM
- [ ] At least 5 attacks simulated and PCAPs saved
- [ ] Each rule tested, with proof and ATT&CK mapping
- [ ] 3+ investigation reports written
- [ ] README complete with diagram and screenshots
- [ ] `python scripts/secrets_check.py` returns clean
- [ ] LICENSE, topics and description added
- [ ] Repo pinned and shared on LinkedIn

## Publish commands
```bash
git init -b main
git add .
git commit -m "Initial commit: lab scaffold, rules, scripts, docs"
git remote add origin https://github.com/YOUR-USERNAME/home-soc-detection-lab.git
git push -u origin main
```
Suggested topics: `cybersecurity` `suricata` `sigma` `mitre-attack` `soc` `blue-team` `zeek` `detection-engineering`
