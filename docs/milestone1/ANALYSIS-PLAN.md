# Milestone 1 — Analysis plan

## Deliverables checklist

- [x] Local lab stack (`./cs up`)
- [x] Integration verify (`./cs verify` — 16 checks)
- [x] Auth gate (`./cs gate` — §4.5)
- [x] L2 engage (`./cs set-level L2` + `./cs verify-l2`)
- [x] Intelligence plane (`http://127.0.0.1:18090/`)
- [x] Activity monitor (`./cs monitor`)
- [x] Three arms (base, adaptive, p2)
- [x] Red-team profiles (`./cs redteam`)
- [x] A/A validation (`./cs aa-validate`)
- [ ] ≥4 weeks three-arm collection (run `./cs collect` daily)
- [ ] Human realism study (optional)
- [ ] Final thesis chapter with survival analysis

## Commands

```bash
./cs milestone          # full milestone 1 verification
./cs up                 # Arm A
./cs up-adaptive        # Arm B
./cs up-p2              # Arm C
./cs redteam            # scripted profiles
./cs analyze            # write data/milestone1-report.json
./cs aa-validate        # exposure parity
```

## Demonstration script (viva)

1. `./cs verify` — lab healthy
2. `./cs monitor` — show actors + transitions
3. Open `http://127.0.0.1:18090/` — intelligence dashboard
4. `./cs redteam spray` — generate traffic, watch escalation on adaptive arm
5. `./cs analyze` — show arm comparison JSON
