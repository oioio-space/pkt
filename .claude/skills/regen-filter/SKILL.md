---
name: regen-filter
description: Régénère windivert/filter/grammar.go depuis grammar.peg via pigeon (go generate). À invoquer après toute modification de grammar.peg.
disable-model-invocation: true
---

```bash
# Vérifier que pigeon est installé
which pigeon || go install github.com/mna/pigeon@latest

# Régénérer le parser
go generate ./windivert/filter/...

# Vérifier que ça compile
GOOS=windows go build ./windivert/filter/...

echo "grammar.go régénéré. Vérifiez les tests: GOOS=windows go test ./windivert/filter/..."
```
