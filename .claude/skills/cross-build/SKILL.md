---
name: cross-build
description: Compile et vérifie le workspace pkt pour Linux et Windows. Lance go vet sur tous les modules.
disable-model-invocation: true
---

Exécute dans le répertoire racine du workspace:

```bash
echo "=== Linux build ===" && GOOS=linux go build ./... && echo "OK"
echo "=== Windows build ===" && GOOS=windows go build ./... && echo "OK"
echo "=== go vet ===" && go vet ./... && echo "OK"
echo "=== go work sync ===" && go work sync && echo "OK"
```

Rapporte les erreurs clairement avec le module concerné.
