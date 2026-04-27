# Security regression (Queue / Ticketing / Payment)

Scripts défensifs pour vérifier les contrôles de sécurité suivants :

- Rejet des tokens modifiés
- Anti-replay (token one-time)
- Rate-limit effectif
- Idempotence paiement
- Refus session/device mismatch

## 1) Python (recommandé)

```bash
python3 security_regression.py \
  --base-url https://api.example.test \
  --access-token "$ACCESS_TOKEN" \
  --queue-token "$QUEUE_TOKEN" \
  --checkout-grant "$CHECKOUT_GRANT" \
  --session-id sess-123 \
  --device-id dev-abc
```

Variables d'environnement supportées :

- `BASE_URL`, `ACCESS_TOKEN`, `QUEUE_TOKEN`, `CHECKOUT_GRANT`
- `SESSION_ID`, `DEVICE_ID`, `EVENT_ID`, `ORDER_ID`, `AMOUNT`, `CURRENCY`
- `CHECKOUT_START_PATH`, `CHECKOUT_FINALIZE_PATH`, `RATE_LIMIT_PROBE_PATH`, `PAYMENT_CONFIRM_PATH`

Le script retourne un code non-zéro si une régression sécurité est détectée.

## 2) Postman/Newman

1. Importer `postman_security_collection.json`
2. Renseigner les variables de collection
3. Exécuter dans Postman ou via Newman

```bash
newman run postman_security_collection.json \
  --env-var base_url=https://api.example.test \
  --env-var access_token="$ACCESS_TOKEN" \
  --env-var queue_token="$QUEUE_TOKEN" \
  --env-var checkout_grant="$CHECKOUT_GRANT"
```

> Utiliser uniquement sur un environnement autorisé (staging/lab), jamais en production sans accord formel.
