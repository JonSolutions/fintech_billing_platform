from __future__ import annotations
import hashlib
import hmac
from typing import Dict, Any

async def verify_stripe_webhook_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    expected = hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)

def build_webhook_ack(event_id: str, verified: bool) -> Dict[str, Any]:
    if not event_id:
        raise ValueError('event_id is required')
    return {'event_id': event_id, 'verified': verified, 'status': 200}
