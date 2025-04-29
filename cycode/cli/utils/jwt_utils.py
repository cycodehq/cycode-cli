from typing import Optional

import jwt

_JWT_PAYLOAD_POSSIBLE_USER_ID_FIELD_NAMES = ('userId', 'internalId', 'token-user-id')


def get_user_and_tenant_ids_from_access_token(access_token: str) -> tuple[Optional[str], Optional[str]]:
    payload = jwt.decode(access_token, options={'verify_signature': False})

    user_id = None
    for field in _JWT_PAYLOAD_POSSIBLE_USER_ID_FIELD_NAMES:
        user_id = payload.get(field)
        if user_id:
            break

    tenant_id = payload.get('tenantId')

    return user_id, tenant_id
