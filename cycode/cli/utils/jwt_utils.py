from typing import Tuple

import jwt


def get_user_and_tenant_ids_from_access_token(access_token: str) -> Tuple[str, str]:
    payload = jwt.decode(access_token, options={'verify_signature': False})
    user_id = payload.get('userId')
    tenant_id = payload.get('tenantId')

    if not user_id or not tenant_id:
        raise ValueError('Invalid access token')

    return user_id, tenant_id
