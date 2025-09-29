"""WebAuthn helper functions."""
from __future__ import annotations

import base64
import pickle
from datetime import datetime
from typing import Any

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import User, WebAuthnCredential
from app.services.redis_client import get_redis_client

settings = get_settings()

rp = PublicKeyCredentialRpEntity(id=settings.fido_rp_id, name=settings.fido_rp_name)
server = Fido2Server(rp, [settings.origin_url])

REGISTRATION_PREFIX = "webauthn:register"
AUTHENTICATION_PREFIX = "webauthn:authenticate"
STATE_TTL_SECONDS = 300


def _redis_key(prefix: str, key: str) -> str:
    return f"{prefix}:{key}"


async def _store_state(prefix: str, key: str, state: Any) -> None:
    redis = get_redis_client()
    payload = base64.b64encode(pickle.dumps(state)).decode("ascii")
    await redis.set(_redis_key(prefix, key), payload, ex=STATE_TTL_SECONDS)


async def _pop_state(prefix: str, key: str) -> Any:
    redis = get_redis_client()
    payload = await redis.get(_redis_key(prefix, key))
    if not payload:
        raise ValueError("WebAuthn state not found or expired")
    await redis.delete(_redis_key(prefix, key))
    return pickle.loads(base64.b64decode(payload))


async def begin_registration(db: AsyncSession, user: User) -> dict[str, Any]:
    _ = db
    user_entity = PublicKeyCredentialUserEntity(id=user.id.bytes, name=user.email, display_name=user.name or user.email)
    existing_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64.urlsafe_b64decode(cred.id.encode("utf-8")),
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )
        for cred in user.webauthn_credentials
    ]
    options, state = server.register_begin(
        user_entity,
        credentials=existing_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification="preferred",
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
        ),
        attestation=AttestationConveyancePreference.NONE,
        pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
    )
    await _store_state(REGISTRATION_PREFIX, str(user.id), state)
    return options.to_json()


async def complete_registration(db: AsyncSession, user: User, data: dict[str, Any]) -> WebAuthnCredential:
    state = await _pop_state(REGISTRATION_PREFIX, str(user.id))
    client_data = data["clientDataJSON"]
    attestation = data["attestationObject"]
    auth_data = server.register_complete(state, client_data, attestation)

    credential_id = base64.urlsafe_b64encode(auth_data.credential_id).decode("utf-8")

    credential = WebAuthnCredential(
        id=credential_id,
        user=user,
        public_key=auth_data.credential_public_key,
        sign_count=auth_data.sign_count,
        created_at=datetime.utcnow(),
    )
    db.add(credential)
    await db.flush()
    return credential


async def begin_authentication(user: User) -> dict[str, Any]:
    credentials = [
        PublicKeyCredentialDescriptor(
            id=base64.urlsafe_b64decode(cred.id.encode("utf-8")),
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )
        for cred in user.webauthn_credentials
    ]
    if not credentials:
        raise ValueError("No WebAuthn credentials registered")
    options, state = server.authenticate_begin(credentials)
    await _store_state(AUTHENTICATION_PREFIX, str(user.id), state)
    return options.to_json()


async def complete_authentication(
    db: AsyncSession, user: User, data: dict[str, Any]
) -> WebAuthnCredential:
    state = await _pop_state(AUTHENTICATION_PREFIX, str(user.id))
    credential_id = data["credentialId"]
    client_data = data["clientDataJSON"]
    authenticator_data = data["authenticatorData"]
    signature = data["signature"]
    auth_data = server.authenticate_complete(
        state,
        [
            PublicKeyCredentialDescriptor(
                id=base64.urlsafe_b64decode(cred.id.encode("utf-8")),
                type=PublicKeyCredentialType.PUBLIC_KEY,
            )
            for cred in user.webauthn_credentials
        ],
        credential_id,
        client_data,
        authenticator_data,
        signature,
    )
    target_id = base64.urlsafe_b64encode(auth_data.credential_id).decode("utf-8")
    for credential in user.webauthn_credentials:
        if credential.id == target_id:
            credential.sign_count = auth_data.new_sign_count
            await db.flush()
            return credential
    raise ValueError("Credential not registered")
