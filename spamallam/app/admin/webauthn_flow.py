"""FIDO2 WebAuthn registration + authentication (py_webauthn)."""
from __future__ import annotations

import base64
import json
from typing import Any

from fastapi import HTTPException, Request
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ..store import users as users_store
from . import security


def registration_options(username: str) -> tuple[str, str]:
    """Returns (options_json, sealed_challenge)."""
    user = users_store.get_user(username)
    exclude = [
        PublicKeyCredentialDescriptor(id=users_store.unb64url(c["id"]))
        for c in (user or {}).get("credentials", [])
    ]
    options = generate_registration_options(
        rp_id=security.rp_id(),
        rp_name="SpamAllam Admin",
        user_id=username.encode(),
        user_name=username,
        user_display_name=(user or {}).get("display", username),
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    sealed = security.seal_challenge(options.challenge, f"reg:{username}")
    return options_to_json(options), sealed


def verify_registration(request: Request, username: str, body: dict[str, Any],
                        label: str) -> None:
    challenge = security.open_challenge(body.get("sealed", ""), f"reg:{username}")
    try:
        verification = verify_registration_response(
            credential=body.get("credential"),
            expected_challenge=challenge,
            expected_rp_id=security.rp_id(),
            expected_origin=security.expected_origin(request),
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"passkey registration failed: {exc}") from exc
    users_store.add_credential(
        username,
        users_store.b64url(verification.credential_id),
        base64.b64encode(verification.credential_public_key).decode(),
        verification.sign_count,
        label,
    )


def authentication_options(username: str | None = None) -> tuple[str, str]:
    """Returns (options_json, sealed_challenge). With username=None a
    discoverable-credential (usernameless) flow is offered."""
    allow = []
    if username:
        user = users_store.get_user(username) or {}
        allow = [
            PublicKeyCredentialDescriptor(id=users_store.unb64url(c["id"]))
            for c in user.get("credentials", [])
        ]
    options = generate_authentication_options(
        rp_id=security.rp_id(),
        allow_credentials=allow or None,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    sealed = security.seal_challenge(options.challenge, "auth")
    return options_to_json(options), sealed


def verify_authentication(request: Request, body: dict[str, Any]) -> str:
    """Verify an assertion; returns the authenticated username."""
    challenge = security.open_challenge(body.get("sealed", ""), "auth")
    credential = body.get("credential") or {}
    raw_id = credential.get("rawId") or credential.get("id") or ""
    if isinstance(credential, str):
        credential_dict = json.loads(credential)
        raw_id = credential_dict.get("rawId") or credential_dict.get("id") or ""

    found = users_store.find_credential(raw_id)
    if found is None:
        raise HTTPException(status_code=400, detail="unknown passkey")
    username, cred = found

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=security.rp_id(),
            expected_origin=security.expected_origin(request),
            credential_public_key=base64.b64decode(cred["public_key"]),
            credential_current_sign_count=int(cred.get("sign_count", 0)),
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"passkey authentication failed: {exc}") from exc

    users_store.update_sign_count(username, cred["id"], verification.new_sign_count)
    return username
