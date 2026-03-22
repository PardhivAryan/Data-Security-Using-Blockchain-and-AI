from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    verify_registration_response,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from app.core.config import settings


def start_registration_options(user_id_bytes: bytes, user_name: str, exclude_cred_ids: list[bytes]) -> tuple[str, bytes]:
    opts = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.rp_name,
        user_id=user_id_bytes,
        user_name=user_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c) for c in exclude_cred_ids],
    )
    return options_to_json(opts), opts.challenge


def finish_registration(credential: dict, expected_challenge_b64: str):
    return verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge_b64),
        expected_origin=settings.expected_origin,
        expected_rp_id=settings.rp_id,
        require_user_verification=True,
    )


def start_authentication_options(allow_cred_ids: list[bytes]) -> tuple[str, bytes]:
    opts = generate_authentication_options(
        rp_id=settings.rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c) for c in allow_cred_ids],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(opts), opts.challenge


def finish_authentication(
    credential: dict,
    expected_challenge_b64: str,
    credential_public_key_b64: str,
    credential_current_sign_count: int,
):
    return verify_authentication_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge_b64),
        expected_origin=settings.expected_origin,
        expected_rp_id=settings.rp_id,
        credential_public_key=base64url_to_bytes(credential_public_key_b64),
        credential_current_sign_count=credential_current_sign_count,
        require_user_verification=True,
    )


def b64e(b: bytes) -> str:
    return bytes_to_base64url(b)


def b64d(s: str) -> bytes:
    return base64url_to_bytes(s)