from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    # App
    app_name: str = Field(default="Data Security Using Blockchain and AI", alias="APP_NAME")
    debug: bool = Field(default=True, alias="DEBUG")

    # API
    api_prefix: str = Field(default="/api", alias="API_PREFIX")
    cors_origins: list[str] = Field(default=["http://localhost:8000"], alias="CORS_ORIGINS")

    # Database
    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/medsec_ai",
        alias="DATABASE_URL",
    )

    # JWT
    jwt_secret: str = Field(default="CHANGE_ME_TO_A_LONG_RANDOM_SECRET", alias="JWT_SECRET")
    jwt_alg: str = Field(default="HS256", alias="JWT_ALG")

    # Keep your old env name working
    jwt_exp_minutes: int = Field(default=480, alias="JWT_EXP_MINUTES")

    # ✅ NEW: what your security.py expects (supports your .env ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token_expire_minutes: int = Field(default=60, alias="ACCESS_TOKEN_EXPIRE_MINUTES")

    # WebAuthn / RP
    rp_id: str = Field(default="localhost", alias="RP_ID")
    rp_name: str = Field(default="MedSec AI", alias="RP_NAME")
    expected_origin: str = Field(default="http://localhost:8000", alias="EXPECTED_ORIGIN")

    # Storage
    storage_dir: str = Field(default="storage", alias="STORAGE_DIR")
    encrypted_dir: str = Field(default="storage/encrypted", alias="ENCRYPTED_DIR")
    quarantined_dir: str = Field(default="storage/quarantined", alias="QUARANTINED_DIR")

    # ✅ Uses your .env FERNET_KEY
    fernet_key: str = Field(default="ggu5BKx08md6bo_c-_ko6xqRPs4ULlRqOmC8PW2N7fs=", alias="FERNET_KEY")

    # ML
    risk_model_path: str = Field(default="app/ml/artifacts/risk_model.pkl", alias="RISK_MODEL_PATH")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

# ✅ Optional: If ACCESS_TOKEN_EXPIRE_MINUTES not provided, fall back to JWT_EXP_MINUTES
# This keeps your project working even if you only set JWT_EXP_MINUTES.
if not getattr(settings, "access_token_expire_minutes", None):
    settings.access_token_expire_minutes = settings.jwt_exp_minutes