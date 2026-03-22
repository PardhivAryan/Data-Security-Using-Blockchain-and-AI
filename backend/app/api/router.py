from fastapi import APIRouter
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.records import router as records_router
from app.api.admin import router as admin_router
from app.api.risk import router as risk_router
from app.api.video import router as video_router

router = APIRouter()
router.include_router(health_router)
router.include_router(auth_router)
router.include_router(records_router)
router.include_router(admin_router)
router.include_router(risk_router)
router.include_router(video_router)