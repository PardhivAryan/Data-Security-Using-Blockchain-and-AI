from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select, cast, String
import json
import uuid

from app.db.session import get_db
from app.api.deps import get_current_user
from app.core.security import decode_access_token
from app.core.rbac import require_roles
from app.models import User, Role, VideoSession, VideoSessionStatus
from app.services import log_event, create_block

router = APIRouter(prefix="/video", tags=["video"])

ROOMS: dict[str, set[WebSocket]] = {}


@router.post("/sessions")
def create_room(patient_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_roles(user, {Role.DOCTOR})

    patient = db.execute(
        select(User)
        .where(cast(User.id, String) == str(patient_id))
        .where(User.role == Role.PATIENT)
        .limit(1)
    ).scalar_one_or_none()

    if not patient:
        raise HTTPException(status_code=400, detail="Invalid patient_id")

    room_id = uuid.uuid4().hex
    session = VideoSession(
        room_id=room_id,
        patient_id=patient.id,
        doctor_id=user.id,
        status=VideoSessionStatus.ACTIVE,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    create_block(
        db,
        {
            "event": "VIDEO_SESSION_CREATED",
            "room_id": room_id,
            "patient_id": str(patient.id),
            "doctor_id": str(user.id),
        },
    )

    return {"room_id": room_id}


def _get_ws_token(websocket: WebSocket) -> str | None:
    return websocket.query_params.get("token")


def _auth_ws_user(token: str | None) -> dict | None:
    if not token:
        return None
    return decode_access_token(token)


@router.websocket("/ws/{room_id}")
async def ws_signaling(websocket: WebSocket, room_id: str):
    token = _get_ws_token(websocket)
    payload = _auth_ws_user(token)
    if not payload or "sub" not in payload:
        await websocket.close(code=4401)
        return

    user_id = str(payload["sub"])
    db: Session = next(get_db())

    try:
        vs = db.execute(select(VideoSession).where(VideoSession.room_id == room_id)).scalar_one_or_none()
        if not vs or vs.status != VideoSessionStatus.ACTIVE:
            await websocket.close(code=4404)
            return

        allowed_ids = {str(vs.doctor_id), str(vs.patient_id)}
        if user_id not in allowed_ids:
            await websocket.close(code=4403)
            return

        await websocket.accept()
        ROOMS.setdefault(room_id, set()).add(websocket)

        log_event(
            db,
            user_id,
            "VIDEO_WS_CONNECTED",
            "INFO",
            None,
            websocket.headers.get("user-agent"),
            {"room_id": room_id},
        )

        try:
            while True:
                msg = await websocket.receive_text()
                for ws in list(ROOMS.get(room_id, set())):
                    if ws is websocket:
                        continue
                    try:
                        await ws.send_text(msg)
                    except Exception:
                        ROOMS.get(room_id, set()).discard(ws)
        except WebSocketDisconnect:
            pass
        finally:
            peers = [ws for ws in list(ROOMS.get(room_id, set())) if ws is not websocket]
            for peer in peers:
                try:
                    await peer.send_text(json.dumps({"type": "peer_left"}))
                except Exception:
                    pass

            ROOMS.get(room_id, set()).discard(websocket)
            if room_id in ROOMS and not ROOMS[room_id]:
                ROOMS.pop(room_id, None)

            log_event(
                db,
                user_id,
                "VIDEO_WS_DISCONNECTED",
                "INFO",
                None,
                websocket.headers.get("user-agent"),
                {"room_id": room_id},
            )
    finally:
        db.close()