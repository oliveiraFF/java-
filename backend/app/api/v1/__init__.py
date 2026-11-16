from fastapi import APIRouter

from app.api.v1 import admin, auth, detect, emails, health, mailboxes, stats, users

router = APIRouter(prefix="/api/v1")
for module in (health, auth, users, mailboxes, emails, detect, admin, stats):
    router.include_router(module.router)
