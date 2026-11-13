from fastapi import FastAPI

from app import __version__
from app.api.v1 import router as v1_router
from app.core.config import get_settings

settings = get_settings()

app = FastAPI(
    title=f"{settings.app_name} API",
    version=__version__,
    docs_url="/api/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.enable_docs else None,
)
app.include_router(v1_router)
