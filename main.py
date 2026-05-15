from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.routes.verify_document import router as document_router
from app.schemas.document_verification import HealthResponse, RootResponse

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(
    title=settings.app_name,
    description="BitCheck Document Verification API.",
    version=settings.version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(document_router)
app.mount("/outputs", StaticFiles(directory=str(settings.output_dir)), name="outputs")


@app.get("/", response_model=RootResponse)
def root() -> RootResponse:
    return RootResponse(
        service=settings.app_name,
        status="running",
        version=settings.version,
    )


@app.get("/health")
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.version,
        ocr_available=False,
        qr_available=False,
        deepseek_available=settings.deepseek_available,
        model=settings.deepseek_model,
    )
