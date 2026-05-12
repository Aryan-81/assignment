"""
Application entry point and configuration for the FastAPI service.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.endpoints import router as certificate_router
from app.core.config import settings
from app.core.database import Base, engine


# APPLICATION LIFESPAN
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handle application startup and shutdown events.
    
    Startup:
        - Create database tables if they don't exist
    
    Shutdown:
        - Clean up resources (placeholder for future use)
    """
    # Startup logic
    Base.metadata.create_all(bind=engine)
    
    yield
    
    # Shutdown logic
    engine.dispose()


# APPLICATION FACTORY
def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title=settings.APP_NAME,
        description="API for checking expiry of SSL certificate",
        version=settings.APP_VERSION,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # CORS Configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Exception Handlers
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        """
        Global exception handler for unhandled exceptions.
        """
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An unexpected error occurred",
                "error": str(exc) if settings.DEBUG else None,
            },
        )

    # Include Routers
    app.include_router(
        certificate_router,
        # prefix="/api/v1", 
    )

    return app


# APPLICATION INSTANCE
app = create_application()