"""统一错误响应：{"code": "...", "message": "..."}。"""
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class AppError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


def not_found(what: str = "资源") -> AppError:
    return AppError(404, "NOT_FOUND", f"{what}不存在")


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError):
        return JSONResponse(status_code=exc.status, content={"code": exc.code, "message": exc.message})

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(x) for x in first.get("loc", [])[1:])
        return JSONResponse(status_code=422, content={"code": "VALIDATION_ERROR",
                                                      "message": f"参数错误：{field} {first.get('msg', '')}".strip(),
                                                      "errors": exc.errors()})
