from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import os
from starlette.middleware.base import BaseHTTPMiddleware 
from starlette.requests import Request as StarletteRequest 
from starlette.responses import Response as StarletteResponse 
from typing import Awaitable, Callable

from datetime import datetime, timezone

from aws_data_fetcher import get_live_eks_data

load_dotenv()

app = FastAPI(title="EKS Dashboard (Live Data)")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

class CurrentTimeMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: StarletteRequest, call_next: Callable[[StarletteRequest], Awaitable[StarletteResponse]]
    ) -> StarletteResponse:
        request.state.now = datetime.now(timezone.utc)
        response = await call_next(request)
        return response

app.add_middleware(CurrentTimeMiddleware)


@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request): 
    """
    Serves the main dashboard page with live EKS data.
    """
    print("Fetching live EKS data for dashboard...")
    dashboard_data = get_live_eks_data()
    print(f"Fetched {len(dashboard_data['clusters'])} clusters.")
    if dashboard_data.get("errors"):
        print(f"Errors during data fetch: {dashboard_data['errors']}")

    context = {
        "request": request, 
        "quick_info": dashboard_data["quick_info"],
        "clusters": dashboard_data["clusters"],
        "clusters_by_version_count": dashboard_data["clusters_by_version_count"],
        "clusters_by_region_count": dashboard_data["clusters_by_region_count"],
        "fetch_errors": dashboard_data.get("errors", [])
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.get("/api/dashboard-data")
async def get_dashboard_api_data():
    """
    An optional API endpoint for live EKS data.
    """
    dashboard_data = get_live_eks_data()
    return dashboard_data


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

