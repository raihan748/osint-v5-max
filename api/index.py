from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import asyncio

app = FastAPI(title="OSINT Suite API")

# Allow CORS since frontend will call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    platforms: list[dict] # expects list of dicts with 'n' (name) and 'u' (url with {u} already replaced if needed, or we replace here)

class PlatformResult(BaseModel):
    name: str
    status: str # "found", "not_found", "error"
    url: str

async def check_platform(client: httpx.AsyncClient, platform: dict, target: str) -> PlatformResult:
    # URL pattern should have {u} replaced with target. If not, replace it.
    url = platform['u'].replace('{u}', target)
    name = platform['n']
    
    # If the platform requires special API check (like GitHub)
    if 'api' in platform:
        api_url = platform['api'].replace('{u}', target)
        try:
            response = await client.get(api_url, timeout=10.0)
            if response.status_code == 200:
                return PlatformResult(name=name, status="found", url=url)
            elif response.status_code == 404:
                return PlatformResult(name=name, status="not_found", url=url)
            else:
                 return PlatformResult(name=name, status="error", url=url)
        except Exception:
            return PlatformResult(name=name, status="error", url=url)
            
    # Standard Web Check
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        response = await client.get(url, headers=headers, timeout=10.0, follow_redirects=True)
        # Very basic heuristic for standard platforms: 200 OK often means profile exists, 404 means it doesn't.
        # Note: In a real Sherlock-style script, we would need specific error messages per platform to avoid false positives.
        # For Vercel demo, we use status codes.
        if response.status_code == 200:
            return PlatformResult(name=name, status="found", url=url)
        elif response.status_code == 404:
            return PlatformResult(name=name, status="not_found", url=url)
        else:
             return PlatformResult(name=name, status="error", url=url)
             
    except httpx.RequestError:
        return PlatformResult(name=name, status="error", url=url)
    except Exception:
         return PlatformResult(name=name, status="error", url=url)

@app.post("/api/scan", response_model=list[PlatformResult])
async def scan_platforms(req: ScanRequest):
    """
    Scans a chunk of platforms asynchronously.
    Designed to return quickly to avoid Vercel's 10s timeout.
    """
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [check_platform(client, plat, req.target) for plat in req.platforms]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Clean up exceptions if any snuck through gather
        cleaned_results = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                cleaned_results.append(PlatformResult(name=req.platforms[i]['n'], status="error", url=req.platforms[i]['u'].replace('{u}', req.target)))
            else:
                cleaned_results.append(res)
                
        return cleaned_results

@app.get("/api/health")
def health_check():
    return {"status": "ok", "message": "OSINT API is running on Vercel Python Runtime"}
