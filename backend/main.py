from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import uuid
import httpx
import ssl
import re
import gzip
import zlib
from typing import Optional
from bs4 import BeautifulSoup
import logging

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("preview_proxy")

class PreviewRequest(BaseModel):
    domain: str
    ip: str

    @validator('domain')
    def validate_domain(cls, v):
        domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(domain_pattern, v, re.IGNORECASE):
            raise ValueError('Invalid domain format')
        return v.lower()

    @validator('ip')
    def validate_ip(cls, v):
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, v):
            raise ValueError('Invalid IP address format')
        return v

preview_links = {}

@app.post("/api/preview-link")
async def generate_preview_link(req: PreviewRequest):
    if not req.domain or not req.ip:
        raise HTTPException(status_code=400, detail="Domain and IP required")
    preview_id = str(uuid.uuid4())[:8]
    preview_links[preview_id] = {"domain": req.domain, "ip": req.ip}
    return {"previewUrl": f"/preview/{preview_id}/"}

@app.get("/api/preview/{preview_id}/status")
async def check_preview_status(preview_id: str):
    data = preview_links.get(preview_id)
    if not data:
        raise HTTPException(status_code=404, detail="Preview link not found")
    return {"exists": True, "domain": data["domain"], "ip": data["ip"]}

def rewrite_css_urls(css: str, prefix: str) -> str:
    # Rewrite all url(/...) not already /preview/
    return re.sub(r'url\(\s*[\'"]?/(?!preview/)', f'url({prefix}', css)

@app.api_route("/preview/{preview_id}/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def preview_proxy(preview_id: str, full_path: str = "", request: Request = None):
    data = preview_links.get(preview_id)
    if not data:
        raise HTTPException(status_code=404, detail="Preview link not found")
    domain = data["domain"]
    ip = data["ip"]
    query_string = str(request.query_params) if request.query_params else ""
    if query_string:
        full_path = f"{full_path}?{query_string}" if full_path else f"?{query_string}"
    for scheme in ["https", "http"]:
        target_url = f"{scheme}://{ip}/{full_path}"
        headers = {}
        for key, value in request.headers.items():
            if key.lower() not in [
                "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailers", "upgrade", "transfer-encoding", "host", "accept-encoding"
            ]:
                headers[key] = value
        headers["host"] = domain
        headers["accept-encoding"] = "identity"
        try:
            body = None
            if request.method in ("POST", "PUT", "PATCH"):
                body = await request.body()
            ssl_ctx = None
            if scheme == "https":
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            timeout = httpx.Timeout(15.0, connect=10.0)
            async with httpx.AsyncClient(
                verify=ssl_ctx,
                timeout=timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.request(
                    request.method,
                    target_url,
                    headers=headers,
                    content=body,
                )
                raw_content = await resp.aread()
                content_encoding = resp.headers.get("content-encoding", "").lower().strip()
                if content_encoding and content_encoding != "identity":
                    try:
                        if "gzip" in content_encoding or "x-gzip" in content_encoding:
                            content = gzip.decompress(raw_content)
                        elif "deflate" in content_encoding:
                            try:
                                content = zlib.decompress(raw_content)
                            except zlib.error:
                                content = zlib.decompress(raw_content, -zlib.MAX_WBITS)
                        elif "br" in content_encoding:
                            try:
                                import brotli
                                content = brotli.decompress(raw_content)
                            except (ImportError, Exception):
                                content = raw_content
                        else:
                            content = raw_content
                    except Exception:
                        content = raw_content
                else:
                    content = raw_content
                status_code = resp.status_code
                response_headers_dict = dict(resp.headers)
            excluded_headers = [
                "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
                "trailers", "upgrade", "transfer-encoding", "content-encoding", "content-length",
                "x-frame-options", "frame-ancestors",
                "content-security-policy", "content-security-policy-report-only"
            ]
            response_headers = {}
            for key, value in response_headers_dict.items():
                key_lower = key.lower()
                if key_lower not in excluded_headers:
                    response_headers[key] = value
            if "content-encoding" in response_headers:
                del response_headers["content-encoding"]
            content_type = response_headers_dict.get("content-type")
            preview_prefix = f"/preview/{preview_id}/"
            charset = resp.encoding if getattr(resp, "encoding", None) else "utf-8"
            if content_type:
                lower_type = content_type.lower()
                if "text/html" in lower_type:
                    try:
                        html_text = content.decode(charset, errors="ignore")
                        soup = BeautifulSoup(html_text, "html.parser")
                        base_tag = soup.find("base")
                        if base_tag:
                            base_tag.extract()
                        for tag in soup.find_all(True):
                            for attr in ["src", "href", "action", "poster", "data", "content"]:
                                if attr in tag.attrs:
                                    url = tag.attrs[attr]
                                    if isinstance(url, str):
                                        try:
                                            # Protocol-relative URLs (e.g., //example.com)
                                            if url.startswith("//"):
                                                tag.attrs[attr] = "https:" + url
                                                continue
                                            # Absolute paths (e.g., /images/logo.png)
                                            if url.startswith("/") and not url.startswith("/preview/"):
                                                tag.attrs[attr] = preview_prefix + url.lstrip("/")
                                                continue
                                            # Avoid rewriting non-URL attributes like width
                                            if attr not in ["src", "href", "action", "poster", "data", "content"]:
                                                continue
                                            # Relative paths (e.g., images/logo.png)
                                            if not url.startswith("http") and not url.startswith("/"):
                                                tag.attrs[attr] = preview_prefix + url
                                                continue
                                            # Ensure query parameters are preserved
                                            if "?" in url:
                                                base_url, query = url.split("?", 1)
                                                if base_url.startswith("/"):
                                                    tag.attrs[attr] = preview_prefix + base_url.lstrip("/") + "?" + query
                                        except Exception as e:
                                            logger.warning(f"Failed to rewrite URL {url}: {str(e)}")
                        for style_tag in soup.find_all("style"):
                            if style_tag.string:
                                try:
                                    style_tag.string = rewrite_css_urls(style_tag.string, preview_prefix)
                                except Exception as e:
                                    logger.warning(f"Failed to rewrite CSS in <style>: {str(e)}")
                        for tag in soup.find_all(style=True):
                            try:
                                tag['style'] = rewrite_css_urls(tag['style'], preview_prefix)
                            except Exception as e:
                                logger.warning(f"Failed to rewrite inline style: {str(e)}")
                        content = soup.encode(charset)
                    except Exception as ex:
                        logger.error(f"Error processing HTML content: {str(ex)}")
                elif "text/css" in lower_type:
                    try:
                        css_text = content.decode(charset, errors="ignore")
                        content = rewrite_css_urls(css_text, preview_prefix).encode(charset)
                    except Exception as e:
                        logger.error(f"Error processing CSS content: {str(e)}")
            response_headers["content-length"] = str(len(content))
            return Response(
                content=content,
                status_code=status_code,
                headers=response_headers,
                media_type=content_type
            )
        except httpx.TimeoutException:
            logger.error(f"Timeout while connecting to {target_url}")
            if scheme == "https":
                continue
            raise HTTPException(
                status_code=504,
                detail=f"Connection timeout. The server at {ip} is not responding. Please verify the IP address is correct."
            )
        except httpx.ConnectError:
            logger.error(f"Connection error while connecting to {target_url}")
            if scheme == "https":
                continue
            raise HTTPException(
                status_code=502,
                detail=f"Cannot connect to {ip}. Please verify the IP address is correct and the server is accessible."
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP status error {e.response.status_code} while connecting to {target_url}")
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"Server returned error: {e.response.status_code}"
            )
        except Exception as e:
            logger.exception(f"Unexpected error while connecting to {target_url}: {str(e)}")
            if scheme == "https":
                continue
            raise HTTPException(
                status_code=502,
                detail=f"Error connecting to {ip}: {str(e)}"
            )
    raise HTTPException(
        status_code=502,
        detail=f"Could not connect to {domain} at {ip}. Please verify the IP address is correct and the server is accessible."
    )

@app.get("/")
async def root():
    return {"message": "HostPreview API"}

