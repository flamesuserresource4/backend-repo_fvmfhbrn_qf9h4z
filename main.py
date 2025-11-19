import os
import re
import time
import hmac
import hashlib
import base64
from typing import Optional, Dict, Any

import requests
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None

app = FastAPI(title="Creator LeadGen & Redesign SaaS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Auth utilities (HMAC token)
# ---------------------------
SECRET = os.getenv("AUTH_SECRET", "dev_secret_change_me")
TOKEN_TTL = 60 * 60 * 24 * 7  # 7 days


def hash_password(password: str) -> str:
    salt = os.getenv("AUTH_SALT", "static_salt")
    return hashlib.sha256((salt + password).encode()).hexdigest()


def make_token(email: str) -> str:
    ts = str(int(time.time()))
    msg = f"{email}.{ts}".encode()
    sig = hmac.new(SECRET.encode(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(msg + b"." + sig).decode()


def verify_token(token: str) -> Optional[str]:
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        parts = raw.split(b".")
        if len(parts) != 3:
            return None
        email = parts[0].decode()
        ts = int(parts[1].decode())
        sig = parts[2]
        expected = hmac.new(SECRET.encode(), f"{email}.{ts}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(time.time()) - ts > TOKEN_TTL:
            return None
        return email
    except Exception:
        return None


def get_current_user(x_auth_token: Optional[str] = Header(default=None)) -> Optional[dict]:
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="Missing auth token")
    email = verify_token(x_auth_token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid auth token")
    user = db["saasuser"].find_one({"email": email}) if db else None
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["id"] = str(user.get("_id"))
    return user


def get_admin_user(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role", "user") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ---------------------------
# Startup bootstrap: promote configured email to admin if no admin exists
# ---------------------------
@app.on_event("startup")
def bootstrap_admin_on_startup():
    try:
        if db is None:
            return
        existing_admin = db["saasuser"].find_one({"role": "admin"})
        if existing_admin:
            return
        email = os.getenv("BOOTSTRAP_ADMIN_EMAIL")
        if not email:
            return
        user = db["saasuser"].find_one({"email": email})
        if user:
            db["saasuser"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "updated_at": time.time()}})
    except Exception:
        # Silent fail to avoid blocking startup
        pass


# ---------------------------
# Models
# ---------------------------
class SignupPayload(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


class SearchPayload(BaseModel):
    location: str
    category: str
    limit: int = 10


class AnalyzePayload(BaseModel):
    url: str


class ProposalPayload(BaseModel):
    url: str
    business_name: Optional[str] = None
    category: Optional[str] = None


class UpdatePlanPayload(BaseModel):
    email: EmailStr
    plan: str


class UpdateRolePayload(BaseModel):
    email: EmailStr
    role: str  # user | admin


# ---------------------------
# Auth endpoints
# ---------------------------
@app.post("/auth/signup")
def signup(payload: SignupPayload):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    existing = db["saasuser"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    doc = {
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "name": payload.name,
        "plan": "free",
        "role": "user",
    }
    create_document("saasuser", doc)
    token = make_token(payload.email)
    return {"token": token, "email": payload.email, "plan": "free", "role": "user"}


@app.post("/auth/login")
def login(payload: LoginPayload):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["saasuser"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = make_token(payload.email)
    return {"token": token, "email": payload.email, "plan": user.get("plan", "free"), "role": user.get("role", "user")}


@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return {"email": user.get("email"), "plan": user.get("plan", "free"), "role": user.get("role", "user")}


@app.post("/auth/bootstrap-admin")
def bootstrap_admin(user=Depends(get_current_user)):
    """
    Promote the current authenticated user to admin if no admin exists yet.
    Safe bootstrap to create the first admin.
    """
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    existing_admin = db["saasuser"].find_one({"role": "admin"})
    if existing_admin:
        raise HTTPException(status_code=403, detail="Admin already exists")
    db["saasuser"].update_one({"_id": user["_id"]}, {"$set": {"role": "admin", "updated_at": time.time()}})
    return {"ok": True, "role": "admin"}


# ---------------------------
# Local business search (OSM Nominatim)
# ---------------------------
CATEGORY_TAGS = {
    "restaurant": "amenity=restaurant",
    "dentist": "amenity=dentist",
    "salon": "shop=hairdresser",
    "cafe": "amenity=cafe",
    "bar": "amenity=bar",
    "bakery": "shop=bakery",
}


def nominatim_search(location: str, category: str, limit: int = 10):
    # Geocode location to lat/lon
    geo = requests.get(
        "https://nominatim.openstreetmap.org/search",
        params={"q": location, "format": "json", "limit": 1},
        headers={"User-Agent": "creator-saas/1.0"},
        timeout=15,
    ).json()
    if not geo:
        return []
    lat = geo[0]["lat"]
    lon = geo[0]["lon"]
    tag = CATEGORY_TAGS.get(category.lower(), "amenity=restaurant")

    # Overpass query for POIs near the location
    overpass_query = f"""
    [out:json][timeout:25];
    (
      node[{tag}](around:4000,{lat},{lon});
      way[{tag}](around:4000,{lat},{lon});
      relation[{tag}](around:4000,{lat},{lon});
    );
    out center {limit};
    """
    data = requests.post(
        "https://overpass-api.de/api/interpreter",
        data=overpass_query.encode("utf-8"),
        headers={"User-Agent": "creator-saas/1.0", "Content-Type": "text/plain"},
        timeout=30,
    ).json()
    results = []
    for el in data.get("elements", [])[:limit]:
        tags = el.get("tags", {})
        name = tags.get("name")
        if not name:
            continue
        website = tags.get("website") or tags.get("contact:website") or tags.get("url")
        addr = ", ".join(
            filter(
                None,
                [
                    tags.get("addr:street"),
                    tags.get("addr:housenumber"),
                    tags.get("addr:city"),
                ],
            )
        )
        results.append(
            {
                "name": name,
                "address": addr,
                "category": category,
                "website": website,
            }
        )
    return results


@app.post("/business/search")
def business_search(payload: SearchPayload, user=Depends(get_current_user)):
    items = nominatim_search(payload.location, payload.category, payload.limit)
    # Filter: must have website
    items = [b for b in items if b.get("website")]
    return {"results": items}


# ---------------------------
# Website analysis
# ---------------------------
CONTACT_RE = re.compile(r"(\+?\d[\d\s\-()]{6,}|[\w.+-]+@[\w.-]+)", re.I)


def fetch_html(url: str) -> str:
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = requests.get(url, headers={"User-Agent": "creator-saas/1.0"}, timeout=20)
        return r.text
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch: {e}")


def analyze_html(url: str, html: str) -> Dict[str, Any]:
    start = time.time()
    https = url.startswith("https://")
    soup = BeautifulSoup(html, "html.parser") if BeautifulSoup else None

    title = None
    meta_desc = None
    h1 = None
    h2 = []
    text_sample = ""
    has_viewport = False
    contact_present = False

    if soup:
        t = soup.find("title")
        title = t.text.strip() if t else None
        md = soup.find("meta", attrs={"name": "description"})
        meta_desc = md.get("content", "").strip() if md else None
        h1_tag = soup.find("h1")
        h1 = h1_tag.text.strip() if h1_tag else None
        h2 = [el.text.strip() for el in soup.find_all("h2")[:5]]
        has_viewport = soup.find("meta", attrs={"name": "viewport"}) is not None
        # collect body text sample
        texts = [t.get_text(" ", strip=True) for t in soup.find_all(["p", "li"])[:20]]
        text_sample = " ".join(texts)[:1000]
        contact_present = bool(CONTACT_RE.search(text_sample))

    score = 10
    issues = []
    if not https:
        score -= 2
        issues.append("Site is not using HTTPS")
    if not has_viewport:
        score -= 2
        issues.append("Missing responsive meta viewport")
    if not title or len(title) < 10:
        score -= 1
        issues.append("Weak or missing page title")
    if not meta_desc or len(meta_desc) < 40:
        score -= 1
        issues.append("Missing or short meta description")
    if not h1:
        score -= 1
        issues.append("Missing clear H1 headline")
    if not contact_present:
        score -= 2
        issues.append("No obvious contact info (phone/email)")

    dur = max(0.2, time.time() - start)

    recs = [
        "Enable HTTPS and configure redirects",
        "Add responsive meta viewport for mobile friendliness",
        "Write a clear, compelling H1 and page title",
        "Include a descriptive meta description (120–160 chars)",
        "Add visible phone/email and a strong call to action",
        "Organize content into clear sections (hero, services, about, CTA)",
    ]

    return {
        "url": url,
        "metrics": {
            "uses_https": https,
            "has_viewport_meta": has_viewport,
            "analysis_time_sec": round(dur, 2),
        },
        "title": title,
        "meta_description": meta_desc,
        "h1": h1,
        "h2": h2,
        "text_sample": text_sample,
        "score": max(1, min(10, score)),
        "issues": issues,
        "recommendations": recs,
    }


@app.post("/analyze")
def analyze(payload: AnalyzePayload, user=Depends(get_current_user)):
    html = fetch_html(payload.url)
    result = analyze_html(payload.url, html)
    # Persist minimal record
    doc = {
        "user_id": str(user["_id"]),
        "url": result["url"],
        "score": result["score"],
        "summary": "; ".join(result["issues"]) or "OK",
        "recommendations": result["recommendations"],
        "metrics": result["metrics"],
    }
    create_document("analysis", doc)
    return result


# ---------------------------
# Proposal generation (rule-based)
# ---------------------------

def generate_structure(data: Dict[str, Any], business_name: Optional[str] = None, category: Optional[str] = None):
    headline = data.get("h1") or data.get("title") or (business_name or "Your Business")
    sub = data.get("meta_description") or "Professional, modern website redesign focused on clarity and conversions."
    services_guess = [
        f"{category.title()} Services" if category else "Our Services",
        "About Us",
        "Contact",
    ]
    return {
        "hero": {
            "headline": headline,
            "subheadline": sub,
            "cta": {"label": "Get a Free Proposal", "href": "#contact"},
        },
        "about": {
            "title": "About",
            "body": f"{business_name or 'We'} provide quality service with a modern approach."
        },
        "services": {
            "title": "Services",
            "items": [{"title": s, "desc": f"Learn more about our {s.lower()}."} for s in services_guess],
        },
        "whyus": {
            "title": "Why Choose Us",
            "bullets": [
                "Clear value proposition",
                "Mobile-first, fast, and accessible",
                "Easy contact and booking",
            ],
        },
        "cta": {
            "title": "Ready to grow?",
            "subtitle": "Get a conversion-focused redesign today.",
            "button": {"label": "Request Proposal", "href": "#contact"},
        },
        "footer": {
            "copyright": f"© {time.gmtime().tm_year} {business_name or 'Your Business'}",
        },
    }


@app.post("/proposal")
def proposal(payload: ProposalPayload, user=Depends(get_current_user)):
    html = fetch_html(payload.url)
    analysis = analyze_html(payload.url, html)
    structure = generate_structure(analysis, payload.business_name, payload.category)
    # Persist
    doc = {
        "user_id": str(user["_id"]),
        "business_id": None,
        "structure": structure,
        "html_preview": None,
    }
    create_document("proposal", doc)
    return {"structure": structure}


class PreviewPayload(BaseModel):
    structure: Dict[str, Any]


def structure_to_html(structure: Dict[str, Any]) -> str:
    hero = structure.get("hero", {})
    about = structure.get("about", {})
    services = structure.get("services", {})
    why = structure.get("whyus", {})
    cta = structure.get("cta", {})
    footer = structure.get("footer", {})

    # Minimal Tailwind HTML (no external CSS required in preview context)
    return f"""
<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{hero.get('headline','Redesign Proposal')}</title>
  <script src=\"https://cdn.tailwindcss.com\"></script>
</head>
<body class=\"bg-slate-950 text-slate-100\">\n  <section class=\"px-6 py-20 text-center bg-gradient-to-b from-slate-900 to-slate-950\">\n    <h1 class=\"text-4xl md:text-6xl font-bold mb-4\">{hero.get('headline','')}</h1>\n    <p class=\"text-lg md:text-xl text-slate-300 max-w-2xl mx-auto\">{hero.get('subheadline','')}</p>\n    <a href=\"{hero.get('cta',{}).get('href','#contact')}\" class=\"inline-block mt-8 px-6 py-3 rounded-lg bg-blue-500 hover:bg-blue-600 text-white font-medium\">{hero.get('cta',{}).get('label','Get Started')}</a>\n  </section>\n\n  <section class=\"px-6 py-16 max-w-5xl mx-auto\">\n    <h2 class=\"text-3xl font-semibold mb-4\">{about.get('title','About')}</h2>\n    <p class=\"text-slate-300\">{about.get('body','')}</p>\n  </section>\n\n  <section class=\"px-6 py-16 max-w-5xl mx-auto\">\n    <h2 class=\"text-3xl font-semibold mb-8\">{services.get('title','Services')}</h2>\n    <div class=\"grid md:grid-cols-3 gap-6\">\n      {''.join([f'<div class=\\"p-6 rounded-xl bg-slate-900 border border-slate-800\\"><h3 class=\\"font-semibold mb-2\\">{it.get('" + "title" + "','') }</h3><p class=\\"text-slate-300\\">{it.get('" + "desc" + "','')}</p></div>' for it in services.get('items',[])])}
    </div>
  </section>

  <section class=\"px-6 py-16 max-w-5xl mx-auto\">\n    <h2 class=\"text-3xl font-semibold mb-6\">{why.get('title','Why Us')}</h2>\n    <ul class=\"grid md:grid-cols-3 gap-4\">\n      {''.join([f'<li class=\\"p-4 rounded-lg bg-slate-900 border border-slate-800\\">• {b}</li>' for b in why.get('bullets',[])])}
    </ul>
  </section>

  <section id=\"contact\" class=\"px-6 py-20 text-center bg-slate-900\">\n    <h2 class=\"text-3xl font-semibold mb-2\">{cta.get('title','')}</h2>\n    <p class=\"text-slate-300 mb-6\">{cta.get('subtitle','')}</p>\n    <a href=\"{cta.get('button',{}).get('href','#')}\" class=\"inline-block px-6 py-3 rounded-lg bg-blue-500 hover:bg-blue-600 text-white font-medium\">{cta.get('button',{}).get('label','Contact Us')}</a>\n  </section>\n
  <footer class=\"px-6 py-8 text-center text-slate-400\">{footer.get('copyright','')}</footer>
</body>
</html>
"""


@app.post("/proposal/preview")
def proposal_preview(payload: PreviewPayload, user=Depends(get_current_user)):
    html = structure_to_html(payload.structure)
    return {"html": html}


# ---------------------------
# Admin endpoints
# ---------------------------
@app.get("/admin/users")
def admin_list_users(admin=Depends(get_admin_user)):
    users = []
    if db is None:
        return {"users": users}
    for u in db["saasuser"].find({}, {"password_hash": 0}).limit(200):
        u["id"] = str(u.get("_id"))
        users.append(u)
    return {"users": users}


@app.post("/admin/users/plan")
def admin_update_plan(payload: UpdatePlanPayload, admin=Depends(get_admin_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    res = db["saasuser"].update_one({"email": payload.email}, {"$set": {"plan": payload.plan, "updated_at": time.time()}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


@app.post("/admin/users/role")
def admin_update_role(payload: UpdateRolePayload, admin=Depends(get_admin_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if payload.role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")
    res = db["saasuser"].update_one({"email": payload.email}, {"$set": {"role": payload.role, "updated_at": time.time()}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


@app.get("/admin/stats")
def admin_stats(admin=Depends(get_admin_user)):
    if db is None:
        return {"users": 0, "analyses": 0, "proposals": 0}
    return {
        "users": db["saasuser"].count_documents({}),
        "analyses": db["analysis"].count_documents({}),
        "proposals": db["proposal"].count_documents({}),
    }


# ---------------------------
# Health/test
# ---------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "backend"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ Connected but error: {str(e)[:80]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
