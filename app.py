import os
import re
import subprocess
import uuid
import json
import zipfile
import io
import time
import shutil
from pathlib import Path
from typing import List, Optional, Union
import bcrypt
import jwt
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Depends
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.background import BackgroundTask

SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-tactics-key-change-in-prod")
ALGORITHM = "HS256"

APP_ENV = os.getenv("APP_ENV", "PROD").upper()
APP_ENV_LABEL = "Dev" if APP_ENV == "DEV" else "Prod"

app = FastAPI(title=f"Sports Film Room Analyzer ({APP_ENV_LABEL})")

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
CLIPS_DIR = DATA_DIR / "clips"
REELS_DIR = DATA_DIR / "reels"
THUMBS_DIR = DATA_DIR / "thumbnails"
PLAYERS_DIR = DATA_DIR / "players"
LOGOS_DIR = DATA_DIR / "logos"
DB_FILE = DATA_DIR / "store.json"

for folder in [UPLOAD_DIR, CLIPS_DIR, REELS_DIR, THUMBS_DIR, PLAYERS_DIR, LOGOS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

security = HTTPBearer()

app.mount("/media/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/media/clips", StaticFiles(directory=str(CLIPS_DIR)), name="clips")
app.mount("/media/reels", StaticFiles(directory=str(REELS_DIR)), name="reels")
app.mount("/media/thumbnails", StaticFiles(directory=str(THUMBS_DIR)), name="thumbnails")
app.mount("/media/players", StaticFiles(directory=str(PLAYERS_DIR)), name="players")
app.mount("/media/logos", StaticFiles(directory=str(LOGOS_DIR)), name="logos")

def sanitize_for_filename(name: Optional[str], default: str = "Unassigned") -> str:
    if not name or not name.strip():
        return default
    clean = name.strip()
    if "unassigned" in clean.lower():
        return "Team"
    clean = clean.replace("#", "").replace("/", " ").replace("&", "")
    clean = re.sub(r'[^\w\s-]', '', clean)
    clean = re.sub(r'[\s_-]+', '_', clean).strip('_')
    return clean if clean else default

def generate_thumbnail(video_path: Path, project_id: str) -> Optional[str]:
    thumb_filename = f"thumb_{project_id}.jpg"
    thumb_path = THUMBS_DIR / thumb_filename
    cmd = [
        "ffmpeg", "-y",
        "-ss", "00:00:03",
        "-i", str(video_path),
        "-vframes", "1",
        "-vf", "scale=640:360:force_original_aspect_ratio=decrease,pad=640:360:(ow-iw)/2:(oh-ih)/2",
        str(thumb_path)
    ]
    res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if res.returncode == 0 and thumb_path.exists() and thumb_path.stat().st_size > 0:
        return f"/media/thumbnails/{thumb_filename}"
    return None

def init_db():
    if not DB_FILE.exists():
        hashed_admin = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode('utf-8')
        hashed_coach = bcrypt.hashpw(b"coach123", bcrypt.gensalt()).decode('utf-8')
        hashed_viewer = bcrypt.hashpw(b"viewer123", bcrypt.gensalt()).decode('utf-8')
        default_data = {
            "users": [
                {"id": "usr_admin", "username": "admin", "password_hash": hashed_admin, "role": "admin", "project_ids": ["*"]},
                {"id": "usr_coach", "username": "coach", "password_hash": hashed_coach, "role": "coach", "project_ids": ["proj_varsity"]},
                {"id": "usr_viewer", "username": "viewer", "password_hash": hashed_viewer, "role": "viewer", "project_ids": ["proj_varsity"]}
            ],
            "projects": [
                {
                    "id": "proj_varsity",
                    "name": "Varsity Season Opener",
                    "sport": "Basketball",
                    "opponent": "West High Tigers",
                    "game_date": "2026-10-15",
                    "league": "Class 4A Regional",
                    "description": "Season opener game tape",
                    "video_filename": None,
                    "thumbnail_url": None,
                    "roster_name": "Varsity 2026"
                }
            ],
            "rosters": [
                {
                    "name": "Varsity 2026",
                    "players": ["#23 Jordan", "#33 Pippen", "#91 Rodman", "#4 Kerr", "#9 Harper"],
                    "logo_url": None
                },
                {
                    "name": "JV Squad",
                    "players": ["#2 Curry", "#3 Paul", "#11 Thompson", "#23 Green"],
                    "logo_url": None
                }
            ],
            "clips": [],
            "reels": [],
            "player_photos": {}
        }
        with open(DB_FILE, "w") as f:
            json.dump(default_data, f, indent=2)

init_db()

def read_db():
    try:
        with open(DB_FILE, "r") as f:
            data = json.load(f)
            data.setdefault("reels", [])
            data.setdefault("rosters", [])
            for r in data.get("rosters", []):
                r.setdefault("logo_url", None)
            data.setdefault("player_photos", {})
            for p in data.get("projects", []):
                p.setdefault("sport", "Basketball")
                p.setdefault("thumbnail_url", None)
            for c in data.get("clips", []):
                if "categories" not in c and "category" in c:
                    c["categories"] = [c["category"]] if c["category"] else ["General"]
                if "players" not in c:
                    c["players"] = [c["player"]] if c.get("player") else ["Unassigned / Team Play"]
                c.setdefault("sport", "Basketball")
                c.setdefault("annotation", "")
            return data
    except Exception:
        return {"users": [], "projects": [], "clips": [], "reels": [], "rosters": [], "player_photos": {}}

def write_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

def create_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "project_ids": user.get("project_ids", []),
        "player_name": user.get("player_name", None),
        "exp": int(time.time()) + (3600 * 24 * 7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def check_project_access(user: dict, project_id: str):
    if user["role"] in ["admin", "player"] or "*" in user.get("project_ids", []):
        return True
    if project_id in user.get("project_ids", []):
        return True
    raise HTTPException(status_code=403, detail="Access denied for this project")

@app.get("/", response_class=FileResponse)
async def serve_app():
    return FileResponse(BASE_DIR / "templates" / "index.html")

@app.get("/api/config")
def get_app_config():
    return {
        "env": APP_ENV,
        "env_label": APP_ENV_LABEL,
        "app_title": f"Sports Film Room ({APP_ENV_LABEL})"
    }

class LoginPayload(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
def login(payload: LoginPayload):
    db = read_db()
    user = next((u for u in db["users"] if u["username"].lower() == payload.username.lower()), None)
    if not user or not bcrypt.checkpw(payload.password.encode('utf-8'), user["password_hash"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {
        "access_token": create_token(user),
        "token_type": "bearer",
        "user": {
            "id": user["id"], 
            "username": user["username"], 
            "role": user["role"],
            "player_name": user.get("player_name"),
            "project_ids": user.get("project_ids", [])
        }
    }

class ProjectCreatePayload(BaseModel):
    name: str
    sport: Optional[str] = "Basketball"
    opponent: Optional[str] = ""
    game_date: Optional[str] = ""
    league: Optional[str] = ""
    description: Optional[str] = ""
    roster_name: Optional[str] = "Varsity 2026"

class ProjectUpdatePayload(BaseModel):
    name: str
    sport: Optional[str] = "Basketball"
    opponent: Optional[str] = ""
    game_date: Optional[str] = ""
    league: Optional[str] = ""
    description: Optional[str] = ""
    roster_name: Optional[str] = "Varsity 2026"

@app.get("/api/projects")
def get_projects(user: dict = Depends(get_current_user)):
    db = read_db()
    if user["role"] in ["admin", "player"] or "*" in user.get("project_ids", []):
        return db["projects"]
    return [p for p in db["projects"] if p["id"] in user.get("project_ids", [])]

@app.post("/api/projects")
def create_project(payload: ProjectCreatePayload, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only Admins can create new games")
    db = read_db()
    new_project = {
        "id": f"proj_{uuid.uuid4().hex[:6]}",
        "name": payload.name,
        "sport": payload.sport or "Basketball",
        "opponent": payload.opponent,
        "game_date": payload.game_date,
        "league": payload.league,
        "description": payload.description,
        "roster_name": payload.roster_name,
        "video_filename": None,
        "thumbnail_url": None
    }
    db["projects"].insert(0, new_project)
    write_db(db)
    return new_project

@app.put("/api/projects/{project_id}")
def update_project(project_id: str, payload: ProjectUpdatePayload, user: dict = Depends(get_current_user)):
    check_project_access(user, project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")
    
    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project["name"] = payload.name
    project["sport"] = payload.sport or project.get("sport", "Basketball")
    project["opponent"] = payload.opponent
    project["game_date"] = payload.game_date
    project["league"] = payload.league
    project["description"] = payload.description
    project["roster_name"] = payload.roster_name

    write_db(db)
    return project

@app.delete("/api/projects/{project_id}")
def delete_project(project_id: str, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only Admins can delete games")

    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.get("video_filename"):
        (UPLOAD_DIR / project["video_filename"]).unlink(missing_ok=True)
    (THUMBS_DIR / f"thumb_{project_id}.jpg").unlink(missing_ok=True)

    for c in [c for c in db["clips"] if c.get("project_id") == project_id]:
        (CLIPS_DIR / c["filename"]).unlink(missing_ok=True)

    db["clips"] = [c for c in db["clips"] if c.get("project_id") != project_id]
    db["projects"] = [p for p in db["projects"] if p["id"] != project_id]
    write_db(db)
    return {"status": "deleted"}

@app.post("/api/projects/{project_id}/upload-chunk")
async def upload_video_chunk(
    project_id: str,
    chunk: UploadFile = File(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    original_filename: str = Form(...),
    upload_id: str = Form(...),
    user: dict = Depends(get_current_user)
):
    check_project_access(user, project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")

    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    ext = Path(original_filename).suffix or ".mp4"
    safe_filename = f"{project_id}_{upload_id}{ext}"
    target_path = UPLOAD_DIR / safe_filename

    mode = "wb" if chunk_index == 0 else "ab"
    with open(target_path, mode) as f:
        while content := await chunk.read(1024 * 1024 * 4):
            f.write(content)

    if chunk_index == total_chunks - 1:
        faststart_path = UPLOAD_DIR / f"faststart_{safe_filename}"
        cmd_optimize = [
            "ffmpeg", "-y", "-i", str(target_path),
            "-c", "copy", "-movflags", "+faststart", str(faststart_path)
        ]
        res = subprocess.run(cmd_optimize, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0 and faststart_path.exists() and faststart_path.stat().st_size > 0:
            target_path.unlink(missing_ok=True)
            faststart_path.rename(target_path)

        project["video_filename"] = safe_filename
        project["video_original_name"] = original_filename
        project["thumbnail_url"] = generate_thumbnail(target_path, project_id)
        write_db(db)
        return {
            "status": "complete",
            "filename": safe_filename,
            "url": f"/media/uploads/{safe_filename}",
            "thumbnail_url": project["thumbnail_url"]
        }

    return {"status": "chunk_received", "chunk_index": chunk_index}

@app.get("/api/rosters")
def list_rosters(user: dict = Depends(get_current_user)):
    db = read_db()
    return db.get("rosters", [])

class RosterSavePayload(BaseModel):
    name: str
    players: List[str]
    logo_url: Optional[str] = None
    old_name: Optional[str] = None

@app.post("/api/rosters")
def save_roster(payload: RosterSavePayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")

    db = read_db()
    rosters = db.setdefault("rosters", [])
    clean_players = [p.strip() for p in payload.players if p.strip() and "unassigned" not in p.lower()]

    target_name = payload.old_name if payload.old_name else payload.name.strip()
    existing = next((r for r in rosters if r["name"].lower() == target_name.lower()), None)
    
    if existing:
        existing["name"] = payload.name.strip()
        existing["players"] = clean_players
        if payload.logo_url is not None:
            existing["logo_url"] = payload.logo_url
    else:
        rosters.append({
            "name": payload.name.strip(),
            "players": clean_players,
            "logo_url": payload.logo_url
        })

    write_db(db)
    return {"status": "saved", "rosters": rosters}

@app.delete("/api/rosters/{roster_name}")
def delete_roster(roster_name: str, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")
    db = read_db()
    db["rosters"] = [r for r in db.get("rosters", []) if r["name"].lower() != roster_name.lower()]
    write_db(db)
    return {"status": "deleted"}

class ReelCreatePayload(BaseModel):
    title: str
    description: Optional[str] = ""

@app.get("/api/reels")
def list_reels(user: dict = Depends(get_current_user)):
    db = read_db()
    return db.get("reels", [])

@app.post("/api/reels")
def create_reel(payload: ReelCreatePayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")
    db = read_db()
    new_reel = {
        "id": f"reel_{uuid.uuid4().hex[:8]}",
        "title": payload.title.strip(),
        "description": payload.description.strip(),
        "clip_ids": [],
        "created_by": user["username"],
        "created_at": int(time.time())
    }
    db["reels"].insert(0, new_reel)
    write_db(db)
    return new_reel

@app.delete("/api/reels/{reel_id}")
def delete_reel(reel_id: str, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")
    db = read_db()
    db["reels"] = [r for r in db.get("reels", []) if r["id"] != reel_id]
    write_db(db)
    return {"status": "deleted"}

class ClipCreatePayload(BaseModel):
    project_id: str
    start_time: float
    end_time: float
    categories: Optional[List[str]] = []
    players: Optional[List[str]] = []
    annotation: Optional[str] = ""

@app.post("/api/clips")
def create_clip(payload: ClipCreatePayload, user: dict = Depends(get_current_user)):
    check_project_access(user, payload.project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")

    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == payload.project_id), None)
    if not project or not project.get("video_filename"):
        raise HTTPException(status_code=400, detail="Video file missing")

    input_path = UPLOAD_DIR / project["video_filename"]
    clip_id = uuid.uuid4().hex[:8]
    clip_filename = f"clip_{clip_id}.mp4"
    output_path = CLIPS_DIR / clip_filename
    duration = max(0.5, payload.end_time - payload.start_time)

    cmd = [
        "ffmpeg", "-y", "-ss", str(payload.start_time), "-i", str(input_path),
        "-t", str(duration), "-c", "copy", "-movflags", "+faststart", str(output_path)
    ]
    res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if res.returncode != 0 or not output_path.exists():
        cmd_fallback = [
            "ffmpeg", "-y", "-ss", str(payload.start_time), "-i", str(input_path),
            "-t", str(duration), "-c:v", "libx264", "-preset", "ultrafast",
            "-crf", "26", "-c:a", "aac", "-movflags", "+faststart", str(output_path)
        ]
        subprocess.run(cmd_fallback, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    clip_record = {
        "id": clip_id,
        "project_id": payload.project_id,
        "project_name": project["name"],
        "filename": clip_filename,
        "url": f"/media/clips/{clip_filename}",
        "categories": payload.categories or ["General"],
        "players": payload.players or ["Unassigned / Team Play"],
        "annotation": (payload.annotation or "").strip()[:100],
        "start_time": round(payload.start_time, 2),
        "end_time": round(payload.end_time, 2),
        "duration": round(duration, 2),
        "created_by": user["username"]
    }
    db["clips"].insert(0, clip_record)
    write_db(db)
    return clip_record

@app.get("/api/projects/{project_id}/clips")
def get_project_clips(project_id: str, user: dict = Depends(get_current_user)):
    check_project_access(user, project_id)
    db = read_db()
    return [c for c in db["clips"] if c["project_id"] == project_id]

@app.delete("/api/clips/{clip_id}")
def delete_clip(clip_id: str, user: dict = Depends(get_current_user)):
    db = read_db()
    clip = next((c for c in db["clips"] if c["id"] == clip_id), None)
    if not clip:
        raise HTTPException(status_code=404, detail="Clip not found")
    check_project_access(user, clip["project_id"])
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")

    (CLIPS_DIR / clip["filename"]).unlink(missing_ok=True)
    db["clips"] = [c for c in db["clips"] if c["id"] != clip_id]
    write_db(db)
    return {"status": "deleted"}