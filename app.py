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
PLAYERS_DIR = DATA_DIR / "players"
DB_FILE = DATA_DIR / "store.json"

for folder in [UPLOAD_DIR, CLIPS_DIR, REELS_DIR, PLAYERS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

security = HTTPBearer()

app.mount("/media/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/media/clips", StaticFiles(directory=str(CLIPS_DIR)), name="clips")
app.mount("/media/reels", StaticFiles(directory=str(REELS_DIR)), name="reels")
app.mount("/media/players", StaticFiles(directory=str(PLAYERS_DIR)), name="players")

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
                    "roster_name": "Varsity 2026"
                }
            ],
            "rosters": [
                {
                    "name": "Varsity 2026",
                    "players": ["#23 Jordan", "#33 Pippen", "#91 Rodman", "#4 Kerr", "#9 Harper"]
                },
                {
                    "name": "JV Squad",
                    "players": ["#2 Curry", "#3 Paul", "#11 Thompson", "#23 Green"]
                },
                {
                    "name": "Varsity Football",
                    "players": ["#12 Brady", "#87 Gronkowski", "#11 Edelman", "#54 Bruschi"]
                },
                {
                    "name": "Varsity Soccer",
                    "players": ["#10 Messi", "#7 Ronaldo", "#11 Neymar", "#9 Haaland"]
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
            data.setdefault("player_photos", {})
            for p in data.get("projects", []):
                p.setdefault("sport", "Basketball")
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
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def check_project_access(user: dict, project_id: str):
    if user["role"] in ["admin", "player"] or "*" in user.get("project_ids", []):
        return True
    if project_id in user.get("project_ids", []):
        return True
    raise HTTPException(status_code=403, detail="Access denied for this project")

@app.get("/", response_class=FileResponse)
async def serve_app(request: Request):
    return FileResponse(BASE_DIR / "templates" / "index.html")

@app.get("/api/config")
def get_app_config():
    return {
        "env": APP_ENV,
        "env_label": APP_ENV_LABEL,
        "app_title": f"Sports Film Room ({APP_ENV_LABEL})"
    }

# --- Auth Endpoints ---
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

# --- User Management (Admin Only) ---
class UserCreatePayload(BaseModel):
    username: str
    password: str
    role: str
    project_ids: List[str]
    player_name: Optional[str] = None

class UserUpdatePayload(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    project_ids: Optional[List[str]] = None
    player_name: Optional[str] = None

@app.get("/api/admin/users")
def list_users(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    db = read_db()
    return [{
        "id": u["id"],
        "username": u["username"],
        "role": u["role"],
        "player_name": u.get("player_name"),
        "project_ids": u.get("project_ids", [])
    } for u in db["users"]]

@app.post("/api/admin/users")
def create_user(payload: UserCreatePayload, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    if payload.role not in ["admin", "coach", "viewer", "player"]:
        raise HTTPException(status_code=400, detail="Invalid role specified")
    if payload.role == "player" and not payload.player_name:
        raise HTTPException(status_code=400, detail="Player accounts must be assigned to a player")
    if len(payload.username.strip()) < 3 or len(payload.password) < 4:
        raise HTTPException(status_code=400, detail="Username (min 3 chars) and Password (min 4 chars) required")

    db = read_db()
    if any(u["username"].lower() == payload.username.lower().strip() for u in db["users"]):
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = bcrypt.hashpw(payload.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = {
        "id": f"usr_{uuid.uuid4().hex[:6]}",
        "username": payload.username.strip(),
        "password_hash": hashed_pw,
        "role": payload.role,
        "player_name": payload.player_name if payload.role == "player" else None,
        "project_ids": ["*"] if payload.role in ["admin", "player"] else payload.project_ids
    }
    db["users"].append(new_user)
    write_db(db)
    return {"status": "created", "id": new_user["id"]}

@app.put("/api/admin/users/{user_id}")
def update_user(user_id: str, payload: UserUpdatePayload, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    db = read_db()
    target = next((u for u in db["users"] if u["id"] == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.password:
        if len(payload.password) < 4:
            raise HTTPException(status_code=400, detail="Password (min 4 chars) required")
        hashed_pw = bcrypt.hashpw(payload.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        target["password_hash"] = hashed_pw

    if payload.role:
        if payload.role not in ["admin", "coach", "viewer", "player"]:
            raise HTTPException(status_code=400, detail="Invalid role specified")
        target["role"] = payload.role

    if payload.player_name is not None:
        target["player_name"] = payload.player_name if target["role"] == "player" else None

    if payload.project_ids is not None:
        target["project_ids"] = ["*"] if target["role"] in ["admin", "player"] else payload.project_ids

    write_db(db)
    return {"status": "updated", "id": user_id}

@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: str, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    if user["sub"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own active admin account")
    
    db = read_db()
    target = next((u for u in db["users"] if u["id"] == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    
    db["users"] = [u for u in db["users"] if u["id"] != user_id]
    write_db(db)
    return {"status": "deleted"}

# --- Project Management Endpoints ---
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
        raise HTTPException(status_code=403, detail="Only Admins can create new game projects")
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
        "video_filename": None
    }
    db["projects"].append(new_project)
    write_db(db)
    return new_project

@app.put("/api/projects/{project_id}")
def update_project(project_id: str, payload: ProjectUpdatePayload, user: dict = Depends(get_current_user)):
    check_project_access(user, project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to edit projects")
    
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
        raise HTTPException(status_code=403, detail="Only Admins can delete game projects")

    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.get("video_filename"):
        raw_video_path = UPLOAD_DIR / project["video_filename"]
        if raw_video_path.exists():
            try:
                raw_video_path.unlink()
            except Exception:
                pass

    clips_to_remove = [c for c in db["clips"] if c.get("project_id") == project_id]
    for c in clips_to_remove:
        clip_path = CLIPS_DIR / c["filename"]
        if clip_path.exists():
            try:
                clip_path.unlink()
            except Exception:
                pass

    db["clips"] = [c for c in db["clips"] if c.get("project_id") != project_id]
    db["projects"] = [p for p in db["projects"] if p["id"] != project_id]

    for u in db["users"]:
        if "project_ids" in u and project_id in u["project_ids"]:
            u["project_ids"] = [pid for pid in u["project_ids"] if pid != project_id]

    write_db(db)
    return {"status": "deleted", "project_id": project_id}

# --- Rosters Management ---
class RosterSavePayload(BaseModel):
    name: str
    players: List[str]
    old_name: Optional[str] = None

@app.get("/api/rosters")
def list_rosters(user: dict = Depends(get_current_user)):
    db = read_db()
    return db.get("rosters", [])

@app.post("/api/rosters")
def save_roster(payload: RosterSavePayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to edit rosters")

    db = read_db()
    rosters = db.setdefault("rosters", [])
    
    clean_players = [
        p.strip() for p in payload.players 
        if p.strip() and "unassigned" not in p.lower()
    ]

    target_name = payload.old_name if payload.old_name else payload.name.strip()
    existing = next((r for r in rosters if r["name"].lower() == target_name.lower()), None)
    
    if existing:
        existing["name"] = payload.name.strip()
        existing["players"] = clean_players
        if payload.old_name and payload.old_name != payload.name.strip():
            for p in db.get("projects", []):
                if p.get("roster_name") == payload.old_name:
                    p["roster_name"] = payload.name.strip()
    else:
        rosters.append({"name": payload.name.strip(), "players": clean_players})

    write_db(db)
    return {"status": "saved", "rosters": rosters}

@app.delete("/api/rosters/{roster_name}")
def delete_roster(roster_name: str, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to delete rosters")

    db = read_db()
    rosters = db.get("rosters", [])
    if len(rosters) <= 1:
        raise HTTPException(status_code=400, detail="Must keep at least one roster")

    db["rosters"] = [r for r in rosters if r["name"].lower() != roster_name.lower()]
    write_db(db)
    return {"status": "deleted"}

# --- Resilient Chunked Video Ingestion with Fast-Start Relocation ---
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
        raise HTTPException(status_code=403, detail="Permission denied to upload video")

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
            "ffmpeg", "-y",
            "-i", str(target_path),
            "-c", "copy",
            "-movflags", "+faststart",
            str(faststart_path)
        ]
        res_opt = subprocess.run(cmd_optimize, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        if res_opt.returncode == 0 and faststart_path.exists() and faststart_path.stat().st_size > 0:
            target_path.unlink(missing_ok=True)
            faststart_path.rename(target_path)
        else:
            if faststart_path.exists():
                faststart_path.unlink(missing_ok=True)

        project["video_filename"] = safe_filename
        project["video_original_name"] = original_filename
        write_db(db)
        return {
            "status": "complete",
            "filename": safe_filename,
            "url": f"/media/uploads/{safe_filename}"
        }

    return {"status": "chunk_received", "chunk_index": chunk_index}

@app.post("/api/projects/{project_id}/upload-cancel")
def cancel_upload(
    project_id: str,
    upload_id: str = Form(...),
    original_filename: str = Form(...),
    user: dict = Depends(get_current_user)
):
    check_project_access(user, project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied")
    ext = Path(original_filename).suffix or ".mp4"
    safe_filename = f"{project_id}_{upload_id}{ext}"
    target_path = UPLOAD_DIR / safe_filename
    faststart_path = UPLOAD_DIR / f"faststart_{safe_filename}"
    cleanup_temp_files(target_path, faststart_path)
    return {"status": "cancelled"}

# --- Video Clipping & Editing Endpoints ---
class ClipCreatePayload(BaseModel):
    project_id: str
    start_time: float
    end_time: float
    categories: Optional[List[str]] = []
    category: Optional[str] = None
    players: Optional[List[str]] = []
    player: Optional[str] = None
    annotation: Optional[str] = ""
    notes: Optional[str] = ""

class ClipUpdatePayload(BaseModel):
    categories: List[str]
    players: List[str]
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    timestamp: Optional[Union[float, str]] = None
    annotation: Optional[str] = ""
    notes: Optional[str] = ""

@app.post("/api/clips")
def create_clip(payload: ClipCreatePayload, user: dict = Depends(get_current_user)):
    check_project_access(user, payload.project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to slice clips")

    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == payload.project_id), None)
    if not project or not project.get("video_filename"):
        raise HTTPException(status_code=400, detail="Source game tape not uploaded")

    input_path = UPLOAD_DIR / project["video_filename"]
    if payload.end_time <= payload.start_time:
        raise HTTPException(status_code=400, detail="Out point must be greater than In point")

    tags = payload.categories or []
    if payload.category and payload.category not in tags:
        tags.insert(0, payload.category)
    if not tags:
        tags = ["Play"]

    tagged_players = payload.players or []
    if payload.player and payload.player not in tagged_players:
        tagged_players.insert(0, payload.player)
    if not tagged_players:
        tagged_players = ["Unassigned / Team Play"]

    clip_id = uuid.uuid4().hex[:8]
    clean_player_slug = "_".join([sanitize_for_filename(p, default="Player") for p in tagged_players[:2]])
    tags_slug = "_".join([sanitize_for_filename(t, default="Tag") for t in tags[:2]])
    clip_filename = f"clip_{clean_player_slug}_{tags_slug}_{clip_id}.mp4"
    output_path = CLIPS_DIR / clip_filename
    duration = payload.end_time - payload.start_time

    cmd_fast = [
        "ffmpeg", "-y",
        "-ss", str(payload.start_time),
        "-i", str(input_path),
        "-t", str(duration),
        "-c", "copy",
        "-map", "0:v:0",
        "-map", "0:a:0?",
        "-avoid_negative_ts", "make_zero",
        "-movflags", "+faststart",
        str(output_path)
    ]
    res = subprocess.run(cmd_fast, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)

    if res.returncode != 0 or not output_path.exists() or output_path.stat().st_size < 1000:
        cmd_fallback = [
            "ffmpeg", "-y",
            "-ss", str(payload.start_time),
            "-i", str(input_path),
            "-t", str(duration),
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-crf", "26",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac",
            "-b:a", "96k",
            "-threads", "0",
            "-movflags", "+faststart",
            str(output_path)
        ]
        res_fb = subprocess.run(cmd_fallback, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        if res_fb.returncode != 0:
            raise HTTPException(status_code=500, detail="Clip processing failed")

    clip_record = {
        "id": clip_id,
        "project_id": payload.project_id,
        "project_name": project["name"],
        "sport": project.get("sport", "Basketball"),
        "filename": clip_filename,
        "url": f"/media/clips/{clip_filename}",
        "categories": tags,
        "category": tags[0],
        "players": tagged_players,
        "player": tagged_players[0],
        "annotation": (payload.annotation or "").strip()[:100],
        "notes": payload.notes or "",
        "start_time": round(payload.start_time, 2),
        "end_time": round(payload.end_time, 2),
        "duration": round(duration, 2),
        "created_by": user["username"]
    }
    db["clips"].insert(0, clip_record)
    write_db(db)
    return clip_record

@app.put("/api/clips/{clip_id}")
def update_clip(clip_id: str, payload: ClipUpdatePayload, user: dict = Depends(get_current_user)):
    db = read_db()
    clip = next((c for c in db["clips"] if c["id"] == clip_id), None)
    if not clip:
        raise HTTPException(status_code=404, detail="Clip not found")

    check_project_access(user, clip["project_id"])
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to edit clips")

    tags = [t.strip() for t in payload.categories if t.strip()]
    if not tags:
        tags = ["Play"]

    pls = [p.strip() for p in payload.players if p.strip()]
    if not pls:
        pls = ["Unassigned / Team Play"]

    clip["categories"] = tags
    clip["category"] = tags[0]
    clip["players"] = pls
    clip["player"] = pls[0]
    clip["annotation"] = (payload.annotation or "").strip()[:100]
    clip["notes"] = payload.notes or ""

    if payload.start_time is not None:
        clip["start_time"] = round(payload.start_time, 2)
    elif payload.timestamp is not None:
        try:
            clip["start_time"] = round(float(payload.timestamp), 2)
        except ValueError:
            pass

    if payload.end_time is not None:
        clip["end_time"] = round(payload.end_time, 2)

    if clip.get("start_time") is not None and clip.get("end_time") is not None:
        clip["duration"] = round(max(0.0, clip["end_time"] - clip["start_time"]), 2)

    write_db(db)
    return clip

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
        raise HTTPException(status_code=403, detail="Permission denied to delete clips")

    clip_path = CLIPS_DIR / clip["filename"]
    if clip_path.exists():
        clip_path.unlink()
        
    db["clips"] = [c for c in db["clips"] if c["id"] != clip_id]
    
    for r in db["reels"]:
        r["clip_ids"] = [cid for cid in r.get("clip_ids", []) if cid != clip_id]

    write_db(db)
    return {"status": "deleted"}

# --- Player Vault Query Endpoint ---
@app.get("/api/players/clips")
def get_player_clips(
    player_name: Optional[str] = None, 
    roster_name: Optional[str] = None, 
    user: dict = Depends(get_current_user)
):
    db = read_db()
    
    if user["role"] == "player":
        target_player = user.get("player_name")
        if not target_player:
            raise HTTPException(status_code=403, detail="No player linked to this account")
    else:
        target_player = player_name

    if not target_player:
        return []

    allowed_proj_ids = None
    if user["role"] not in ["admin", "player"] and "*" not in user.get("project_ids", []):
        allowed_proj_ids = set(user.get("project_ids", []))

    matching_project_ids = None
    if roster_name and roster_name != "ALL":
        matching_project_ids = {
            p["id"] for p in db.get("projects", []) 
            if p.get("roster_name", "").lower() == roster_name.lower()
        }

    matched_clips = []
    target_clean = target_player.strip().lower()

    for clip in db.get("clips", []):
        if allowed_proj_ids is not None and clip.get("project_id") not in allowed_proj_ids:
            continue
        if matching_project_ids is not None and clip.get("project_id") not in matching_project_ids:
            continue

        clip_players = [p.strip().lower() for p in clip.get("players", [clip.get("player", "")])]
        if target_clean in clip_players:
            matched_clips.append(clip)

    return matched_clips

# --- Custom Reels & Playlists ---
class ReelCreatePayload(BaseModel):
    title: str
    description: Optional[str] = ""

class ReelUpdatePayload(BaseModel):
    title: str
    description: Optional[str] = ""

class ReelUpdateClipsPayload(BaseModel):
    clip_ids: List[str]

@app.get("/api/reels")
def list_reels(user: dict = Depends(get_current_user)):
    db = read_db()
    return db.get("reels", [])

@app.post("/api/reels")
def create_reel(payload: ReelCreatePayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to create reels")
    db = read_db()
    new_reel = {
        "id": f"reel_{uuid.uuid4().hex[:8]}",
        "title": payload.title.strip(),
        "description": payload.description.strip(),
        "clip_ids": [],
        "created_by": user["username"],
        "created_at": int(time.time())
    }
    db["reels"].append(new_reel)
    write_db(db)
    return new_reel

@app.put("/api/reels/{reel_id}")
def update_reel(reel_id: str, payload: ReelUpdatePayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to modify reels")
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")

    reel["title"] = payload.title.strip()
    reel["description"] = payload.description.strip()
    write_db(db)
    return reel

@app.get("/api/reels/{reel_id}")
def get_reel(reel_id: str, user: dict = Depends(get_current_user)):
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")
    
    clips_lookup = {c["id"]: c for c in db["clips"]}
    ordered_clips = [clips_lookup[cid] for cid in reel.get("clip_ids", []) if cid in clips_lookup]
    return {
        "reel": reel,
        "clips": ordered_clips
    }

@app.put("/api/reels/{reel_id}/clips")
def update_reel_clips(reel_id: str, payload: ReelUpdateClipsPayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to modify reels")
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")
    
    reel["clip_ids"] = payload.clip_ids
    write_db(db)
    return reel

@app.post("/api/reels/{reel_id}/add-clip")
def add_clip_to_reel(reel_id: str, clip_id: str = Form(...), user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to modify reels")
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")
    
    if clip_id not in reel.get("clip_ids", []):
        reel.setdefault("clip_ids", []).append(clip_id)
        write_db(db)
    return reel

@app.delete("/api/reels/{reel_id}")
def delete_reel(reel_id: str, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to delete reels")
    db = read_db()
    db["reels"] = [r for r in db["reels"] if r["id"] != reel_id]
    write_db(db)
    return {"status": "deleted"}

# --- Player Photos Management ---
@app.get("/api/players/photos")
def get_player_photos(user: dict = Depends(get_current_user)):
    db = read_db()
    photos = db.get("player_photos", {})
    return {
        name: f"/media/players/{filename}"
        for name, filename in photos.items()
    }

@app.post("/api/players/photo")
async def upload_player_photo(
    player_name: str = Form(...),
    photo: UploadFile = File(...),
    user: dict = Depends(get_current_user)
):
    clean_player = player_name.strip()
    if not clean_player:
        raise HTTPException(status_code=400, detail="Player name required")

    if user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot upload player photos")
    if user["role"] == "player" and user.get("player_name") != clean_player:
        raise HTTPException(status_code=403, detail="Cannot upload photos for other players")

    ext = Path(photo.filename or "").suffix.lower()
    if ext not in [".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif"]:
        raise HTTPException(status_code=400, detail="Unsupported image format. Use JPG, PNG, WEBP, or GIF")

    content = await photo.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image file too large (max 10MB)")

    db = read_db()
    photos = db.setdefault("player_photos", {})

    old_filename = photos.get(clean_player)
    if old_filename:
        old_file = PLAYERS_DIR / old_filename
        if old_file.exists():
            try:
                old_file.unlink()
            except Exception:
                pass

    safe_slug = sanitize_for_filename(clean_player, default="player")
    unique_filename = f"player_{safe_slug}_{uuid.uuid4().hex[:6]}{ext}"
    target_path = PLAYERS_DIR / unique_filename

    with open(target_path, "wb") as f:
        f.write(content)

    photos[clean_player] = unique_filename
    write_db(db)

    return {
        "status": "uploaded",
        "player_name": clean_player,
        "url": f"/media/players/{unique_filename}"
    }

@app.delete("/api/players/photo")
def delete_player_photo(player_name: str, user: dict = Depends(get_current_user)):
    clean_player = player_name.strip()
    if user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="Permission denied")
    if user["role"] == "player" and user.get("player_name") != clean_player:
        raise HTTPException(status_code=403, detail="Cannot delete photos for other players")

    db = read_db()
    photos = db.setdefault("player_photos", {})
    old_filename = photos.pop(clean_player, None)
    if old_filename:
        old_file = PLAYERS_DIR / old_filename
        if old_file.exists():
            try:
                old_file.unlink()
            except Exception:
                pass
        write_db(db)

    return {"status": "deleted", "player_name": clean_player}

def cleanup_temp_files(*paths: Path):
    for p in paths:
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass

# --- Backup & Restore (Admin Only) ---
@app.get("/api/admin/backup")
def backup_all_data(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    backup_buffer = io.BytesIO()
    with zipfile.ZipFile(backup_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Include the database (users, projects, clips metadata, rosters, reels, photos map)
        if DB_FILE.exists():
            zf.write(DB_FILE, arcname="store.json")

        # 2. Include media directories preserving the relative layout under data/.
        #    NOTE: "uploads" (the full-length game tapes) is intentionally excluded
        #    because those files are very large and make the backup slow. Clips,
        #    reels, and player photos are still included.
        media_dirs = {
            "clips": CLIPS_DIR,
            "reels": REELS_DIR,
            "players": PLAYERS_DIR,
        }
        for arc_prefix, folder in media_dirs.items():
            if not folder.exists():
                continue
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    rel = file_path.relative_to(folder)
                    zf.write(file_path, arcname=f"media/{arc_prefix}/{rel.as_posix()}")

        # 3. Small manifest so restores can sanity-check the archive
        db = read_db()
        manifest = {
            "app": "sports-film-room",
            "env": APP_ENV,
            "exported_at": int(time.time()),
            "counts": {
                "users": len(db.get("users", [])),
                "projects": len(db.get("projects", [])),
                "clips": len(db.get("clips", [])),
                "reels": len(db.get("reels", [])),
                "rosters": len(db.get("rosters", [])),
                "player_photos": len(db.get("player_photos", {})),
            }
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    backup_buffer.seek(0)
    total_bytes = backup_buffer.getbuffer().nbytes
    stamp = time.strftime("%Y%m%d_%H%M%S")
    zip_filename = f"film_room_backup_{APP_ENV_LABEL.lower()}_{stamp}.zip"

    return StreamingResponse(
        backup_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{zip_filename}"',
            "Content-Length": str(total_bytes),
            "X-Backup-Total-Bytes": str(total_bytes),
        }
    )

@app.post("/api/admin/restore")
async def restore_all_data(
    backup: UploadFile = File(...),
    overwrite: bool = Form(True),
    user: dict = Depends(get_current_user)
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    raw = await backup.read()
    if len(raw) > 2 * 1024 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Backup file too large (max 2GB)")

    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive")

    names = archive.namelist()
    if "store.json" not in names:
        raise HTTPException(status_code=400, detail="Backup is missing store.json")

    # Validate the store.json before wiping anything
    try:
        restored_db = json.loads(archive.read("store.json").decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="store.json in backup is not valid JSON")

    if "users" not in restored_db or "projects" not in restored_db:
        raise HTTPException(status_code=400, detail="store.json is missing required keys")

    # Ensure the active admin can still log in after restore. If the current
    # admin's account isn't in the backup, inject it back so we don't lock out.
    restored_users = restored_db.get("users", [])
    if not any(u["id"] == user["sub"] for u in restored_users):
        current_db = read_db()
        me = next((u for u in current_db["users"] if u["id"] == user["sub"]), None)
        if me:
            restored_users.append(me)
            restored_db["users"] = restored_users

    # Make sure defaults exist so read_db() normalization works
    restored_db.setdefault("reels", [])
    restored_db.setdefault("rosters", [])
    restored_db.setdefault("player_photos", [])
    restored_db.setdefault("clips", [])

    # Snapshot the current DB in case something fails mid-restore
    snapshot = None
    if DB_FILE.exists():
        try:
            snapshot = DB_FILE.read_bytes()
        except Exception:
            snapshot = None

    restored_files = 0
    try:
        # --- Restore media files ---
        media_dirs = {
            "uploads": UPLOAD_DIR,
            "clips": CLIPS_DIR,
            "reels": REELS_DIR,
            "players": PLAYERS_DIR,
        }
        for arc_prefix, folder in media_dirs.items():
            if overwrite:
                # Clear existing contents
                for existing in folder.rglob("*"):
                    if existing.is_file():
                        try:
                            existing.unlink()
                        except Exception:
                            pass
            prefix = f"media/{arc_prefix}/"
            for name in names:
                if not name.startswith(prefix) or name.endswith("/"):
                    continue
                rel = name[len(prefix):]
                target = folder / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(name) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                restored_files += 1

        # --- Restore DB last so media is already in place ---
        write_db(restored_db)
    except Exception as e:
        # Roll back DB if we had a snapshot
        if snapshot is not None:
            try:
                DB_FILE.write_bytes(snapshot)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=f"Restore failed: {e}")

    return {
        "status": "restored",
        "overwrite": overwrite,
        "restored_files": restored_files,
        "users": len(restored_db.get("users", [])),
        "projects": len(restored_db.get("projects", [])),
        "clips": len(restored_db.get("clips", [])),
        "reels": len(restored_db.get("reels", [])),
        "rosters": len(restored_db.get("rosters", [])),
    }

# --- Highlight Reel Concatenation Export ---
@app.get("/api/reels/{reel_id}/export-video")
def export_reel_concatenated_video(reel_id: str, user: dict = Depends(get_current_user)):
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")

    clips_lookup = {c["id"]: c for c in db["clips"]}
    ordered_clips = [clips_lookup[cid] for cid in reel.get("clip_ids", []) if cid in clips_lookup]

    valid_clip_paths = []
    for c in ordered_clips:
        p = CLIPS_DIR / c["filename"]
        if p.exists() and p.stat().st_size > 0:
            valid_clip_paths.append(p)

    if not valid_clip_paths:
        raise HTTPException(status_code=400, detail="No valid MP4 clips found in this reel to concatenate")

    export_id = uuid.uuid4().hex[:8]
    concat_list_file = REELS_DIR / f"concat_{export_id}.txt"
    output_video_path = REELS_DIR / f"reel_{export_id}.mp4"

    with open(concat_list_file, "w") as f:
        for p in valid_clip_paths:
            clean_path = str(p.resolve()).replace("'", "'\\''")
            f.write(f"file '{clean_path}'\n")

    cmd = [
        "ffmpeg", "-y",
        "-f", "concat",
        "-safe", "0",
        "-i", str(concat_list_file),
        "-c", "copy",
        "-movflags", "+faststart",
        str(output_video_path)
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if res.returncode != 0 or not output_video_path.exists() or output_video_path.stat().st_size == 0:
        cmd_reencode = [
            "ffmpeg", "-y",
            "-f", "concat",
            "-safe", "0",
            "-i", str(concat_list_file),
            "-vf", "scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,setsar=1",
            "-c:v", "libx264",
            "-preset", "veryfast",
            "-crf", "23",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac",
            "-b:a", "128k",
            "-ac", "2",
            "-ar", "44100",
            "-movflags", "+faststart",
            str(output_video_path)
        ]
        res_re = subprocess.run(cmd_reencode, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res_re.returncode != 0:
            cleanup_temp_files(concat_list_file, output_video_path)
            err_msg = res_re.stderr.decode("utf-8", errors="ignore")
            raise HTTPException(status_code=500, detail=f"Highlight stitching failed: {err_msg[-200:]}")

    if concat_list_file.exists():
        try:
            concat_list_file.unlink()
        except Exception:
            pass

    download_name = f"{sanitize_for_filename(reel['title'], default='Highlight_Reel')}.mp4"
    return FileResponse(
        path=str(output_video_path),
        media_type="application/octet-stream",
        filename=download_name,
        headers={
            "Content-Disposition": f'attachment; filename="{download_name}"',
            "Accept-Ranges": "none"
        },
        background=BackgroundTask(cleanup_temp_files, output_video_path)
    )

@app.get("/api/projects/{project_id}/export-zip")
def export_project_clips_zip(project_id: str, category: Optional[str] = None, user: dict = Depends(get_current_user)):
    check_project_access(user, project_id)
    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    clips = [c for c in db["clips"] if c["project_id"] == project_id]
    if category and category != "ALL":
        clips = [c for c in clips if category in c.get("categories", [c.get("category", "")])]

    if not clips:
        raise HTTPException(status_code=400, detail="No clips available to export")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("metadata.json", json.dumps(clips, indent=2))
        csv_header = "ID,Sport,Categories,Players,Filename,Start_Sec,End_Sec,Duration_Sec,Annotation,Created_By\n"
        
        csv_rows = []
        for c in clips:
            cats = ";".join(c.get("categories", [c.get("category", "")]))
            pls = ";".join(c.get("players", [c.get("player", "")]))
            sp = c.get("sport", "Basketball")
            annot = (c.get("annotation", "") or "").replace('"', '""')
            csv_rows.append(
                f'{c["id"]},{sp},"{cats}","{pls}",{c["filename"]},{c["start_time"]},{c["end_time"]},{c["duration"]},"{annot}",{c["created_by"]}'
            )
        zip_file.writestr("summary.csv", csv_header + "\n".join(csv_rows))

        for c in clips:
            file_path = CLIPS_DIR / c["filename"]
            if file_path.exists():
                zip_file.write(file_path, arcname=f"clips/{c['filename']}")

    zip_buffer.seek(0)
    zip_filename = f"{project['name'].replace(' ', '_')}_clips.zip"
    
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{zip_filename}"'}
    )