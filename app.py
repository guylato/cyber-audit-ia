from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes import router

app = FastAPI(title="Cyber AI Supervisor", version="3.2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Pour lancer:
# 1) ollama serve
# 2-8) ollama pull <model> (voir config.py pour la liste)
# 9) python3 -m venv .venv && source .venv/bin/activate
# 10) pip install fastapi uvicorn pydantic requests
# 11) uvicorn app:app --reload
# 12) http://127.0.0.1:8000/docs
