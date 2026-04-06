import os
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ENGINE_API_KEY = os.getenv("ENGINE_API_KEY", "dev-engine-key")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,app://renderer").split(",")
