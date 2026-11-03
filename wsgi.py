from app import app
from database import init_db
from token_blocklist import initialize_blocklist_store

init_db()
initialize_blocklist_store()
