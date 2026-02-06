import os

def owner_set() -> set[str]:
    raw = os.getenv("OWNER_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}

def is_owner(email: str | None) -> bool:
    if not email:
        return False
    return email.strip().lower() in owner_set()
