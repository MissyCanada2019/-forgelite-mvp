from api.owner import is_owner

# --- OWNER ROLE HELPER ---
# When you have the authenticated user's email available (Google now, GitHub later),
# you can determine role like:
# user_role = "owner" if is_owner(user_email) else "user"
# --- END OWNER ROLE HELPER ---
