from fastapi import FastAPI, Depends
from auth import verify_token

app = FastAPI()

@app.get("/")
def public_route():
    """
    Public endpoint that doesn't require authentication.
    """
    return {"message": "Welcome to the public API route"}

@app.get("/protected")
async def protected_route(token: str = Depends(verify_token)):
    """
    Protected endpoint that requires a valid OAuth2 token.
    """
    return {"message": "You have accessed a protected route"}
