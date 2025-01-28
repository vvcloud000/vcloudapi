import os
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer
from authlib.jose import jwt, JoseError
from dotenv import load_dotenv
import requests

load_dotenv()

AUTHORITY = os.getenv("AUTHORITY")  # Example: https://login.microsoftonline.com/<tenant_id>
CLIENT_ID = os.getenv("CLIENT_ID")  # Azure AD App Registration Client ID
API_SCOPE = os.getenv("API_SCOPE")  # Example: api://<client-id>/access_as_app

security = HTTPBearer()

def get_public_keys():
    """
    Fetch public keys (JWKS) from Azure AD OpenID configuration.
    """
    try:
        openid_config_url = f"{AUTHORITY}/v2.0/.well-known/openid-configuration"
        response = requests.get(openid_config_url)
        response.raise_for_status()
        jwks_uri = response.json()["jwks_uri"]

        # Fetch JWKS (JSON Web Key Set)
        jwks_response = requests.get(jwks_uri)
        jwks_response.raise_for_status()
        return jwks_response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch public keys: {str(e)}")

def verify_token(auth_header: str = Security(security)):
    """
    Verify and decode an incoming OAuth2 token using Azure AD public keys.
    """
    token = auth_header.credentials  # Extract token from Authorization header
    keys = get_public_keys()

    try:
        # Decode and validate the token
        claims = jwt.decode(token, keys)

        # Validate standard claims (e.g., expiration)
        claims.validate()

        # Additional validation: Check audience (aud) and issuer (iss)
        if claims.get("aud") != CLIENT_ID:
            raise HTTPException(status_code=403, detail="Invalid token audience")
        
        if claims.get("iss") != f"{AUTHORITY}/v2.0":
            raise HTTPException(status_code=403, detail="Invalid token issuer")

        return claims  # Return claims if token is valid
    except JoseError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
