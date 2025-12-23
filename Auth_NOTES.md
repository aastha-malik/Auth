> These notes are written for learning and reference purposes.
> They summarize authentication concepts as implemented in backend systems using FastAPI.

#AUTHENTICATION
________________________________________________


## 1. What is Authentication? (Basic Foundation)
Authentication = proving who you are.
Examples:
* Logging in with email + password
* Logging in with Google
* Entering OTP sent to your email
If authentication succeeds → backend knows “this person is X”.
________________


## 2. What is Authorization?
Authorization = what you are allowed to do after login.
Examples:
* Access your profile
* Access admin panel
Authentication happens first, then authorization happens.
________________


## 3. Local Authentication (Your Own System)
This is when a user signs up with:
* Email (or Username if exists)
* Password




Backend responsibilities:
✔ Store users in DB
A user has:
* id
* email
* hashed password
* name (optional)
* username(optional)
* email_verified (boolean)

✔ Verify email during signup
Backend sends OTP or link → user proves email ownership. 
[Goggle STMP used for email verification]
✔ Login
Match email → hash password → compare → issue JWT.
________________


## 4. Password Hashing (Mandatory for Security)
Never store raw passwords.
Instead:
   * Use bcrypt or argon2.
   * Hash the password → store the hash.
   * During login: hash the input → compare hashes.
Hashing ensures:
   * Even if DB leaks → attacker cannot see passwords.
   * Backend cannot reverse the hash.
________________


## 5. Email Verification (Your System Only, NOT OAuth)
Two common methods:
✔ Method A: OTP (6-digit code)
   * Generate random 6-digit code
   * Email it
   * User enters it
   * Verify → mark email as verified
✔ Method B: Verification link
   * Generate token
   * Put in a URL
   * User clicks link
   * Backend confirms token → verifies email
Both methods achieve the same goal.
________________


## 6. JWT (JSON Web Token) – Your Own Login Token
After a user logs in or signs up:
Backend generates a JWT, which contains:
   * user_id
   * expiry time
   * issued time
JWT = header + payload + signature
It is signed using backend’s secret.
Frontend/Tkinter stores this JWT and sends it with EVERY request:  
Authorization: Bearer <jwt>
Backend verifies signature → identifies the user.
JWT = your session system.
________________


## 7. Third-Party Login (Google, GitHub, etc.)
Third-party login is NOT your password system.
Instead:
   * User authenticates with Google/GitHub
   * Provider confirms their identity
   * Provider gives your backend enough information
   * Backend creates your own JWT again
So final result is the same:
👉 user always ends up with your JWT.
________________


## 8. OAuth2 (Framework Behind Third-Party Login)
OAuth2 is NOT authentication —  It’s a system for “permission + delegated access”.
But we use it for login by adding OIDC (next section).
OAuth2 Authorization Code Flow steps:
1. User clicks “Login with Google”  (Backend redirects user to Google.)
2. Google shows login page  (User logs in.)
3. Google redirects user back to your callback URL
URL includes:    =>     code=XYZ123
This code is:    {  Temporary | One-time use | NOT a token | Must be exchanged by backend  }




4. Backend exchanges the code
Backend sends the code + client_secret → Google sends:
   * access_token
   * id_token (Google only)
5. Backend now has identity (via ID token or API calls)
________________


## 9. OIDC (OpenID Connect) — Adds Identity to OAuth2
OAuth2 alone does NOT provide identity.
OIDC adds:
   * ID Token (a signed JWT)
   * UserInfo endpoint
Google uses OIDC.
GitHub does NOT.
ID Token contains:
   * sub (unique user ID)
   * email
   * email_verified
   * name
   * picture
   * expiry
   * audience (must match your client_id)
   * issuer
Backend verifies signature using Google’s public keys.
________________




## 10. Access Token vs ID Token
✔ Access Token:
   * Means: user authenticated ON provider
   * Used to call provider APIs
   * Does NOT contain identity
✔ ID Token (Google only):
   * A JWT containing identity
   * Backend verifies it
   * Contains sub, email, etc
   * Used to identify user
________________


## 11. Provider Differences
✔ Google (OIDC Provider)
   * Gives ID Token → contains identity
   * Easy to extract user info
   * Usually no extra API calls
✔ GitHub (OAuth2 Only)
   * No ID token
   * Must call APIs:
   * /user
   * /user/emails
   * Requires access token
   * Must get verified primary email to identify user
Other providers work similarly to one of these two categories.
________________




## 12. Callback Endpoint (Heart of Third-Party Login)
This is where EVERYTHING important happens.
Inside /auth/google/callback:
Step 1: Receive code from provider.
Step 2: Backend exchanges code → tokens.
Step 3: Extract identity:
   * Google → from ID token
   * GitHub → from API calls
Step 4: Check DB:
   * If email exists → login user
   * If not → create user (signup)
Step 5: Generate your own JWT.
Step 6: Return JWT to frontend/Tkinter/Swagger.
{  Callback = the entire brain of third-party auth.  }
________________


## 13. User Storage (DB Design for Authentication)
User table includes:
   * id
   * name
   * email
   * email_verified
   * password_hash (for local auth only)
   * provider (google/github/local)
   * provider_id (google “sub”, github “id”)
   * created_at
Third-party users often have:
   * no password
   * provider + provider_id
________________


## 14. Refresh Tokens (Advanced but Important)
JWTs expire fast (15–60 mins).
Refresh tokens:
   * last longer (days/weeks)
   * stored in DB
   * allow generating new JWTs
   * can be revoked if user logs out
Not mandatory for your project now.
Needed later for production systems.
________________


## 15. Security Essentials
   * Always use HTTPS in production
   * Never share client_secret
   * Validate ID token signature
   * Use strong JWT secrets
   * Make redirect URIs exact
   * Rate-limit login attempts
   * Hash passwords
   * Store refresh tokens safely
   * Validate email during signup
________________


## 16. Putting It All Together (Mental Map)
Local Auth:
Signup → email/password → hash → store → verify → JWT
Third-Party Auth:
Login with Google → code → token exchange → ID token → extract identity → DB → JWT
Everything ends with:
👉 your own JWT
👉 your own session
👉 your own user stored in DB
________________


And that’s it … byee