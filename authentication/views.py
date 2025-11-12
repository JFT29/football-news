from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

def _get_data(request):
    """
    Read payload from form-encoded (request.POST) or JSON body.
    """
    if request.method != 'POST':
        return {}
    # Prefer form data (what CookieRequest.post sends by default)
    if request.POST:
        return request.POST
    # Fallback to JSON if someone calls postJson()
    try:
        return json.loads(request.body.decode() or "{}")
    except json.JSONDecodeError:
        return {}

@csrf_exempt
def login(request):
    if request.method != 'POST':
        return JsonResponse({"status": False, "message": "Invalid request method."}, status=400)

    data = _get_data(request)
    username = (data.get('username') or '').strip()
    password = data.get('password') or data.get('password1') or ''

    user = authenticate(username=username, password=password)
    if user is not None and user.is_active:
        auth_login(request, user)
        return JsonResponse({
            "username": user.username,
            "status": True,
            "message": "Login successful!"
        }, status=200)
    elif user is not None:
        return JsonResponse({"status": False, "message": "Login failed, account is disabled."}, status=401)
    else:
        return JsonResponse({"status": False, "message": "Login failed, please check your username or password."}, status=401)

@csrf_exempt
def register(request):
    if request.method != 'POST':
        return JsonResponse({"status": False, "message": "Invalid request method."}, status=400)

    data = _get_data(request)
    username = (data.get('username') or '').strip()
    # Tutorial form usually uses password1/password2
    password1 = data.get('password1') or data.get('password') or ''
    password2 = data.get('password2') or data.get('password_confirm') or ''

    if not username or not password1 or not password2:
        return JsonResponse({"status": False, "message": "Missing fields."}, status=400)

    if password1 != password2:
        return JsonResponse({"status": False, "message": "Passwords do not match."}, status=400)

    if User.objects.filter(username=username).exists():
        return JsonResponse({"status": False, "message": "Username already exists."}, status=400)

    user = User.objects.create_user(username=username, password=password1)
    return JsonResponse({
        "username": user.username,
        "status": True,
        "message": "User created successfully!"
    }, status=200)

@csrf_exempt
def logout(request):
    try:
        uname = getattr(request.user, "username", "")
        auth_logout(request)
        return JsonResponse({"username": uname, "status": True, "message": "Logged out successfully!"}, status=200)
    except Exception:
        return JsonResponse({"status": False, "message": "Logout failed."}, status=401)
