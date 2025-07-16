"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license."""

import logging
import os
from typing import List
from urllib.parse import quote

import requests
from core.feature_flags import flag_set
from core.middleware import enforce_csrf_checks
from core.utils.common import load_func
from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect, render, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from jose import JOSEError, jwt
from organizations.forms import OrganizationSignupForm
from organizations.models import Organization
from rest_framework.authtoken.models import Token
from users import forms
from users.functions import login, proceed_registration
from users.models import User

logger = logging.getLogger()

google_oauth_redir_uri = os.getenv("GOOGLE_OAUTH_REDIRECT_URI")
auth0_domain = os.getenv("AUTH0_DOMAIN")
auth0_db = os.getenv("AUTH0_DB")

auth0_m2m_id = os.getenv("AUTH0_M2M_CLIENT_ID")
auth0_m2m_secret = os.getenv("AUTH0_M2M_CLIENT_SECRET")
auth0_id = os.getenv("AUTH0_REG_CLIENT_ID")
auth0_secret = os.getenv("AUTH0_REG_CLIENT_SECRET")

if not all([google_oauth_redir_uri, auth0_domain, auth0_m2m_id, auth0_m2m_secret, auth0_db, auth0_id, auth0_secret]):
    raise ValueError("Auth0 variables not found")


@login_required
def logout(request):
    auth.logout(request)

    if settings.LOGOUT_REDIRECT_URL:
        return redirect(settings.LOGOUT_REDIRECT_URL)

    if settings.HOSTNAME:
        redirect_url = settings.HOSTNAME
        if not redirect_url.endswith("/"):
            redirect_url += "/"
        return redirect(redirect_url)
    return redirect("/")


@enforce_csrf_checks
def user_signup(request):
    """Sign up page"""
    user = request.user
    next_page = request.GET.get("next")
    token = request.GET.get("token")

    # checks if the URL is a safe redirection.
    if not next_page or not url_has_allowed_host_and_scheme(url=next_page, allowed_hosts=request.get_host()):
        if flag_set("fflag_all_feat_dia_1777_ls_homepage_short", user):
            next_page = reverse("main")
        else:
            next_page = reverse("projects:project-index")

    user_form = forms.UserSignupForm()
    organization_form = OrganizationSignupForm()

    if user.is_authenticated:
        return redirect(next_page)

    if request.method == "POST":
        organization = Organization.objects.first()
        if settings.DISABLE_SIGNUP_WITHOUT_LINK is True:
            if not (token and organization and token == organization.token):
                raise PermissionDenied()
        else:
            if token and organization and token != organization.token:
                raise PermissionDenied()

        # ======== Main Logic ========

        # Bound form i.e. data is bound to the form instance
        user_form = forms.UserSignupForm(request.POST)
        organization_form = OrganizationSignupForm(request.POST)

        # Run validation checks on the form data
        # If valid, returns True and populates the cleaned_data attribute of the form with normalized data
        # Begin by authenticating with Auth0 to receive an access_token for managing users
        if user_form.is_valid():
            res = requests.post(
                url=f"https://{auth0_domain}/oauth/token",
                json={
                    "grant_type": "client_credentials",
                    "client_id": auth0_m2m_id,
                    "client_secret": auth0_m2m_secret,
                    "audience": f"https://{auth0_domain}/api/v2/",
                },
            )
            # In case the API call fails, render the signup template with a non-field error
            if res.status_code != 200:
                user_form.add_error(None, "Something Went Wrong")
                return render(
                    request,
                    "users/new-ui/user_signup.html",
                    {
                        "user_form": user_form,
                        "organization_form": organization_form,
                        "next": quote(next_page),
                        "token": token,
                        "found_us_options": forms.FOUND_US_OPTIONS,
                        "elaborate": forms.FOUND_US_ELABORATE,
                        "client_id": auth0_id,
                        "redirect_uri": google_oauth_redir_uri,
                        "auth0_domain": auth0_domain,
                    },
                )
            resData = res.json()
            access_token = resData["access_token"]

            # Normalized Data
            user_data = user_form.cleaned_data
            # Call Auth0 to create a new user in the DB that this M2M client is authorized to use
            res = requests.post(
                url=f"https://{auth0_domain}/api/v2/users",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {access_token}"},
                json={"email": user_data.get("email"), "password": user_data.get("password"), "connection": auth0_db},
            )

            if res.status_code != 201:
                user_form.add_error(None, "Unable to process your data")
                print(f"user_form.data (Auth0 create user failed): {user_form.data}")
                return render(
                    request,
                    "users/new-ui/user_signup.html",
                    {
                        "user_form": user_form,
                        "organization_form": organization_form,
                        "next": quote(next_page),
                        "token": token,
                        "found_us_options": forms.FOUND_US_OPTIONS,
                        "elaborate": forms.FOUND_US_ELABORATE,
                        "client_id": auth0_id,
                        "redirect_uri": google_oauth_redir_uri,
                        "auth0_domain": auth0_domain,
                    },
                )
            # Push a new record in the native DB with an "unusable" password
            # Keeps it in sync with Auth0
            redirect_response = proceed_registration(request, user_form, organization_form, next_page)
            if redirect_response:
                return redirect_response

    return render(
        request,
        "users/new-ui/user_signup.html",
        {
            "user_form": user_form,
            "organization_form": organization_form,
            "next": quote(next_page),
            "token": token,
            "found_us_options": forms.FOUND_US_OPTIONS,
            "elaborate": forms.FOUND_US_ELABORATE,
            "client_id": auth0_id,
            "redirect_uri": google_oauth_redir_uri,
            "auth0_domain": auth0_domain,
        },
    )


@enforce_csrf_checks
def user_login(request):
    """Login page"""
    user = request.user
    next_page = request.GET.get("next")
    oauth_error = request.GET.get("oauth")

    # checks if the URL is a safe redirection.
    if not next_page or not url_has_allowed_host_and_scheme(url=next_page, allowed_hosts=request.get_host()):
        if flag_set("fflag_all_feat_dia_1777_ls_homepage_short", user):
            next_page = reverse("main")
        else:
            next_page = reverse("projects:project-index")

    login_form = load_func(settings.USER_LOGIN_FORM)
    form = login_form()

    # If OAuth fails, render the login template with an error field in its context
    if oauth_error:
        error_msg = "Invalid Token" if oauth_error == "invalid_token" else "Something Went Wrong"
        return render(
            request,
            "users/new-ui/user_login.html",
            {
                "form": form,
                "next": quote(next_page),
                "client_id": auth0_id,
                "redirect_uri": google_oauth_redir_uri,
                "auth0_domain": auth0_domain,
                "error_msg": error_msg
            },
        )

    if user.is_authenticated:
        return redirect(next_page)

    if request.method == "POST":
        form = login_form(request.POST)

        # Returns True only when the user exists in the native DB
        # LoginForm takes care of the search
        # If found, call Auth0 to validate the credentials
        if form.is_valid():
            creds = form.cleaned_data
            res = requests.post(
                url=f"https://{auth0_domain}/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
                    "username": creds.get("email"),
                    "password": creds.get("password"),
                    "audience": f"https://{auth0_domain}/api/v2/",
                    "client_id": auth0_m2m_id,
                    "client_secret": auth0_m2m_secret,
                    "realm": auth0_db,
                },
            )
            if res.status_code != 200:
                form.add_error(None, "Invalid Credentials")
                return render(
                    request,
                    "users/new-ui/user_login.html",
                    {
                        "form": form,
                        "next": quote(next_page),
                        "client_id": auth0_id,
                        "redirect_uri": google_oauth_redir_uri,
                        "auth0_domain": auth0_domain,
                    },
                )

            user = form.cleaned_data["user"]
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            if form.cleaned_data["persist_session"] is not True:
                # Set the session to expire when the browser is closed
                request.session["keep_me_logged_in"] = False
                request.session.set_expiry(0)

            # user is organization member
            org_pk = Organization.find_by_user(user).pk
            user.active_organization_id = org_pk
            user.save(update_fields=["active_organization"])
            return redirect(next_page)

    return render(
        request,
        "users/new-ui/user_login.html",
        {
            "form": form,
            "next": quote(next_page),
            "client_id": auth0_id,
            "redirect_uri": google_oauth_redir_uri,
            "auth0_domain": auth0_domain,
        },
    )


def google_callback_handler(request):
    """
    * Receives the authorization code as a query param
    * Hits Auth0 with the code for an ID token
    * A public key is needed to verify the JWT, since Auth0 uses an asymmetric signature
        - The public key ID is made available in the JWT header
        - For each of its tenants, Auth0 exposes an endpoint to retreive the keyset (JWKs).
    * If the key ID is found in the keyset, then the corresponding JWK is used to verify and decode the JWT.
    * For any error during the verification process, the login template is rendered with a relevant message.
    """
    code = request.GET.get("code")

    res = requests.post(
        f"https://{auth0_domain}/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "client_id": auth0_id,
            "client_secret": auth0_secret,
            "code": code,
            "redirect_uri": google_oauth_redir_uri,
        },
    )

    if res.status_code != 200:
        return redirect("/user/login?oauth=server_error")

    resData = res.json()
    id_token = resData["id_token"]
    id_token_header = jwt.get_unverified_header(id_token)
    key_id = id_token_header["kid"]

    # Fetch the public keyset or JWKS (JSON Web Key Set)
    res = requests.get(f"https://{auth0_domain}/.well-known/jwks.json")

    if res.status_code != 200:
        return redirect("/user/login?oauth=server_error")

    jwks = res.json()
    keys: List[dict] = jwks["keys"]

    # Search for key_id in the keyset
    # If found, use the corresponding key (JWK) for JWT verification
    public_key = None
    for k in keys:
        if k["kid"] == key_id:
            public_key = k
            break

    try:
        if not public_key:
            raise JOSEError()
        owner_info = jwt.decode(id_token, key=public_key, algorithms=["RS256"], audience=auth0_id)
    except JOSEError:
        return redirect("/user/login?oauth=invalid_token")

    email = owner_info["email"]
    next_page = reverse("projects:project-index")
    user = None

    # For fresh login, create a new record in the native DB with an unusable password
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        user = User.objects.create(email=email)
        user.set_unusable_password()
        user.save()

    # For consistency, this is copied from the original login flow
    if Organization.objects.exists():
        org = Organization.objects.first()
        org.add_user(user)
    else:
        org = Organization.create_organization(created_by=user, title="Label Studio")

    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    org_pk = Organization.find_by_user(user).pk
    user.active_organization_id = org_pk
    user.save(update_fields=["active_organization"])
    return redirect(next_page)


@login_required
def user_account(request, sub_path=None):
    """
    Handle user account view and profile updates.

    This view displays the user's profile information and allows them to update
    it. It requires the user to be authenticated and have an active organization
    or an organization_pk in the session.

    Args:
        request (HttpRequest): The request object.
        sub_path (str, optional): A sub-path parameter for potential URL routing.
            Defaults to None.

    Returns:
        HttpResponse: Renders the user account template with user profile form,
            or redirects to 'main' if no active organization is found,
            or redirects back to user-account after successful profile update.

    Notes:
        - Authentication is required (enforced by @login_required decorator)
        - Retrieves the user's API token for display in the template
        - Form validation happens on POST requests
    """
    user = request.user

    if user.active_organization is None and "organization_pk" not in request.session:
        return redirect(reverse("main"))

    form = forms.UserProfileForm(instance=user)
    token = Token.objects.get(user=user)

    if request.method == "POST":
        form = forms.UserProfileForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect(reverse("user-account"))

    return render(
        request,
        "users/user_account.html",
        {"settings": settings, "user": user, "user_profile_form": form, "token": token},
    )
