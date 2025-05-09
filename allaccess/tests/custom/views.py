import base64
import hashlib

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.encoding import force_str, smart_bytes

from allaccess.views import OAuthCallback, OAuthRedirect


class CustomRedirect(OAuthRedirect):
    """Redirect to custom callback."""

    def get_callback_url(self, provider):
        """Return the callback url for this provider."""
        return reverse('custom-callback', kwargs={'provider': provider.name})


class CustomCallback(OAuthCallback):
    """Create custom user on callback."""

    def get_or_create_user(self, provider, access, info):
        """Create a shell custom.MyUser."""
        email = info.get('email', None)
        if email is None:
            # No email was given by the provider so create a fake one
            digest = hashlib.sha1(smart_bytes(access)).digest()
            # Base 64 encode to get below 30 characters
            # Removed padding characters
            identifier = force_str(base64.urlsafe_b64encode(digest)).replace('=', '')
            email = f'{identifier}@example.com'
        User = get_user_model()
        kwargs = {
            'email': email,
            'password': None
        }
        return User.objects.create_user(**kwargs)
