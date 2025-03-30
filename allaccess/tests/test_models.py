"""Models and field encryption tests."""
from itertools import product
from .base import AccountAccess, AllAccessTestCase, Provider
from allaccess.fields import SignatureException


class ProviderTestCase(AllAccessTestCase):
    """Custom provider methods and key/secret encryption."""
    encrypted_fields = ['consumer_key', 'consumer_secret']

    def setUp(self):
        # provider with emtpy encrypted fields
        self.provider = self.create_provider()

    def test_save_empty_value(self):
        """None/blank key should normalize to None which is not encrypted."""
        values = [
            (0, '0'),
            ('', None),
            (None, None),
            ('foo', 'foo'),
        ]
        for field, value in product(self.encrypted_fields, values):
            with self.subTest(field=field, value=value):
                setattr(self.provider, field, value[0])
                self.provider.save()
                with self.assertNumQueries(1):
                    self.provider.refresh_from_db()
                self.assertEqual(getattr(self.provider, field), value[1])

    def test_encrypted_save(self):
        """Encrypt on save; decrypt on get."""
        values = [self.get_random_string(), self.get_random_string()]
        for field, value in zip(self.encrypted_fields, values):
            with self.subTest(field=field, value=value):
                setattr(self.provider, field, value)
                self.provider.save()
                provider = (
                    Provider.objects
                    .extra(select={'raw_value': field})
                    .get(pk=self.provider.pk)
                )
                # raw value is encrypted
                self.assertNotEqual(provider.raw_value, value)
                self.assertTrue(provider.raw_value.startswith('$AES$'))
                # value can be read back decrypted
                self.assertEqual(getattr(provider, field), value)

    def test_encrypted_read(self):
        """Encrypt/decrypt with SECRET_KEY"""
        self.provider.consumer_key = value = self.get_random_string()

        with self.settings(SECRET_KEY='foo'):
            self.provider.save()
            self.provider.refresh_from_db()
            self.assertEqual(self.provider.consumer_key, value)

        with self.settings(SECRET_KEY='bar'):
            # exception raises on db query, not field access
            with self.assertRaises(SignatureException):
                self.provider.refresh_from_db()
            with self.assertRaises(SignatureException):
                Provider.objects.get(pk=self.provider.pk)
            with self.assertRaises(SignatureException):
                Provider.objects.first()
            with self.assertRaises(SignatureException):
                list(Provider.objects.all())

        with self.settings(SECRET_KEY='foo'):
            self.provider.refresh_from_db()
            self.assertEqual(self.provider.consumer_key, value)


class AccountAccessTestCase(AllAccessTestCase):
    """Custom AccountAccess methods and access token encryption."""

    def setUp(self):
        self.access = self.create_access()

    def test_save_empty_token(self):
        """None/blank access token should normalize to None which is not encrypted."""
        self.access.access_token = ''
        self.access.save()
        self.access.refresh_from_db()
        self.assertEqual(self.access.access_token, None)

        self.access.access_token = None
        self.access.save()
        self.access.refresh_from_db()
        self.assertEqual(self.access.access_token, None)

    def test_encrypted_save(self):
        """Encrypt access token on save."""
        access_token = self.get_random_string()
        self.access.access_token = access_token
        self.access.save()
        access = AccountAccess.objects.extra(
            select={'raw_token': 'access_token'}
        ).get(pk=self.access.pk)
        self.assertNotEqual(access.raw_token, access_token)
        self.assertTrue(access.raw_token.startswith('$AES$'))
        self.assertEqual(access.access_token, access_token, 'Token should be unencrypted on fetch.')

    def test_encrypted_update(self):
        """Access token should be encrypted on update."""
        access_token = self.get_random_string()
        AccountAccess.objects.filter(pk=self.access.pk).update(access_token=access_token)
        access = AccountAccess.objects.extra(
            select={'raw_token': 'access_token'}
        ).get(pk=self.access.pk)
        self.assertNotEqual(access.raw_token, access_token)
        self.assertTrue(access.raw_token.startswith('$AES$'))
        self.assertEqual(access.access_token, access_token, 'Token should be unencrypted on fetch.')

    def test_fetch_api_client(self):
        """Get API client with the provider and user token set."""
        access_token = self.get_random_string()
        self.access.access_token = access_token
        self.access.save()
        self.access.refresh_from_db()
        api = self.access.api_client
        self.assertEqual(api.provider, self.access.provider)
        self.assertEqual(api.token, self.access.access_token)
