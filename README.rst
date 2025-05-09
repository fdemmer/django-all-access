django-all-access
===================

|Build| |Coverage| |PyPI Download| |PyPI Python Versions| |PyPI License|

.. |Build| image:: https://github.com/fdemmer/django-all-access/actions/workflows/main.yml/badge.svg?branch=master
    :target: https://github.com/fdemmer/django-all-access/actions?workflow=CI

.. |Coverage| image:: https://codecov.io/gh/fdemmer/django-all-access/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/fdemmer/django-all-access

.. |PyPI Download| image:: https://img.shields.io/pypi/v/fdemmer-django-all-access.svg
   :target: https://pypi.python.org/pypi/fdemmer-django-all-access/

.. |PyPI Python Versions| image:: https://img.shields.io/pypi/pyversions/fdemmer-django-all-access.svg
   :target: https://pypi.python.org/pypi/fdemmer-django-all-access/

.. |PyPI License| image:: https://img.shields.io/pypi/l/fdemmer-django-all-access.svg
   :target: https://pypi.python.org/pypi/fdemmer-django-all-access/


django-all-access is a reusable application for user registration and authentication
from OAuth 1.0 and OAuth 2.0 providers such as Twitter and Facebook.

The goal of this project is to make it easy to create your own workflows for
authenticating with these remote APIs. django-all-access will provide the simple
views with sane defaults along with hooks to override the default behavior.

This is a fork to provide updates for compatibility and a package on PyPI only.

django-all-access was originally authored by `Mark Lavin <https://mlavin.org/>`_.


Features
------------------------------------

- Sane and secure defaults for OAuth authentication
- Easy customization through class-based views
- Built using the amazing `requests <https://requests.readthedocs.io/en/master/>`_ library


Installation
------------------------------------

It is easiest to install this fork of django-all-access using pip:

.. code-block:: shell

    pip install fdemmer-django-all-access


django-all-access requires Python & Django along with the following Python
packages (which are automatically installed if necessary):

.. code-block:: text

    pycryptodome>=3.9
    requests>=2.0
    requests_oauthlib>=0.4.2
    oauthlib>=0.6.2


Configuration
--------------------------------------

``ALL_ACCESS_SECRET_KEY``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default ``SECRET_KEY`` is used by ``EncryptedField`` to encrypt ``Provider.consumer_key``,
``Provider.consumer_secret`` and ``AccountAccess.access_token``.
Alternatively you can explicitly configure an encryption key using
``ALL_ACCESS_SECRET_KEY``.

*Tip*: To generate secrets use ``get_random_secret_key()`` from ``django.core.management.utils``.

``ALL_ACCESS_DISABLED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To avoid passing around secret keys and still being able to work with encrypted data,
you can disable decryption of ``EncryptedField`` values by setting ``ALL_ACCESS_DISABLED``
to ``True``.

With this setting enabled, ``EncryptedField`` return the encrypted value instead.
Modifying the encrypted value will almost certainly break decrypting it later.

Be aware, that this is a workaround for development environments only and will break
all functionality of django-all-access aside from reading the ``Provider`` and
``AccountAccess`` models.


Documentation
--------------------------------------

Additional documentation on using django-all-access is available on
`Read The Docs <https://django-all-access.readthedocs.io/en/latest/>`_.


Releases
--------------------------------------

`Changelog <https://github.com/fdemmer/django-all-access/blob/master/docs/releases.rst>`_.


License
--------------------------------------

django-all-access is released under the BSD License. See the
`LICENSE <https://github.com/fdemmer/django-all-access/blob/master/LICENSE>`_
file for more details.


Contributing
--------------------------------------

If you have questions about using django-all-access or want to follow updates about
the project you can join the `mailing list <https://groups.google.com/group/django-all-access>`_
through Google Groups.

If you think you've found a bug or are interested in contributing to this project
check out `django-all-access on Github <https://github.com/fdemmer/django-all-access>`_.
