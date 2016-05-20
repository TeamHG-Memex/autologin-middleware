Autologin middleware
====================

.. image:: https://img.shields.io/pypi/v/autologin-middleware.svg
   :target: https://pypi.python.org/pypi/autologin-middleware
   :alt: PyPI Version

.. image:: https://img.shields.io/travis/TeamHG-Memex/autologin-middleware/master.svg
   :target: http://travis-ci.org/TeamHG-Memex/autologin-middleware
   :alt: Build Status

.. image:: https://codecov.io/github/TeamHG-Memex/autologin-middleware/coverage.svg?branch=master
   :target: https://codecov.io/github/TeamHG-Memex/autologin-middleware?branch=master
   :alt: Code Coverage

This is a a Scrapy middleware that uses
`autologin <https://github.com/TeamHG-Memex/autologin>`_ http-api
to maintain a logged-in state for a scrapy spider.

Install with pip::

    pip install autologin-middleware

Include the autologin middleware into the project settings
and specify autologin url::

    AUTOLOGIN_URL = 'http://127.0.0.1:8089'
    AUTOLOGIN_ENABLED = True
    DOWNLOADER_MIDDLEWARES['autologin_middleware.AutologinMiddleware'] = 605

Cookie support is also required. There are currently several options:

- scrapy cookie middleware (``COOKIES_ENABLED = True``),
  but autologin middleware requires access to cookies, so you need to enable
  a custom cookie middleware::

    DOWNLOADER_MIDDLEWARES = {
        'autologin_middleware.AutologinMiddleware': 605,
        'scrapy.downloadermiddlewares.cookies.CookiesMiddleware': None,
        'autologin_middleware.ExposeCookiesMiddleware': 700,
    }

- `scrapy-splash <https://github.com/scrapy-plugins/scrapy-splash>`_
  cookie middleware (``scrapy_splash.SplashCookiesMiddleware``)
- any other middleware that gets cookies from ``request.cookies`` and
  sets ``response.cookiejar`` like scrapy-splash middleware,
  or exposes them in ``response.flags`` like ``ExposeCookiesMiddleware``.

Autologin middleware uses autologin to make all requests while being
logged in. It uses autologin to get cookies, detects logouts and tries
to avoid them in the future. A single authorization domain for the spider
is assumed. Autologin middleware also puts ``autologin_active`` into
``request.meta``, which is ``True`` only if we are logged in
(and to ``False`` if domain is skipped or login failed).
If requests are made via splash (and ``SPLASH_URL`` is set),
autologin middleware passes it to autologin,
and this splash instance is also used to obtain login cookies.

There are some optional settings:

- ``AUTOLOGIN_COOKIES``: pass auth cookies after manual login
  (format is ``name=value; name2=value2``).
- ``AUTOLOGIN_LOGOUT_URL``: pass url substring to avoid.
- ``AUTOLOGIN_USERNAME``, ``AUTOLOGIN_PASSWORD``, ``AUTOLOGIN_LOGIN_URL``,
  ``AUTOLOGIN_EXTRA_JS`` are passed to autologin and override values
  from stored credentials.  ``AUTOLOGIN_LOGIN_URL`` is a relative url,
  and can be omitted if it is the same as the start url.
  ``AUTOLOGIN_EXTRA_JS`` is required only if you want to use the ``extra_js``
  feature of the autologin.

Autologin middleware passes the following settings to the autologin:
``SPLASH_URL``, ``USER_AGENT``, ``HTTP_PROXY``, ``HTTPS_PROXY``, so they
are used for autologin requests.

There is also an utility ``autologin_middleware.link_looks_like_logout``
for checking if a links looks like a logout link: you can use it in the
spider to avoid logout links. Logouts are handled
by the autologin middleware anyway,
but avoiding logout links can be beneficial for two reasons:

- no time is waster retrying requests that were logged out
- in some cases, logout urls can be unique, and the spider will be logging
  out continuously (for example, ``/logout?sid=UNIQUE_ID``).

Check ``tests.utils.TestSpider`` for an example of a minimal spider
that uses ``link_looks_like_logout``, and an example of project settings.

License is MIT.
