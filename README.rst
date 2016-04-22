Autologin middleware
====================

This is a a Scrapy middleware that uses
`autologin <https://github.com/TeamHG-Memex/autologin>`_ http-api
to maintain a logged-in state for a scrapy spider.

Include the autologin middleware into the project settings
and specify autologin url::

    AUTOLOGIN_URL = 'http://127.0.0.1:8089'
    AUTOLOGIN_ENABLED = True
    DOWNLOADER_MIDDLEWARES['autologin_middleware.AutologinMiddleware'] = 584

Cookie support is also required. There are currently several options:

- scrapy cookie middleware (``COOKIES_ENABLED = True``),
  but autologin middleware requires access to cookies, so you need to enable
  a custom cookie middleware::

    DOWNLOADER_MIDDLEWARES = {
        'autologin_middleware.AutologinMiddleware': 584,
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

There are some optional settings:

- ``AUTH_COOKIES``: pass auth cookies after manual login
  (format is ``name=value; name2=value2``)
- ``LOGOUT_URL``: pass url substring to avoid
- ``USERNAME``, ``PASSWORD``, ``LOGIN_URL`` are passed to autologin and
  override values from stored credentials. ``LOGIN_URL`` is a relative url,
  and can be omitted if it is the same as the start url.

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
