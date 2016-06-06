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

Autologin middleware uses autologin to make all requests while being
logged in. It uses autologin to get cookies, detects logouts and tries
to avoid them in the future. A single authorization domain for the spider
is assumed. Autologin middleware also puts ``autologin_active`` into
``request.meta``, which is ``True`` only if we are logged in
(and to ``False`` if domain is skipped or login failed).
If requests are made via `splash <http://splash.readthedocs.org>`_
(and ``SPLASH_URL`` is set),
autologin middleware passes it to autologin,
and this splash instance is also used to obtain login cookies.

Installation
------------

It works on python 2.7 and python 3, and requires at least scrapy 1.1.
Install with pip::

    pip install autologin-middleware


Configuration
-------------

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

There are some optional settings:

- ``AUTOLOGIN_COOKIES``: pass auth cookies after manual login
  (format is ``name=value; name2=value2``).
- ``AUTOLOGIN_LOGOUT_URL``: pass url substring to avoid.
- ``AUTOLOGIN_CHECK_LOGOUT``: set to ``False`` in order to disable automatic
  logout detection: it remembers cookies obtained during login and
  checks them on each response to see if any disappeared. This can be
  problematic for sites that set a lot of cookies on login,
  so this is an option to disable it.
  If you disable it, you must rely on avoiding logout links with
  ``link_looks_like_logout`` (see below), or setting a custom
  ``AUTOLOGIN_LOGOUT_URL``.
- ``AUTOLOGIN_USERNAME``, ``AUTOLOGIN_PASSWORD``, ``AUTOLOGIN_LOGIN_URL``,
  ``AUTOLOGIN_EXTRA_JS`` are passed to autologin and override values
  from stored credentials.  ``AUTOLOGIN_LOGIN_URL`` is a relative url,
  and can be omitted if it is the same as the start url.
  ``AUTOLOGIN_EXTRA_JS`` is required only if you want to use the ``extra_js``
  feature of the autologin.

It is also possible to override some settings per-request via corresponding
lower-case keys in ``request.meta``: ``autologin_username``,
``autologin_password``, ``autologin_extra_js``, ``autologin_login_url`` and
``autologin_logout_url``.

Autologin middleware passes the following settings to the autologin:
``SPLASH_URL``, ``USER_AGENT``, ``HTTP_PROXY``, ``HTTPS_PROXY``, so they
are used for autologin requests.

Avoiding logouts
----------------

There is also an utility ``autologin_middleware.link_looks_like_logout``
for checking if a links looks like a logout link: you can use it in the
spider to avoid logout links. Logouts are handled
by the autologin middleware by default
(unless ``AUTOLOGIN_CHECK_LOGOUT`` is ``False``),
but avoiding logout links can be beneficial for two reasons:

- no time is waster retrying requests that were logged out
- in some cases, logout urls can be unique, and the spider will be logging
  out continuously (for example, ``/logout?sid=UNIQUE_ID``).


Usage with Splash
-----------------

Autologin middleware supports splash via
`scrapy-splash <https://github.com/scrapy-plugins/scrapy-splash>`_,
but correctly settings everything up can be tricky.

First, you need to specify the following settings
(check scrapy-splash docs for more details)::

    SPLASH_URL = 'http://127.0.0.1:8050'
    SPIDER_MIDDLEWARES = {
        'scrapy_splash.SplashDeduplicateArgsMiddleware': 100,
    }
    DUPEFILTER_CLASS = 'scrapy_splash.SplashAwareDupeFilter'
    DOWNLOADER_MIDDLEWARES = {
        'autologin_middleware.AutologinMiddleware': 605,
        'scrapy_splash.SplashCookiesMiddleware': 723,
        'scrapy_splash.SplashMiddleware': 725,
        'scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware': 810,
    }

Second, you need to make requests to splash and pass cookies with
``splash:init_cookies(splash.args.cookies)``, and return them in the
``cookies`` field using ``splash:get_cookies()``. If you are already using
a splash script (``execute`` endpoint), modify your script accordingly.
But if you just want to crawl using splash, you can use
``autologin_middleware.splash.splash_request`` instead of ``scrapy.Request``.
It has a minimal lua script that passes cookies and returns html, so you won't
need to change anything else in you spider.


Development
-----------

You need to start ``autologin-http-api`` (from
`autologin <https://github.com/TeamHG-Memex/autologin>`_),
and `splash <http://splash.readthedocs.org>`_ (the easiest option is to run
``docker run -p 8050:8050 scrapinghub/splash``).

Run tests with tox::

    tox

When using Docker to run Splash on OS X and Windows, it will start on
a non-default address, so you need to specify it when running tests,
for example::

    SPLASH_URL=http://192.168.99.100:8050 tox


License
-------

License is MIT.
