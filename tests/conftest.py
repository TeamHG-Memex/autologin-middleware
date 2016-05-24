import os

import pytest


pytest_plugins = 'pytest_twisted'


def base_settings():
    return {
        'AUTOLOGIN_URL': 'http://127.0.0.1:8089',
        'AUTOLOGIN_ENABLED': True,
        # Higher fixed value to make the test more reliable
        'AUTOLOGIN_MAX_LOGOUT_COUNT': 8,
        'DOWNLOADER_MIDDLEWARES': {
            'autologin_middleware.AutologinMiddleware': 605,
        }
    }


@pytest.fixture(params=[False, True])  # use splash
def settings(request):
    use_splash = request.param
    s = base_settings()
    if use_splash:
        s.update({
            'SPLASH_URL': os.environ.get('SPLASH_URL', 'http://127.0.0.1:8050'),
            'SPLASH_COOKIES_DEBUG': True,
            'SPIDER_MIDDLEWARES': {
                'scrapy_splash.SplashDeduplicateArgsMiddleware': 100,
            },
            'DUPEFILTER_CLASS': 'scrapy_splash.SplashAwareDupeFilter',
        })
        s['DOWNLOADER_MIDDLEWARES'].update({
            'scrapy_splash.SplashCookiesMiddleware': 723,
            'scrapy_splash.SplashMiddleware': 725,
            'scrapy.downloadermiddlewares.httpcompression'
            '.HttpCompressionMiddleware': 810,
        })
    else:
        s.update({
            'COOKIES_ENABLED': True,
            'COOKIES_DEBUG': True,
        })
        s['DOWNLOADER_MIDDLEWARES'].update({
            'scrapy.downloadermiddlewares.cookies.CookiesMiddleware': None,
            'autologin_middleware.ExposeCookiesMiddleware': 700,
        })
    return s
