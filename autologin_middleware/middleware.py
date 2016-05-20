from copy import deepcopy
import json
import logging
from six.moves.http_cookies import SimpleCookie
from six.moves.urllib.parse import urljoin

import scrapy
from scrapy.downloadermiddlewares.cookies import CookiesMiddleware
from scrapy.exceptions import IgnoreRequest, NotConfigured
from scrapy.http.cookies import CookieJar
from twisted.internet.defer import inlineCallbacks, returnValue


logger = logging.getLogger(__name__)


class AutologinMiddleware:
    """
    Autologin middleware uses autologin to make all requests while being
    logged in. It uses autologin to get cookies, detects logouts and tries
    to avoid them in the future. A single authorization domain for the spider
    is assumed. Middleware also puts "autologin_active" into request.meta,
    which is True only if we are logged in (and False if domain is skipped
    or login failed).
    """
    def __init__(self, autologin_url, crawler):
        self.crawler = crawler
        s = crawler.settings
        self.passed_setting = {
            name: s.get(name) for name in [
                'SPLASH_URL', 'USER_AGENT', 'HTTP_PROXY', 'HTTPS_PROXY']
            if s.get(name)}
        self.autologin_url = autologin_url
        self.login_url = s.get('AUTOLOGIN_LOGIN_URL')
        self.username = s.get('AUTOLOGIN_USERNAME')
        self.password = s.get('AUTOLOGIN_PASSWORD')
        self.extra_js = s.get('AUTOLOGIN_EXTRA_JS')
        self.autologin_download_delay = s.get('AUTOLOGIN_DOWNLOAD_DELAY')
        self.logout_url = s.get('AUTOLOGIN_LOGOUT_URL')
        # _force_skip and _n_pend and for testing only
        self._force_skip = s.getbool('_AUTOLOGIN_FORCE_SKIP')
        self._n_pend = s.getint('_AUTOLOGIN_N_PEND')
        self._login_df = None
        self.max_logout_count = s.getint('AUTOLOGIN_MAX_LOGOUT_COUNT', 4)
        auth_cookies = s.get('AUTOLOGIN_COOKIES')
        self.skipped = False
        if auth_cookies:
            cookies = SimpleCookie()
            cookies.load(auth_cookies)
            self.auth_cookies = [
                {'name': m.key, 'value': m.value} for m in cookies.values()]
            self.logged_in = True
        else:
            self.auth_cookies = None
            self.logged_in = False

    @classmethod
    def from_crawler(cls, crawler):
        if not crawler.settings.getbool('AUTOLOGIN_ENABLED'):
            raise NotConfigured
        return cls(crawler.settings['AUTOLOGIN_URL'], crawler)

    @inlineCallbacks
    def process_request(self, request, spider):
        """ Login if we are not logged in yet.
        """
        if '_autologin' in request.meta or request.meta.get('skip_autologin'):
            returnValue(None)
        yield self._ensure_login(request, spider)
        if self.skipped:
            request.meta['autologin_active'] = False
            returnValue(None)
        elif self.logged_in:
            request.meta['autologin_active'] = True
            if self.logout_url and self.logout_url in request.url:
                logger.debug('Ignoring logout request %s', request.url)
                raise IgnoreRequest
            # Save original request to be able to retry it in case of logout
            req_copy = request.replace(meta=deepcopy(request.meta))
            req_copy.callback = req_copy.errback = None
            request.meta['_autologin'] = autologin_meta = {'request': req_copy}
            # TODO - it should be possible to put auth cookies into the
            # cookiejar in process_response (but also check non-splash)
            if self.auth_cookies:
                request.cookies = self.auth_cookies
                autologin_meta['cookie_dict'] = {
                    c['name']: c['value'] for c in self.auth_cookies}

    @inlineCallbacks
    def _ensure_login(self, request, spider):
        if not (self.skipped or self.logged_in):
            self._login_df = self._login_df or self._login(request, spider)
            yield self._login_df
            self._login_df = None

    @inlineCallbacks
    def _login(self, request, spider):
        while not (self.skipped or self.logged_in):
            login_request = self._login_request(request)
            response = yield self.crawler.engine.download(
                login_request, spider)
            response_data = json.loads(response.text)
            status = response_data['status']
            if self._force_skip:
                status = 'skipped'
            elif self._n_pend:
                self._n_pend -= 1
                status = 'pending'
            logger.debug('Got login response with status "%s"', status)
            if status == 'pending':
                continue
            elif status in {'skipped', 'error'}:
                self.auth_cookies = None
                self.skipped = True
                if status == 'error':
                    logger.error(
                        "Can't login; crawl will continue without auth.")
            elif status == 'solved':
                cookies = response_data.get('cookies')
                if cookies:
                    cookies = _cookies_to_har(cookies)
                    logger.debug('Got cookies after login %s', cookies)
                    self.auth_cookies = cookies
                    self.logged_in = True
                else:
                    logger.error('No cookies after login')
                    self.auth_cookies = None
                    self.skipped = True

    def _login_request(self, request):
        logger.debug('Attempting login at %s', request.url)
        autologin_endpoint = urljoin(self.autologin_url, '/login-cookies')
        params = {
            'url': urljoin(request.url, self.login_url)
                   if self.login_url else request.url,
            'username': self.username,
            'password': self.password,
            'extra_js': self.extra_js,
            'settings': {
                'ROBOTSTXT_OBEY': False,
            }
        }
        params['settings'].update(self.passed_setting)
        if self.autologin_download_delay:
            params['settings']['DOWNLOAD_DELAY'] = self.autologin_download_delay
        return scrapy.Request(
            autologin_endpoint, method='POST',
            body=json.dumps(params).encode(),
            headers={'content-type': 'application/json'},
            dont_filter=True,
            meta={'skip_autologin': True},
            priority=1000)

    @inlineCallbacks
    def process_response(self, request, response, spider):
        """ If we were logged out, login again and retry request.
        """
        if request.meta.get('_autologin') and self.is_logout(response):
            autologin_meta = request.meta['_autologin']
            retryreq = autologin_meta['request'].copy()
            retryreq.dont_filter = True
            logger.debug(
                'Logout at %s: %s', retryreq.url, _response_cookies(response))
            if self.logged_in:
                # We could have already done relogin after initial logout
                if any(autologin_meta['cookie_dict'].get(c['name']) !=
                        c['value'] for c in self.auth_cookies):
                    logger.debug('Request was stale, will retry %s', retryreq)
                else:
                    self.logged_in = False
                    # It's better to re-login straight away
                    yield self._ensure_login(retryreq, spider)
                    logout_count = retryreq.meta['autologin_logout_count'] = (
                        retryreq.meta.get('autologin_logout_count', 0) + 1)
                    if logout_count >= self.max_logout_count:
                        logger.debug('Max logouts exceeded, will not retry %s',
                                     retryreq)
                        raise IgnoreRequest
                    else:
                        logger.debug(
                            'Request caused log out (%d), still retrying %s',
                            logout_count, retryreq)
            returnValue(retryreq)
        returnValue(response)

    def is_logout(self, response):
        response_cookies = _response_cookies(response)
        if self.auth_cookies and response_cookies is not None:
            auth_keys = {c['name'] for c in self.auth_cookies if c['value']}
            response_keys = {
                name for name, value in response_cookies.items() if value}
            return bool(auth_keys - response_keys)


def _response_cookies(response):
    """ Return response cookies as a dict, or None if there are no cookies.
    """
    cookies = None
    if hasattr(response, 'cookiejar'):
        cookies = response.cookiejar
    else:
        for obj in response.flags:
            if isinstance(obj, CookieJar):
                cookies = obj
                break
    if cookies is not None:
        return {m.name: m.value for m in cookies}


def _cookies_to_har(cookies):
    """ Leave only documented cookie attributes.
    """
    return [_cookie_to_har(c) for c in cookies]


def _cookie_to_har(c):
    d = {
        'name': c['name'],
        'value': c['value'],
        'path': c.get('path', '/'),
    }
    # Do not set domain if domain_specified is False
    if c.get('domain') and c.get('domain_specified') != False:
        d['domain'] = c['domain']
    return d


class ExposeCookiesMiddleware(CookiesMiddleware):
    """
    This middleware appends CookieJar with current cookies to response flags.

    To use it, disable default CookiesMiddleware and enable
    this middleware instead::

        DOWNLOADER_MIDDLEWARES = {
            'scrapy.downloadermiddlewares.cookies.CookiesMiddleware': None,
            'autologin.middleware.ExposeCookiesMiddleware': 700,
        }

    """
    def process_response(self, request, response, spider):
        response = super(ExposeCookiesMiddleware, self).process_response(
            request, response, spider)
        cookiejarkey = request.meta.get('cookiejar')
        response.flags.append(self.jars[cookiejarkey])
        return response
