from copy import deepcopy
import json
import logging
from six.moves.http_cookies import SimpleCookie
from six.moves.urllib.parse import urljoin

import scrapy
from scrapy.downloadermiddlewares.cookies import CookiesMiddleware
from scrapy.exceptions import IgnoreRequest, NotConfigured
from scrapy.http.cookies import CookieJar
from scrapy.utils.reqser import request_to_dict, request_from_dict
import tldextract
from twisted.internet.defer import inlineCallbacks, returnValue


logger = logging.getLogger(__name__)


class AutologinMiddleware(object):
    """
    Autologin middleware uses autologin to make all requests while being
    logged in. It uses autologin to get cookies, detects logouts and tries
    to avoid them in the future. A single authorization domain for the spider
    is assumed.
    Autologin response is available in response.meta['autologin_response'],
    if we made requests to autologin while processing this request.
    Middleware also puts 'autologin_active' into response.meta,
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
        self.check_logout = s.getbool('AUTOLOGIN_CHECK_LOGOUT', True)
        self.max_logout_count = s.getint('AUTOLOGIN_MAX_LOGOUT_COUNT', 4)
        self.stats = crawler.stats
        # _force_skip and _n_pend and for testing only
        self._force_skip = s.getbool('_AUTOLOGIN_FORCE_SKIP')
        self._n_pend = s.getint('_AUTOLOGIN_N_PEND')

        self._login_df = PerDomainState()
        self._skipped = PerDomainState()
        self._auth_cookies = PerDomainState()
        self._logged_in = PerDomainState()
        auth_cookies = s.get('AUTOLOGIN_COOKIES')
        if auth_cookies:
            auth_cookies_domain = s.get('AUTOLOGIN_COOKIES_DOMAIN')
            if not auth_cookies_domain:
                raise ValueError('Please specify AUTOLOGIN_COOKIES_DOMAIN in '
                                 'addition to AUTOLOGIN_COOKIES')
            cookies = SimpleCookie()
            cookies.load(auth_cookies)
            self._auth_cookies[auth_cookies_domain] = [
                {'name': m.key, 'value': m.value} for m in cookies.values()]
            self._logged_in[auth_cookies_domain] = True

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
        # FIXME - how do we handle it? count domains?
        # self.stats.set_value('autologin/logged_in', self._logged_in)
        if self._skipped[request]:
            request.meta['autologin_active'] = False
            returnValue(None)
        elif self._logged_in[request]:
            request.meta['autologin_active'] = True
            logout_url = request.meta.get(
                'autologin_logout_url', self.logout_url)
            if logout_url and logout_url in request.url:
                logger.info('Ignoring logout request {}'.format(request.url))
                raise IgnoreRequest
            # Save original request to be able to retry it in case of logout
            req_copy = request.replace(meta=deepcopy(request.meta))
            request.meta['_autologin'] = autologin_meta = {}
            try:
                autologin_meta['request'] = request_to_dict(
                    req_copy, spider=spider)
            except ValueError:
                # Serialization failed, but it might be ok if we do not persist
                # requests, so store the request itself here.
                autologin_meta['request'] = req_copy
            # TODO - it should be possible to put auth cookies into the
            # cookiejar in process_response (but also check non-splash)
            if self._auth_cookies[request]:
                request.cookies = self._auth_cookies[request]
                autologin_meta['cookie_dict'] = {
                    c['name']: c['value'] for c in self._auth_cookies[request]}

    def needs_login(self, request, spider):
        """ Whether this request needs to be performed while logged in.
        You can redefine this method in subclasses to customize which domains
        require login and which do not.
        """
        return True

    @inlineCallbacks
    def _ensure_login(self, request, spider):
        if (self.needs_login(request, spider) and
                not (self._skipped[request] or self._logged_in[request])):
            self._login_df[request] = (
                self._login_df[request] or self._login(request, spider))
            yield self._login_df[request]
            self._login_df[request] = None

    @inlineCallbacks
    def _login(self, request, spider):
        while not (self._skipped[request] or self._logged_in[request]):
            login_request = self.login_request(request, spider)
            logger.info('Attempting login at {} via {}'
                        .format(request.url, login_request.url))
            response = yield self.crawler.engine.download(
                login_request, spider)
            response_data = json.loads(response.text)
            request.meta['autologin_response'] = response_data
            status = response_data['status']
            if self._force_skip:
                status = 'skipped'
            elif self._n_pend:
                self._n_pend -= 1
                status = 'pending'
            logger.info('Got login response with status "{}"'.format(status))
            if status == 'pending':
                continue
            elif status in {'skipped', 'error'}:
                self._auth_cookies[request] = None
                self._skipped[request] = True
                if status == 'error':
                    logger.error(
                        "Can't login; crawl will continue without auth.")
            elif status == 'solved':
                cookies = response_data.get('cookies')
                if cookies:
                    cookies = _cookies_to_har(cookies)
                    logger.info('Got cookies after login {}'.format(cookies))
                    self._auth_cookies[request] = cookies
                    self._logged_in[request] = True
                else:
                    logger.error('No cookies after login')
                    self._auth_cookies[request] = None
                    self._skipped[request] = True

    def login_request(self, request, spider):
        autologin_endpoint = urljoin(self.autologin_url, '/login-cookies')
        meta = request.meta
        login_url = meta.get('autologin_login_url', self.login_url)
        params = {
            'url': urljoin(request.url, login_url)
                   if login_url else request.url,
            'username': meta.get('autologin_username', self.username),
            'password': meta.get('autologin_password', self.password),
            'extra_js': meta.get('autologin_extra_js', self.extra_js),
            'settings': {
                'ROBOTSTXT_OBEY': False,
            }
        }
        params['settings'].update(self.passed_setting)
        if 'splash' not in request.meta:
            # if request does not use splash, do not pass SPLASH_URL
            params['settings'].pop('SPLASH_URL', None)
        if self.autologin_download_delay:
            params['settings']['DOWNLOAD_DELAY'] = self.autologin_download_delay
        return scrapy.Request(
            autologin_endpoint, method='POST',
            body=json.dumps(params).encode(),
            headers={'content-type': 'application/json'},
            dont_filter=True,
            meta={'skip_autologin': True, 'proxy': None},
            priority=1000)

    @inlineCallbacks
    def process_response(self, request, response, spider):
        """ If we were logged out, login again and retry request.
        """
        if request.meta.get('_autologin') and self.is_logout(response):
            autologin_meta = request.meta['_autologin']
            if isinstance(autologin_meta['request'], dict):
                retryreq = request_from_dict(autologin_meta['request'], spider)
            else:
                retryreq = autologin_meta['request'].copy()
            retryreq.dont_filter = True
            logger.info('Logout at {}: {}'
                        .format(retryreq.url, _response_cookies(response)))
            if self._logged_in[request]:
                # We could have already done relogin after initial logout
                if any(autologin_meta['cookie_dict'].get(c['name']) !=
                        c['value'] for c in self._auth_cookies[request]):
                    logger.info('Request was stale, will retry {}'
                                .format(retryreq))
                else:
                    self._logged_in[request] = False
                    # It's better to re-login straight away
                    yield self._ensure_login(retryreq, spider)
                    logout_count = retryreq.meta['autologin_logout_count'] = (
                        retryreq.meta.get('autologin_logout_count', 0) + 1)
                    if logout_count >= self.max_logout_count:
                        logger.info('Max logouts exceeded, will not retry {}'
                                    .format(retryreq))
                        raise IgnoreRequest
                    else:
                        logger.info(
                            'Request caused log out ({}), still retrying {}'
                            .format(logout_count, retryreq))
            returnValue(retryreq)
        returnValue(response)

    def is_logout(self, response):
        if not self.check_logout:
            return False
        response_cookies = _response_cookies(response)
        if self._auth_cookies[response] and response_cookies is not None:
            auth_keys = {c['name'] for c in self._auth_cookies[response] if c['value']}
            response_keys = {
                name for name, value in response_cookies.items() if value}
            return bool(auth_keys - response_keys)
        return False


class PerDomainState(object):
    def __init__(self):
        self.state = {}

    def __getitem__(self, key):
        return self.state.get(self._get_key(key), None)

    def __setitem__(self, key, value):
        self.state[self._get_key(key)] = value

    def _get_key(self, request):
        if hasattr(request, 'url'):
            url = request.url
        else:
            url = request
        return _get_domain(url)


def _get_domain(url):
    return tldextract.extract(url).registered_domain.lower()


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
