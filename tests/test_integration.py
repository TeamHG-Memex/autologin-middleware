from __future__ import absolute_import

import json
import uuid
from six.moves.urllib.parse import urlsplit, urlunsplit
import tempfile

from flaky import flaky
import scrapy
from scrapy.crawler import CrawlerRunner
from scrapy.linkextractors import LinkExtractor
from scrapy.utils.log import configure_logging
from scrapy.utils.python import to_bytes
from scrapy_splash import SplashRequest
from twisted.internet import reactor
from twisted.trial.unittest import TestCase
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET
from twisted.web.util import Redirect

from autologin_middleware import AutologinMiddleware, link_looks_like_logout
from .mockserver import MockServer
from .conftest import inlineCallbacks, make_crawler, base_settings


configure_logging()


class TestSpider(scrapy.Spider):
    name = 'test_spider'

    def __init__(self, url):
        self.start_urls = [url]
        self.link_extractor = LinkExtractor()
        self.collected_items = []
        self.visited_urls = []
        super(TestSpider, self).__init__()

    def parse(self, response):
        p = urlsplit(response.url)
        self.visited_urls.append(
            urlunsplit(['', '', p.path, p.query, p.fragment]) or '/')
        urls = {link.url for link in
                self.link_extractor.extract_links(response)
                if not self._looks_like_logout(link, response)}
        for url in urls:
            yield self.make_request(url)

    def make_request(self, url):
        return scrapy.Request(url, callback=self.parse)

    def _looks_like_logout(self, link, response):
        if not self.settings.getbool('AUTOLOGIN_ENABLED') or not \
                response.meta.get('autologin_active'):
            return False
        return link_looks_like_logout(link)


def html(content):
    return '<html><head></head><body>{}</body></html>'.format(content)


def text_resource(content):
    class Page(Resource):
        isLeaf = True
        def render_GET(self, request):
            request.setHeader(b'content-type', b'text/html')
            return to_bytes(content)
    return Page


def get_session_id(request):
    return request.received_cookies.get(b'_uctest_auth')


def is_authenticated(request):
    session_id = get_session_id(request)
    if session_id not in SESSIONS:
        return False

    if SESSIONS[session_id]:
        return True
    else:
        request.setHeader(b'set-cookie', b'_uctest_auth=')
        return False


def authenticated_text(content, delay=0.0):
    class R(Resource):
        def render_GET(self, request):
            reactor.callLater(delay, self._delayedRender, request)
            return NOT_DONE_YET

        def _delayedRender(self, request):
            if not is_authenticated(request):
                result = Redirect(b'/login').render(request)
            else:
                result = content.encode()
            request.write(result)
            request.finish()
    return R


SESSIONS = {}  # session_id -> logged_in?


class Login(Resource):
    class _Login(Resource):
        isLeaf = True

        def render_GET(self, request):
            return html(
                '<form action="/login" method="POST">'
                '<input type="text" name="login">'
                '<input type="password" name="password">'
                '<input type="submit" value="Login">'
                '</form>').encode()

        def render_POST(self, request):
            if request.args[b'login'][0] == b'admin' and \
                    request.args[b'password'][0] == b'secret':
                session_id = uuid.uuid4().hex.encode('ascii')
                SESSIONS[session_id] = True
                request.setHeader(b'set-cookie', b'_uctest_auth=' + session_id)
            return Redirect(b'/').render(request)

    class _Index(Resource):
        isLeaf = True

        def render_GET(self, request):
            if is_authenticated(request):
                return html(
                    '<a href="/hidden">hidden</a> '
                    '<a href="/file.pdf">file.pdf</a>'
                ).encode()
            else:
                return html('<a href="/login">Login</a>').encode()

    def __init__(self):
        Resource.__init__(self)
        self.putChild(b'', self._Index())
        self.putChild(b'login', self._Login())
        self.putChild(b'hidden', authenticated_text(html('hidden resource'))())
        self.putChild(b'file.pdf', authenticated_text('data')())


class LoginIfUserAgentOk(Login):
    class _Login(Login._Login):
        def render_POST(self, request):
            user_agent = request.requestHeaders.getRawHeaders(b'User-Agent')
            if user_agent != [b'MyCustomAgent']:
                return html("Invalid User-Agent: %s" % user_agent).encode('utf8')
            return Login._Login.render_POST(self, request)


class LoginWithLogout(Login):
    class _Logout(Resource):
        isLeaf = True
        def __init__(self, delay=0.0):
            Resource.__init__(self)
            self.delay = delay

        def render_GET(self, request):
            session_id = get_session_id(request)
            if session_id is not None:
                SESSIONS[session_id] = False
            request.setHeader(b'set-cookie', b'_uctest_auth=')
            reactor.callLater(self.delay, self._delayedRender, request)
            return NOT_DONE_YET

        def _delayedRender(self, request):
            request.write(html('you have been logged out').encode())
            request.finish()

    def __init__(self):
        Login.__init__(self)
        self.putChild(b'hidden', authenticated_text(html(
            '<a href="/one">one</a> | '
            '<a href="/one?action=l0gout">one</a> | '     # LOGOUT_URL
            '<a href="/one?action=logout">one</a> | '     # _looks_like_logout
            '<a href="/one?action=lo9out">Logout</a> | '  # _looks_like_logout
            '<a href="/l0gout1">l0gout1</a> | '
            '<a href="/two">two</a> | '
            '<a href="/l0gout2">l0gout2</a> | '
            '<a href="/three">three</a> | '
            '<a href="/slow">slow</a>'
            ))())
        self.putChild(b'one', authenticated_text(html('1'))())
        self.putChild(b'l0gout1', self._Logout())
        self.putChild(b'two', authenticated_text(html('2'))())
        self.putChild(b'l0gout2', self._Logout(delay=0.2))
        self.putChild(b'three', authenticated_text(html('3'))())
        self.putChild(b'slow', authenticated_text(html('slow'), delay=1.0)())


@inlineCallbacks
def test_skip(settings):
    crawler = make_crawler(TestSpider, settings, _AUTOLOGIN_FORCE_SKIP=True)
    with MockServer(Login) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert set(spider.visited_urls) == {'/', '/login'}


AL_SETTINGS = {
    'AUTOLOGIN_USERNAME': 'admin',
    'AUTOLOGIN_PASSWORD': 'secret',
    'AUTOLOGIN_LOGIN_URL': '/login',
    'AUTOLOGIN_LOGOUT_URL': 'action=l0gout',
    'AUTOLOGIN_DOWNLOAD_DELAY': 0.01,
}


@flaky
@inlineCallbacks
def test_login(settings, SpiderCls=TestSpider):
    """ No logout links, just one page after login.
    """
    crawler = make_crawler(SpiderCls, settings, **AL_SETTINGS)
    with MockServer(Login) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 2
    assert set(spider.visited_urls) == {'/', '/hidden'}


@flaky
@inlineCallbacks
def test_login_with_logout(settings):
    """ Login with logout.
    """
    crawler = make_crawler(TestSpider, settings, **AL_SETTINGS)
    with MockServer(LoginWithLogout) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    mandatory_urls = {'/', '/hidden', '/one', '/two', '/three', '/slow'}
    spider_urls = set(spider.visited_urls)
    assert mandatory_urls.difference(spider_urls) == set()
    assert spider_urls.difference(
        mandatory_urls | {'/l0gout1', '/l0gout2'}) == set()


@inlineCallbacks
def test_pending(settings):
    crawler = make_crawler(
        TestSpider, settings, _AUTOLOGIN_N_PEND=3, **AL_SETTINGS)
    with MockServer(Login) as s:
        root_url = s.root_url
        yield crawler.crawl(url=root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 2
    assert set(spider.visited_urls) == {'/', '/hidden'}


@inlineCallbacks
def test_custom_headers(settings):
    crawler = make_crawler(
        TestSpider, settings, USER_AGENT='MyCustomAgent', **AL_SETTINGS)
    with MockServer(LoginIfUserAgentOk) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 2
    assert spider.visited_urls[1] == '/hidden'


def test_autologin_request():
    crawler = make_crawler(TestSpider, base_settings(),
                           SPLASH_URL='http://192.168.99.100:8050')
    mw = AutologinMiddleware('http://127.0.0.1:8089', crawler)
    al_request = mw._login_request(scrapy.Request('http://example.com'))
    data = json.loads(al_request.body.decode('utf-8'))
    assert al_request.dont_filter
    assert al_request.meta['proxy'] is None
    assert data['url'] == 'http://example.com'
    assert data['settings']['USER_AGENT'] == crawler.settings.get('USER_AGENT')
    assert data['settings'].get('SPLASH_URL') is None

    al_request = mw._login_request(SplashRequest('http://example.com'))
    data = json.loads(al_request.body.decode('utf-8'))
    assert data['url'] == 'http://example.com'
    assert data['settings']['SPLASH_URL'] == crawler.settings.get('SPLASH_URL')


class CustomParseSpider(TestSpider):
    def start_requests(self):
        for url in self.start_urls:
            yield self.make_request(url)

    def make_request(self, url):
        # Not serializable request on purpose, and a custom callback.
        return scrapy.Request(url, callback=lambda r: self.custom_parse(r))

    def parse(self, response):
        assert False

    def custom_parse(self, response):
        return super(CustomParseSpider, self).parse(response)


def test_custom_parse(settings):
    return test_login(settings, SpiderCls=CustomParseSpider)


class StoppingSpider(TestSpider):
    def start_requests(self):
        self.state['was_stopped'] = False
        for url in self.start_urls:
            yield self.make_request(url)

    def make_request(self, url):
        return scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        for item in super(StoppingSpider, self).parse(response):
            yield item
        if not self.state['was_stopped']:
            self.state['was_stopped'] = True
            self.crawler.stop()


@inlineCallbacks
def test_resume(settings):
    crawler = make_crawler(
        StoppingSpider, settings,
        JOBDIR=tempfile.mkdtemp(),
        SCHEDULER_DISK_QUEUE='scrapy.squeues.PickleFifoDiskQueue',
        SCHEDULER_MEMORY_QUEUE='scrapy.squeues.FifoMemoryQueue',
        LOG_UNSERIALIZABLE_REQUESTS=True,
        **AL_SETTINGS)
    with MockServer(Login) as s:
        yield crawler.crawl(url=s.root_url)
        # resuming crawl
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 1
    assert set(spider.visited_urls) == {'/hidden'}
