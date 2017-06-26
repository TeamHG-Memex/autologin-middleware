from __future__ import absolute_import

import json
from six.moves.urllib.parse import urlsplit, urlunsplit
import tempfile

from flaky import flaky
from pytest import inlineCallbacks
import scrapy
from scrapy.crawler import CrawlerRunner
from scrapy.linkextractors import LinkExtractor
from scrapy.utils.log import configure_logging
from scrapy_splash import SplashRequest

from autologin_middleware import AutologinMiddleware, link_looks_like_logout
from autologin_middleware.splash import splash_request
from .mockserver import MockServer
from .conftest import base_settings
from .servers import Login, LoginWithLogout, LoginIfUserAgentOk, \
    LoginWithContentAfterLogout


configure_logging()


def make_crawler(settings, spider_cls=None, **extra_settings):
    settings.update(extra_settings)
    runner = CrawlerRunner(settings)
    return runner.create_crawler(spider_cls or TestSpider)


class TestSpider(scrapy.Spider):
    name = 'test_spider'

    def __init__(self, url):
        self.start_urls = [url]
        self.link_extractor = LinkExtractor()
        self.collected_items = []
        self.visited_urls = []
        self.responses = []
        super(TestSpider, self).__init__()

    def start_requests(self):
        for url in self.start_urls:
            yield self.make_request(url)

    def parse(self, response):
        self.responses.append(response)
        p = urlsplit(response.url)
        self.visited_urls.append(
            urlunsplit(['', '', p.path, p.query, p.fragment]) or '/')
        urls = {link.url for link in
                self.link_extractor.extract_links(response)
                if not self._looks_like_logout(link, response)}
        for url in urls:
            yield self.make_request(url)

    def make_request(self, url):
        req_fn = splash_request if self.settings.get('SPLASH_URL') else \
                 scrapy.Request
        return req_fn(url, callback=self.request_callback())

    def request_callback(self):
        return self.parse

    def _looks_like_logout(self, link, response):
        if not self.settings.getbool('AUTOLOGIN_ENABLED') or not \
                response.meta.get('autologin_active'):
            return False
        return link_looks_like_logout(link)


@inlineCallbacks
def test_skip(settings):
    crawler = make_crawler(settings, _AUTOLOGIN_FORCE_SKIP=True)
    with MockServer(Login) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert set(spider.visited_urls) == {'/', '/login'}
    assert all(not r.meta['autologin_active'] for r in spider.responses)


AL_SETTINGS = {
    'AUTOLOGIN_USERNAME': 'admin',
    'AUTOLOGIN_PASSWORD': 'secret',
    'AUTOLOGIN_LOGIN_URL': '/login',
    'AUTOLOGIN_LOGOUT_URL': 'action=l0gout',
    'AUTOLOGIN_DOWNLOAD_DELAY': 0.01,
}


@inlineCallbacks
def test_login(settings, extra_settings=None):
    """ No logout links, just one page after login.
    """
    crawler = make_crawler(settings, **AL_SETTINGS)
    with MockServer(Login) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 2
    assert set(spider.visited_urls) == {'/', '/hidden'}
    response = spider.responses[0]
    assert urlsplit(response.url).path.rstrip('/') == ''
    assert response.meta['autologin_active']
    assert response.meta['autologin_response']['status'] == 'solved'


@inlineCallbacks
def test_login_error(settings, extra_settings=None):
    """ Trying to login with wrong credentials
    """
    al_settings = dict(AL_SETTINGS)
    al_settings['AUTOLOGIN_PASSWORD'] = 'wrong'
    crawler = make_crawler(settings, **al_settings)
    with MockServer(Login) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 2
    assert set(spider.visited_urls) == {'/', '/login'}
    response = spider.responses[0]
    assert urlsplit(response.url).path.rstrip('/') == ''
    assert not response.meta['autologin_active']
    assert response.meta['autologin_response']['status'] == 'error'


class PassMetaSpider(TestSpider):
    def make_request(self, url):
        request = super(PassMetaSpider, self).make_request(url)
        request.meta.update({key: AL_SETTINGS[key.upper()] for key in [
            'autologin_username', 'autologin_password',
            'autologin_login_url', 'autologin_logout_url']})
        return request


@inlineCallbacks
def test_pass_via_meta(settings):
    crawler = make_crawler(settings, spider_cls=PassMetaSpider,
                           AUTOLOGIN_DOWNLOAD_DELAY=0.01)
    with MockServer(Login) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 2
    assert set(spider.visited_urls) == {'/', '/hidden'}


@flaky
@inlineCallbacks
def test_login_with_logout(settings, spider_cls=TestSpider):
    """ Login with logout.
    """
    crawler = make_crawler(settings, spider_cls=spider_cls, **AL_SETTINGS)
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
    crawler = make_crawler(settings, _AUTOLOGIN_N_PEND=3, **AL_SETTINGS)
    with MockServer(Login) as s:
        root_url = s.root_url
        yield crawler.crawl(url=root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 2
    assert set(spider.visited_urls) == {'/', '/hidden'}


@inlineCallbacks
def test_custom_headers(settings):
    crawler = make_crawler(settings, USER_AGENT='MyCustomAgent', **AL_SETTINGS)
    with MockServer(LoginIfUserAgentOk) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert len(spider.visited_urls) == 2
    assert spider.visited_urls[1] == '/hidden'


def test_autologin_request():
    crawler = make_crawler(
        base_settings(), SPLASH_URL='http://192.168.99.100:8050')
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
    def request_callback(self):
        # Not serializable request on purpose, and a custom callback.
        return lambda r: self.custom_parse(r)

    def parse(self, response):
        assert False

    def custom_parse(self, response):
        return super(CustomParseSpider, self).parse(response)


@flaky
def test_custom_parse(settings):
    return test_login_with_logout(settings, spider_cls=CustomParseSpider)


class StoppingSpider(TestSpider):
    def __init__(self, *args, **kwargs):
        super(StoppingSpider, self).__init__(*args, **kwargs)
        self.state = {}

    def start_requests(self):
        self.state['was_stopped'] = False
        return super(StoppingSpider, self).start_requests()

    def parse(self, response):
        for item in super(StoppingSpider, self).parse(response):
            yield item
        if not self.state.get('was_stopped'):
            self.state['was_stopped'] = True
            self.crawler.stop()


@inlineCallbacks
def test_resume(settings):
    crawler = make_crawler(
        settings, spider_cls=StoppingSpider,
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


@inlineCallbacks
def test_disable_logout(settings):
    crawler = make_crawler(settings, **AL_SETTINGS)
    with MockServer(LoginWithContentAfterLogout) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    assert set(spider.visited_urls) == {'/', '/hidden'}
    crawler = make_crawler(
        settings, AUTOLOGIN_CHECK_LOGOUT=False, **AL_SETTINGS)
    with MockServer(LoginWithContentAfterLogout) as s:
        yield crawler.crawl(url=s.root_url)
    spider = crawler.spider
    spider_urls = set(spider.visited_urls)
    assert set(spider.visited_urls) == {'/', '/hidden', '/target'}
