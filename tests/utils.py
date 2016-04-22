from urllib.parse import urlsplit, urlunsplit

import scrapy
from twisted.trial.unittest import TestCase
from twisted.web.resource import Resource
from scrapy.crawler import CrawlerRunner
from scrapy.linkextractors import LinkExtractor
from scrapy.utils.log import configure_logging
from scrapy.utils.python import to_bytes

from autologin_middleware import link_looks_like_logout


configure_logging()


class TestSpider(scrapy.Spider):
    name = 'test_spider'

    def __init__(self, url):
        self.start_urls = [url]
        self.link_extractor = LinkExtractor()
        self.collected_items = []
        self.visited_urls = []
        super().__init__(self)

    def parse(self, response):
        p = urlsplit(response.url)
        self.visited_urls.append(
            urlunsplit(['', '', p.path, p.query, p.fragment]) or '/')
        urls = {link.url for link in
                self.link_extractor.extract_links(response)
                if not self._looks_like_logout(link, response)}
        for url in urls:
            yield scrapy.Request(url, callback=self.parse)

    def _looks_like_logout(self, link, response):
        if not self.settings.getbool('AUTOLOGIN_ENABLED') or not \
                response.meta.get('autologin_active'):
            return False
        return link_looks_like_logout(link)


class SpiderTestCase(TestCase):
    settings = {}

    def setUp(self):
        settings = {
            'AUTOLOGIN_URL': 'http://127.0.0.1:8089',
            'AUTOLOGIN_ENABLED': True,
            'COOKIES_ENABLED': True,
            'COOKIES_DEBUG': True,
            'DOWNLOADER_MIDDLEWARES': {
                'autologin_middleware.AutologinMiddleware': 584,
                'scrapy.downloadermiddlewares.cookies.CookiesMiddleware': None,
                'autologin_middleware.ExposeCookiesMiddleware': 700,
            }
        }
        settings.update(self.settings)
        runner = CrawlerRunner(settings)
        self.crawler = runner.create_crawler(TestSpider)


def html(content):
    return '<html><head></head><body>{}</body></html>'.format(content)


def text_resource(content):
    class Page(Resource):
        isLeaf = True
        def render_GET(self, request):
            request.setHeader(b'content-type', b'text/html')
            return to_bytes(content)
    return Page
