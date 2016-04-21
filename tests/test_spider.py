# -*- coding: utf-8 -*-
from __future__ import absolute_import

import uuid

from twisted.internet import defer, reactor
from twisted.web.resource import Resource
from twisted.web.util import Redirect
from twisted.web.server import NOT_DONE_YET

from .mockserver import MockServer
from .utils import html, SpiderTestCase


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


def authenticated_text(content, delay=0):
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
                session_id = bytes(uuid.uuid4().hex, 'ascii')
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
        super().__init__()
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
            return super(LoginIfUserAgentOk._Login, self).render_POST(request)


class LoginWithLogout(Login):
    class _Logout(Resource):
        isLeaf = True

        def render_GET(self, request):
            session_id = get_session_id(request)
            if session_id is not None:
                SESSIONS[session_id] = False
            request.setHeader(b'set-cookie', b'_uctest_auth=')
            return html('you have been logged out').encode()

    def __init__(self):
        super().__init__()
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
        self.putChild(b'l0gout2', self._Logout())
        self.putChild(b'three', authenticated_text(html('3'))())
        self.putChild(b'slow', authenticated_text(html('slow'), delay=1.0)())


# TODO
#class TestSkip(TestBasic):
#    settings = {'_AUTOLOGIN_FORCE_SKIP': True}


class TestAutologin(SpiderTestCase):
    settings = {
        'USERNAME': 'admin',
        'PASSWORD': 'secret',
        'LOGIN_URL': '/login',
        'LOGOUT_URL': 'action=l0gout',
        'AUTOLOGIN_DOWNLOAD_DELAY': 0.01,
    }

    @defer.inlineCallbacks
    def test_login(self):
        ''' No logout links, just one page after login.
        '''
        with MockServer(Login) as s:
            yield self.crawler.crawl(url=s.root_url)
        spider = self.crawler.spider
        assert len(spider.visited_urls) == 2
        assert set(spider.visited_urls) == {'/', '/hidden'}

    @defer.inlineCallbacks
    def test_login_with_logout(self):
        ''' Login with logout.
        '''
        with MockServer(LoginWithLogout) as s:
            yield self.crawler.crawl(url=s.root_url)
        spider = self.crawler.spider
        assert set(spider.visited_urls) == \
               {'/', '/hidden', '/one', '/two', '/three', '/slow'}


class TestPending(SpiderTestCase):
    settings = {
        'USERNAME': 'admin',
        'PASSWORD': 'secret',
        'LOGIN_URL': '/login',
        'LOGOUT_URL': 'action=l0gout',
        'AUTOLOGIN_DOWNLOAD_DELAY': 0.01,
        '_AUTOLOGIN_N_PEND': 3,
    }

    @defer.inlineCallbacks
    def test_login(self):
        with MockServer(Login) as s:
            root_url = s.root_url
            yield self.crawler.crawl(url=root_url)
        spider = self.crawler.spider
        assert len(spider.visited_urls) == 2
        assert set(spider.visited_urls) == {'/', '/hidden'}


class TestAutoLoginCustomHeaders(SpiderTestCase):
    settings = {
        'USERNAME': 'admin',
        'PASSWORD': 'secret',
        'LOGIN_URL': '/login',
        'USER_AGENT': 'MyCustomAgent',
        'AUTOLOGIN_DOWNLOAD_DELAY': 0.01,
    }

    @defer.inlineCallbacks
    def test_login(self):
        with MockServer(LoginIfUserAgentOk) as s:
            yield self.crawler.crawl(url=s.root_url)
        spider = self.crawler.spider
        assert len(spider.visited_urls) == 2
        assert spider.visited_urls[1] == '/hidden'
