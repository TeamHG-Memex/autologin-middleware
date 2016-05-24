import uuid

from scrapy.utils.python import to_bytes
from twisted.internet import reactor
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET
from twisted.web.util import Redirect


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


def login(request):
    session_id = uuid.uuid4().hex.encode('ascii')
    SESSIONS[session_id] = True
    request.setHeader(b'set-cookie', b'_uctest_auth=' + session_id)


def logout(request):
    session_id = get_session_id(request)
    if session_id is not None:
        SESSIONS[session_id] = False
    request.setHeader(b'set-cookie', b'_uctest_auth=')


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
                login(request)
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
            logout(request)
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


class LoginWithContentAfterLogout(Login):
    class _Logout(Resource):
        isLeaf = True
        def __init__(self):
            Resource.__init__(self)

        def render_GET(self, request):
            logout(request)
            return Redirect(b'/target').render(request)

    def __init__(self):
        Login.__init__(self)
        self.putChild(b'hidden', authenticated_text(html(
            '<a href="/l0gout1">l0gout1</a> | '
        ))())
        self.putChild(b'l0gout1', self._Logout())
        self.putChild(b'target', text_resource(html('target'))())
