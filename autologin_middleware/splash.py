from scrapy_splash import SplashRequest


LUA_SOURCE = """
function main(splash)
    splash:init_cookies(splash.args.cookies)
    local ok, reason = splash:go{
        splash.args.url,
        headers=splash.args.headers,
        http_method=splash.args.http_method,
        body=splash.args.body,
    }
    if ok then
        assert(splash:wait(0.5))
    end

    local entries = splash:history()
    if #entries > 0 then
        local last_response = entries[#entries].response
        return {
            url=splash:url(),
            headers=last_response.headers,
            cookies=splash:get_cookies(),
            html=splash:html(),
            http_status=last_response.status,
        }
    else
        error(reason)
    end
end
"""


def splash_request(*args, **kwargs):
    kwargs['endpoint'] = 'execute'
    splash_args = kwargs.setdefault('args', {})
    splash_args['lua_source'] = LUA_SOURCE
    return SplashRequest(*args, **kwargs)