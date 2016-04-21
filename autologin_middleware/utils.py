def link_looks_like_logout(link):
    """
    Return True is link looks like a logout link.
    This is not a part of AutologinMiddleware because we need a link,
    not just the URL (link text is also used).
    >>> from scrapy.link import Link
    >>> link_looks_like_logout(Link('/logout', text='Log out'))
    True
    >>> link_looks_like_logout(Link('/Logout-me', text='Exit'))
    True
    >>> link_looks_like_logout(Link('/exit', text='Log out'))
    True
    >>> link_looks_like_logout(Link('/exit', text='Logout'))
    True
    >>> link_looks_like_logout(Link('/exit', text='Exit'))
    False
    """
    text = link.text.lower()
    if any(x in text for x in ['logout', 'log out']):
        return True
    if url_looks_like_logout(link.url):
        return True
    return False


def url_looks_like_logout(url):
    return 'logout' in url.lower()
