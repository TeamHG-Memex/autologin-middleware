import os
from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name = "autologin-middleware",
    version = "0.1.0",
    description = "A Scrapy middleware to use with autologin",
    license = "BSD",
    url = "https://github.com/TeamHG-Memex/autologin-middleware",
    packages = ['autologin_middleware'],
    long_description=read('README.rst'),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: Web scraping, Utilities',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
       #'Programming Language :: Python :: 2',
       #'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
