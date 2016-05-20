import os
from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='autologin-middleware',
    version='0.1.1',
    description='A Scrapy middleware to use with autologin',
    license='MIT',
    author='Konstantin Lopuhin, Mikhail Korobov',
    author_email='kostia.lopuhin@gmail.com',
    url='https://github.com/TeamHG-Memex/autologin-middleware',
    packages=['autologin_middleware'],
    long_description=read('README.rst'),
    install_requires=[
        'six',
        'scrapy>=1.1.0',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
