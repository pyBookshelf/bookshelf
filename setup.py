try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


setup(
    name='Bookshelf',
    version='3.0.0',
    description='Bookshelf of Fabric functions',
    author='ClusterHQ',
    author_email='nospam@clusterhq.com',
    url='https://www.github.com/ClusterHQ/Bookshelf/',
    packages=['bookshelf', 'bookshelf.api_v2', 'bookshelf.api_v3',
              'bookshelf.tests', 'bookshelf.tests.api_v2',
              'bookshelf.tests.api_v3', ],
    install_requires=['cuisine', 'fabric', 'pyrax', 'boto',
                      'google-api-python-client==1.4.2', 'oauth2client==1.5.2',
                      'zope.interface', 'flufl.enum', 'pyrsistent'],
    license='Apache License, Version 2.0',
)
