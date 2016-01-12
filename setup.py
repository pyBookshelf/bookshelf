from distutils.core import setup

setup(name='Bookshelf',
      version='1.1.16',
      description='Bookshelf of Fabric functions',
      author='ClusterHQ',
      author_email='nospam@clusterhq.com',
      url='https://www.github.com/ClusterHQ/Bookshelf/',
      packages=['bookshelf', ],
      install_requires=['cuisine', 'fabric', 'pyrax', 'boto',
                        'google-api-python-client', 'oauth2client'],
      license='Apache License, Version 2.0',
     )
