# <one line to give the program's name and a brief idea of what it does.>
# Copyright (C) 2015 Jorge Costa

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


setup(
    name='pyBookshelf',
    version='3.0.2',
    description='Bookshelf of Fabric functions',
    author='Jorge Costa',
    author_email='pybookshelf@azulinho.com',
    url='https://www.github.com/pyBookshelf/Bookshelf/',
    packages=['bookshelf', 'bookshelf.api_v2', 'bookshelf.api_v3',
              'bookshelf.tests', 'bookshelf.tests.api_v2',
              'bookshelf.tests.api_v3', ],
    install_requires=['cuisine', 'fabric', 'pyrax', 'boto',
                      'google-api-python-client==1.4.2', 'oauth2client==1.5.2',
                      'zope.interface', 'flufl.enum', 'pyrsistent'],
    license='GPL v3',
)
