from setuptools import setup
from aiorcon import __version__

with open('README.rst') as f:
    readme = f.read()

setup(
    name='aiorcon',
    version=__version__,
    packages=['aiorcon'],
    url='https://github.com/Sebass13/aiorcon',
    license='GPL-3.0',
    author='Sebastian',
    author_email='sebikele@gmail.com',
    description='An asynchronous interface for the Source RCON Protocol.',
    classifiers=(
        'Development Status :: 3 - Alpha',
        'Framework :: AsyncIO',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Games/Entertainment'
    ),
    long_description=readme,
)
