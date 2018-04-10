from setuptools import setup
from aiorcon import __version__

with open('README.md') as f:
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
    long_description=readme,
    long_description_content_type='text/markdown'
)
