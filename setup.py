from setuptools import setup
import stinkypy

setup(
    name='stinkypy',
    version=stinkypy.__version__,
    packages=['stinkypy'],
    url='https://github.com/reddit/stinkypy',
    license='MIT',
    description='Library to aid in finding patterns associated with security issues within diffs',
    requires=['requests']
)
