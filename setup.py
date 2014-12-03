from setuptools import setup

setup(
    name='stinkypy',
    version='0.1',
    packages=['stinkypy'],
    url='https://github.com/JordanMilne/stinkypy',
    license='MIT',
    author='Jordan Milne',
    author_email='stinkypy@saynotolinux.com',
    description='Library to aid in finding patterns associated with security issues within diffs',
    requires=['requests']
)
