from setuptools import setup, find_packages
import os
import platform

DESCRIPTION = "A Django email backend for Mailgun"

LONG_DESCRIPTION = None
try:
    LONG_DESCRIPTION = open('README.rst').read()
except:
    pass

CLASSIFIERS = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.7'
    'Programming Language :: Python :: 3.4'
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Framework :: Django',
    'Framework :: Django :: 1.7',
    'Framework :: Django :: 1.8',
]

setup(
    name='django-mailgun',
    version='0.2.2',
    packages=['django_mailgun'],
    author='Bradley Whittington',
    author_email='radbrad182@gmail.com',
    url='http://github.com/bradwhittington/django-mailgun/',
    license='MIT',
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    platforms=['any'],
    install_requires=['requests'],
    classifiers=CLASSIFIERS,
    #TODO: get mailgun into pypi so it can be a requirement :)
)

