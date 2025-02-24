# setup.py

from setuptools import setup, find_packages

setup(
    name='django-users',
    version='0.2.09',
    packages=find_packages(),
    include_package_data=True,
    license='MIT License',
    description='A reusable Django app to manage users that also use keycloak for SSO.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/phoebebright/django-users',
    author='Phoebe Bright',
    author_email='phoebebright310@gmail.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
    ],
    install_requires=[
        'Django>=3.2,<5.3',
        'setuptools>=65.5.1',
    ],
)
