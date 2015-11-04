from distutils.core import setup

setup(
    name='blocky',
    version='0.1',
    packages=['blocky'],
    install_requires=['dnspython', 'python-iptables'],
    url='https://github.com/mrkafk/block-youtube',
    license='MIT',
    author='Marcin Krol',
    author_email='mrkafk@gmail.com',
    description='Block YouTube IP addresses periodically in iptables',
     classifiers=[
          'Development Status :: 1 - Planning',
          'Environment :: Console',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python :: 2.7',
          'Topic :: System :: Systems Administration',
          'Topic :: Utilities',
    ],
    scripts=[
         'bin/blocky',
    ],
)
