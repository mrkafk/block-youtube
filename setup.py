from setuptools import setup

setup(
    name='blocky',
    version='0.1',
    packages=['blocky'],
    install_requires=['dnspython', 'python-iptables', 'python-daemon', 'setproctitle', 'psutil'],
    url='https://github.com/mrkafk/block-youtube',
    license='MIT',
    author='Marcin Krol',
    author_email='mrkafk@gmail.com',
    description='Resolve and block IP addresses of a list of hostnames or domains periodically using iptables and ipset',
     classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python :: 2.7',
          'Topic :: System :: Systems Administration',
          'Topic :: Utilities',
    ],
    test_suite='tests',
    # scripts=[
    #      'bin/blocky',
    # ],
)
