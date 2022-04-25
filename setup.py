#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(name='ViTee',
      version='1.2.0',
      description='Virus Total IOC analyzer',
      author='Mario Rojas',
      author_email='mariro_ch@hotmail.com',
      url='https://github.com/TURROKS/ViTee/',
      packages=find_packages(include=['scripts']),
      entry_points={
        'console_scripts': ['ViTee=vitee:main']
      },
      install_requires=[
                        'argparse',
                        'configparser>=5.2.0',
                        'iocextract>=1.13.1',
                        'pandas>=1.4.2',
                        'requests>=2.27.1',
                        'termcolor>=1.1.0',
                        'colorama'
      ],
      )
