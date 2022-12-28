import setuptools
import os.path

with open('README.md', 'r', encoding='UTF-8') as f:
    long_description = f.read()

version_txt_path = os.path.join('venafi_codesigning_gitlab_integration', 'support', 'version.txt')
with open(version_txt_path, 'r', encoding='UTF-8') as f:
    version = f.read().strip()

setuptools.setup(
    name='venafi-codesigning-gitlab-integration',
    version=version,
    license='Apache 2.0',
    author='Qensus',
    author_email='venafi.oss@qensus.com',
    description='Venafi CodeSign Protect: Gitlab integration',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/qensus-labs/venafi-codesigning-gitlab-integration",
    platforms='any',
    zip_safe=False,  # we require support/*
    packages=['venafi_codesigning_gitlab_integration'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'venafi-version=venafi_codesigning_gitlab_integration.version_command:main',  # noqa:E501
            'venafi-container-init=venafi_codesigning_gitlab_integration.container_init_command:main',  # noqa:E501
            'venafi-sign-jarsigner=venafi_codesigning_gitlab_integration.jarsigner_sign_command:main',  # noqa:E501
            'venafi-verify-jarsigner=venafi_codesigning_gitlab_integration.jarsigner_verify_command:main',  # noqa:E501
            'venafi-sign-signtool=venafi_codesigning_gitlab_integration.signtool_sign_command:main',  # noqa:E501
            'venafi-verify-signtool=venafi_codesigning_gitlab_integration.signtool_verify_command:main',  # noqa:E501
        ]
    },
    install_requires=[
        'envparse>=0.2.0,<0.3'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)
