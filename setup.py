import setuptools

with open('README.md', 'r', encoding='UTF-8') as f:
    long_description = f.read()

setuptools.setup(
    name='venafi-codesigning-gitlab-integration',
    version='0.9.0',
    license='Apache 2.0',
    author='Fullstaq',
    author_email='info@fullstaq.com',
    description='Venafi CodeSign Protect: Gitlab integration',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/fullstaq-labs/venafi-codesigning-gitlab-integration",
    platforms='any',
    zip_safe=False,  # we require support/java/*.class
    packages=['venafi_codesigning_gitlab_integration'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
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
