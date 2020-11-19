import setuptools

setuptools.setup(
    name='venafi-codesigning-gitlab-integration',
    version='1.0.0',
    author='Fullstaq',
    author_email='info@fullstaq.com',
    description='Venafi CodeSign Protect: Gitlab integration',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    url="https://github.com/fullstaq-labs/venafi-codesigning-gitlab-integration",
    platforms='any',
    zip_safe=False, # we require support/java/*.class
    packages=['venafi_codesigning_gitlab_integration'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'venafi-sign-jarsigner=venafi_codesigning_gitlab_integration.jarsigner_sign_command:main',
            'venafi-sign-signtool=venafi_codesigning_gitlab_integration.signtool_sign_command:main',
        ]
    },
    install_requires=[
        'envparse==0.2.0'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
)
