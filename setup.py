import setuptools, glob

setuptools.setup(
    name="example-pkg-YOUR-USERNAME-HERE",
    version="0.0.1",
    author="Fullstaq",
    author_email="info@fullstaq.com",
    description="A small example package",
    long_description='hi',
    long_description_content_type="text/markdown",
    url="https://github.com/fullstaq-labs/venafi-codesigning-gitlab-integration",
    entry_points={
        'console_scripts': [
            'sign-jarsigner=venafi_codesigning_gitlab_integration.jarsigner_sign_command:main',
            'sign-signtool=venafi_codesigning_gitlab_integration.signtool_sign_command:main',
        ]
    },
    packages=['venafi_codesigning_gitlab_integration'],
    include_package_data=True,
    install_requires=[
        'envparse==0.2.0'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
