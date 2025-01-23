from setuptools import setup, find_packages

setup(
    name="ShadowChat",
    version="1.0.0",
    description="A futuristic peer-to-peer encrypted messaging application",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Z3r0 S3c",
    author_email="z3r0s3c@greynodesecurity.com",
    maintainer="Grey Node Security",
    maintainer_email="admin@greynodesecurity.com",
    url="https://github.com/GreyNodeSecurity/ShadowChat",
    project_urls={
        "Documentation": "https://github.com/GreyNodeSecurity/ShadowChat/wiki",
        "Source": "https://github.com/GreyNodeSecurity/ShadowChat",
        "Tracker": "https://github.com/GreyNodeSecurity/ShadowChat/issues",
    },
    packages=find_packages(),  # Automatically discovers the packages
    include_package_data=True,  # Includes non-Python files specified in MANIFEST.in
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Telecommunications Industry",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Education",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
        "Topic :: Internet :: Chat",
        "Topic :: Utilities",
        "Topic :: Communications :: Chat",
        "Topic :: Communications :: Conferencing",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    keywords="peer-to-peer messaging encryption secure communication hackers gamers privacy",
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.11.0",
        "cryptography>=39.0.0",
        "PyQt5>=5.15.0",
    ],
    extras_require={
        "dev": ["pytest", "black", "flake8"],
    },
    entry_points={
        "console_scripts": [
            "shadowchat=shadowchat.main:main",  # Entry point for the main application
        ],
    },
    data_files=[
        ("docs", ["README.md", "LICENSE.md"]),  # Include documentation files
    ],
    zip_safe=False,  # Set to False if the package cannot be reliably used from a .zip file
)
