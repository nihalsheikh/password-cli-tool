from setuptools import setup, find_packages

setup(
    name="eigen-vault",
    version="1.0.0",
    author="Nihal Sheikh",
    description="A secure, enterprise-grade password manager and generator.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    py_modules=["eigen_vault"],
    install_requires=[
        "cryptography",
        "pyperclip",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "eigen=eigen_vault:main",
            "eigen-vault=eigen_vault:main",
            "ev=eigen_vault:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
)
