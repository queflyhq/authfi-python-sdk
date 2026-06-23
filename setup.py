from setuptools import setup

setup(
    name="authfi",
    version="0.1.0",
    description="AuthFI Python SDK — JWT validation, RBAC decorators, permission auto-sync",
    py_modules=["authfi"],
    python_requires=">=3.8",
    install_requires=["PyJWT[crypto]>=2.4.0"],
    author="Quefly",
    url="https://github.com/queflyhq/authfi-python-sdk",
    license="Apache-2.0",
    classifiers=[
        "Framework :: Flask",
        "Framework :: FastAPI",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
    ],
)
