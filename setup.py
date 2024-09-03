from setuptools import setup, find_packages

setup(
    name="wooklib",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "aiohttp",
        "cachetools"
    ],
    author="lalaio1",
    description="Uma biblioteca que facilita o discord",
    url="https://github.com/lalaio1/wooklib",
    python_requires='>=3.6',
)
