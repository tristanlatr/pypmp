from setuptools import find_packages, setup


setup(
    name="pypmp",
    version="0.3",
    license="GPL3",
    description="Python lib to interact with ManageEngine Password Manager Pro's REST API",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Philipp Schmitt",
    author_email="philipp.schmitt@post.lu",
    url="https://github.com/post-luxembourg/pypmp",
    packages=find_packages(),
    install_requires=["requests"],
)
