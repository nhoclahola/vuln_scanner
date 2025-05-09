from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="vuln_scanner",
    version="0.1.0",
    author="Your Name",
    author_email="youremail@example.com",
    description="Web Vulnerability Scanner using CrewAI and DeepSeek",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vuln_scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "vuln-scanner=vuln_scanner.main:main",
        ],
    },
) 