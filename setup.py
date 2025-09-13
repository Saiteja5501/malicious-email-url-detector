from setuptools import setup, find_packages

setup(
    name="malicious-email-url-detector",
    version="1.0.0",
    description="Smart Detection System for malicious emails and URLs",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "Flask==2.2.5",
        "Flask-Cors==5.0.0",
        "requests==2.27.1",
        "beautifulsoup4==4.13.5",
        "nltk==3.8.1",
        "textblob==0.17.1",
        "numpy>=1.21.0,<2.0.0",
        "scikit-learn>=1.0.0,<2.0.0",
        "scipy>=1.7.0,<2.0.0",
        "dnspython==2.3.0",
        "whois==0.9.27",
        "python-dateutil==2.9.0.post0",
        "pytz==2024.2",
    ],
    python_requires=">=3.11",
)