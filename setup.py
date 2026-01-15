from setuptools import setup, find_packages

setup(
    name="sin",
    version="0.1.0",
    package_dir={"": "src"},  # Tells python the packages are under src/
    packages=find_packages(where="src"),
    install_requires=[
        "click",
        "python-dotenv",
        "pyyaml",
        "pydantic"
    ],
    entry_points={
        'console_scripts': [
            'sin=main:cli',
        ],
    },
)
