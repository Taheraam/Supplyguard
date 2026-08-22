Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp> pipx install supplyguard
pipx : The term 'pipx' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or
if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ pipx install supplyguard
+ ~~~~
    + CategoryInfo          : ObjectNotFound: (pipx:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp> pip install supplyguard
ERROR: Could not find a version that satisfies the requirement supplyguard (from versions: none)
ERROR: No matching distribution found for supplyguard

[notice] A new release of pip is available: 24.0 -> 26.2.1
[notice] To update, run: C:\Users\Aryan Pandey\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe -m pip install --upgrade pip
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp>
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp> docker build -t supplyguard .
ERROR: error during connect: Head "http://%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/_ping": open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp> docker run --rm -v $(pwd):/src supplyguard scan /src
docker: invalid reference format

Run 'docker run --help' for more information
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp> git clone https://github.com/Taheraam/Supplyguard.git
Cloning into 'Supplyguard'...
remote: Enumerating objects: 93, done.
remote: Counting objects: 100% (93/93), done.
remote: Compressing objects: 100% (78/78), done.
remote: Total 93 (delta 7), reused 93 (delta 7), pack-reused 0 (from 0)
Receiving objects: 100% (93/93), 1.21 MiB | 5.10 MiB/s, done.
Resolving deltas: 100% (7/7), done.
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp> cd Supplyguard
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> python -m venv .venv
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
source : The term 'source' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name,
or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
+ ~~~~~~
    + CategoryInfo          : ObjectNotFound: (source:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> pip install -e ".[dev]"
Obtaining file:///C:/Users/Aryan%20Pandey/OneDrive/Documents/DemoVulnerableApp/Supplyguard
  Installing build dependencies ... done
  Checking if build backend supports build_editable ... done
  Getting requirements to build editable ... done
  Preparing editable metadata (pyproject.toml) ... done
Collecting click>=8.1.0 (from supplyguard==0.3.0)
  Downloading click-8.4.2-py3-none-any.whl.metadata (2.6 kB)
Collecting flask>=3.0.0 (from supplyguard==0.3.0)
  Downloading flask-3.1.3-py3-none-any.whl.metadata (3.2 kB)
Collecting sqlalchemy>=2.0.0 (from supplyguard==0.3.0)
  Downloading sqlalchemy-2.0.52-cp311-cp311-win_amd64.whl.metadata (9.9 kB)
Collecting requests>=2.31.0 (from supplyguard==0.3.0)
  Downloading requests-2.34.2-py3-none-any.whl.metadata (4.8 kB)
Collecting cyclonedx-bom>=3.11.0 (from supplyguard==0.3.0)
  Downloading cyclonedx_bom-7.3.1-py3-none-any.whl.metadata (9.3 kB)
Collecting rich>=13.0.0 (from supplyguard==0.3.0)
  Downloading rich-15.0.0-py3-none-any.whl.metadata (18 kB)
Collecting pyyaml>=6.0 (from supplyguard==0.3.0)
  Downloading pyyaml-6.0.3-cp311-cp311-win_amd64.whl.metadata (2.4 kB)
Collecting anthropic>=0.20.0 (from supplyguard==0.3.0)
  Downloading anthropic-1.0.0-py3-none-any.whl.metadata (3.3 kB)
Collecting pytest>=7.0.0 (from supplyguard==0.3.0)
  Downloading pytest-9.1.1-py3-none-any.whl.metadata (7.6 kB)
Collecting pytest-mock>=3.10.0 (from supplyguard==0.3.0)
  Downloading pytest_mock-3.15.1-py3-none-any.whl.metadata (3.9 kB)
Collecting responses>=0.23.0 (from supplyguard==0.3.0)
  Downloading responses-0.26.2-py3-none-any.whl.metadata (48 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 48.4/48.4 kB 2.4 MB/s eta 0:00:00
Collecting ruff>=0.1.0 (from supplyguard==0.3.0)
  Downloading ruff-0.16.4-py3-none-win_amd64.whl.metadata (26 kB)
Collecting black>=23.0.0 (from supplyguard==0.3.0)
  Downloading black-26.5.1-cp311-cp311-win_amd64.whl.metadata (95 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 95.1/95.1 kB 5.3 MB/s eta 0:00:00
Collecting anyio<5,>=3.5.0 (from anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading anyio-4.14.2-py3-none-any.whl.metadata (4.6 kB)
Collecting docstring-parser<1,>=0.15 (from anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading docstring_parser-0.18.0-py3-none-any.whl.metadata (3.5 kB)
Collecting httpx2<3,>=2.0.0 (from anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading httpx2-2.12.0-py3-none-any.whl.metadata (9.5 kB)
Collecting jiter<1,>=0.4.0 (from anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading jiter-0.16.0-cp311-cp311-win_amd64.whl.metadata (5.3 kB)
Collecting pydantic<3,>=1.9.0 (from anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading pydantic-2.13.4-py3-none-any.whl.metadata (109 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 109.4/109.4 kB ? eta 0:00:00
Collecting sniffio<2,>=1 (from anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading sniffio-1.3.1-py3-none-any.whl.metadata (3.9 kB)
Collecting typing-extensions<5,>=4.14 (from anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading typing_extensions-4.16.0-py3-none-any.whl.metadata (3.3 kB)
Collecting mypy-extensions>=0.4.3 (from black>=23.0.0->supplyguard==0.3.0)
  Downloading mypy_extensions-1.1.0-py3-none-any.whl.metadata (1.1 kB)
Collecting packaging>=22.0 (from black>=23.0.0->supplyguard==0.3.0)
  Downloading packaging-26.3-py3-none-any.whl.metadata (3.5 kB)
Collecting pathspec>=1.0.0 (from black>=23.0.0->supplyguard==0.3.0)
  Downloading pathspec-1.1.1-py3-none-any.whl.metadata (14 kB)
Collecting platformdirs>=2 (from black>=23.0.0->supplyguard==0.3.0)
  Downloading platformdirs-4.11.3-py3-none-any.whl.metadata (5.5 kB)
Collecting pytokens~=0.4.0 (from black>=23.0.0->supplyguard==0.3.0)
  Downloading pytokens-0.4.1-cp311-cp311-win_amd64.whl.metadata (3.9 kB)
Collecting colorama (from click>=8.1.0->supplyguard==0.3.0)
  Downloading colorama-0.4.6-py2.py3-none-any.whl.metadata (17 kB)
Collecting chardet<6.0,>=5.1 (from cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading chardet-5.2.0-py3-none-any.whl.metadata (3.4 kB)
Collecting cyclonedx-python-lib<12,>=8.0 (from cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading cyclonedx_python_lib-11.12.0-py3-none-any.whl.metadata (6.9 kB)
Collecting packageurl-python<2,>=0.11 (from cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading packageurl_python-0.17.6-py3-none-any.whl.metadata (5.1 kB)
Collecting pip-requirements-parser<33.0,>=32.0 (from cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading pip_requirements_parser-32.0.1-py3-none-any.whl.metadata (9.3 kB)
Collecting blinker>=1.9.0 (from flask>=3.0.0->supplyguard==0.3.0)
  Downloading blinker-1.9.0-py3-none-any.whl.metadata (1.6 kB)
Collecting itsdangerous>=2.2.0 (from flask>=3.0.0->supplyguard==0.3.0)
  Downloading itsdangerous-2.2.0-py3-none-any.whl.metadata (1.9 kB)
Collecting jinja2>=3.1.2 (from flask>=3.0.0->supplyguard==0.3.0)
  Downloading jinja2-3.1.6-py3-none-any.whl.metadata (2.9 kB)
Collecting markupsafe>=2.1.1 (from flask>=3.0.0->supplyguard==0.3.0)
  Downloading markupsafe-3.0.3-cp311-cp311-win_amd64.whl.metadata (2.8 kB)
Collecting werkzeug>=3.1.0 (from flask>=3.0.0->supplyguard==0.3.0)
  Downloading werkzeug-3.1.8-py3-none-any.whl.metadata (4.0 kB)
Collecting iniconfig>=1.0.1 (from pytest>=7.0.0->supplyguard==0.3.0)
  Downloading iniconfig-2.3.0-py3-none-any.whl.metadata (2.5 kB)
Collecting pluggy<2,>=1.5 (from pytest>=7.0.0->supplyguard==0.3.0)
  Downloading pluggy-1.6.0-py3-none-any.whl.metadata (4.8 kB)
Collecting pygments>=2.7.2 (from pytest>=7.0.0->supplyguard==0.3.0)
  Downloading pygments-2.21.0-py3-none-any.whl.metadata (2.5 kB)
Collecting charset_normalizer<4,>=2 (from requests>=2.31.0->supplyguard==0.3.0)
  Downloading charset_normalizer-3.5.1-cp311-cp311-win_amd64.whl.metadata (46 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 46.7/46.7 kB 2.3 MB/s eta 0:00:00
Collecting idna<4,>=2.5 (from requests>=2.31.0->supplyguard==0.3.0)
  Downloading idna-3.19-py3-none-any.whl.metadata (9.2 kB)
Collecting urllib3<3,>=1.26 (from requests>=2.31.0->supplyguard==0.3.0)
  Downloading urllib3-2.7.0-py3-none-any.whl.metadata (6.9 kB)
Collecting certifi>=2023.5.7 (from requests>=2.31.0->supplyguard==0.3.0)
  Downloading certifi-2026.7.22-py3-none-any.whl.metadata (2.5 kB)
Collecting markdown-it-py>=2.2.0 (from rich>=13.0.0->supplyguard==0.3.0)
  Downloading markdown_it_py-4.2.0-py3-none-any.whl.metadata (7.4 kB)
Collecting greenlet>=1 (from sqlalchemy>=2.0.0->supplyguard==0.3.0)
  Downloading greenlet-3.5.5-cp311-cp311-win_amd64.whl.metadata (3.9 kB)
Collecting license-expression<31,>=30 (from cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading license_expression-30.4.4-py3-none-any.whl.metadata (11 kB)
Collecting py-serializable<3.0.0,>=2.1.0 (from cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading py_serializable-2.1.0-py3-none-any.whl.metadata (4.3 kB)
Collecting sortedcontainers<3.0.0,>=2.4.0 (from cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading sortedcontainers-2.4.0-py2.py3-none-any.whl.metadata (10 kB)
Collecting jsonschema<5.0,>=4.25 (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading jsonschema-4.26.0-py3-none-any.whl.metadata (7.6 kB)
Collecting lxml<7,>=4 (from cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading lxml-6.1.2-cp311-cp311-win_amd64.whl.metadata (3.4 kB)
Collecting referencing>=0.28.4 (from cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading referencing-0.37.0-py3-none-any.whl.metadata (2.8 kB)
Collecting httpcore2==2.12.0 (from httpx2<3,>=2.0.0->anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading httpcore2-2.12.0-py3-none-any.whl.metadata (25 kB)
Collecting truststore>=0.10 (from httpx2<3,>=2.0.0->anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading truststore-0.10.4-py3-none-any.whl.metadata (4.4 kB)
Collecting h11>=0.16 (from httpcore2==2.12.0->httpx2<3,>=2.0.0->anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading h11-0.16.0-py3-none-any.whl.metadata (8.3 kB)
Collecting mdurl~=0.1 (from markdown-it-py>=2.2.0->rich>=13.0.0->supplyguard==0.3.0)
  Downloading mdurl-0.1.2-py3-none-any.whl.metadata (1.6 kB)
Collecting pyparsing (from pip-requirements-parser<33.0,>=32.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading pyparsing-3.3.2-py3-none-any.whl.metadata (5.8 kB)
Collecting annotated-types>=0.6.0 (from pydantic<3,>=1.9.0->anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading annotated_types-0.8.0-py3-none-any.whl.metadata (15 kB)
Collecting pydantic-core==2.46.4 (from pydantic<3,>=1.9.0->anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading pydantic_core-2.46.4-cp311-cp311-win_amd64.whl.metadata (6.7 kB)
Collecting typing-inspection>=0.4.2 (from pydantic<3,>=1.9.0->anthropic>=0.20.0->supplyguard==0.3.0)
  Downloading typing_inspection-0.4.4-py3-none-any.whl.metadata (2.6 kB)
Collecting attrs>=22.2.0 (from jsonschema<5.0,>=4.25->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading attrs-26.1.0-py3-none-any.whl.metadata (8.8 kB)
Collecting jsonschema-specifications>=2023.03.6 (from jsonschema<5.0,>=4.25->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading jsonschema_specifications-2025.9.1-py3-none-any.whl.metadata (2.9 kB)
Collecting rpds-py>=0.25.0 (from jsonschema<5.0,>=4.25->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading rpds_py-2026.6.3-cp311-cp311-win_amd64.whl.metadata (4.2 kB)
Collecting fqdn (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading fqdn-1.5.1-py3-none-any.whl.metadata (1.4 kB)
Collecting isoduration (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading isoduration-20.11.0-py3-none-any.whl.metadata (5.7 kB)
Collecting jsonpointer>1.13 (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading jsonpointer-3.1.1-py3-none-any.whl.metadata (2.4 kB)
Collecting rfc3339-validator (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading rfc3339_validator-0.1.4-py2.py3-none-any.whl.metadata (1.5 kB)
Collecting rfc3986-validator>0.1.0 (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading rfc3986_validator-0.1.1-py2.py3-none-any.whl.metadata (1.7 kB)
Collecting rfc3987-syntax>=1.1.0 (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading rfc3987_syntax-1.1.0-py3-none-any.whl.metadata (7.7 kB)
Collecting uri-template (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading uri_template-1.3.0-py3-none-any.whl.metadata (8.8 kB)
Collecting webcolors>=24.6.0 (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading webcolors-25.10.0-py3-none-any.whl.metadata (2.2 kB)
Collecting boolean.py>=4.0 (from license-expression<31,>=30->cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading boolean_py-5.0-py3-none-any.whl.metadata (2.3 kB)
Collecting defusedxml<0.8.0,>=0.7.1 (from py-serializable<3.0.0,>=2.1.0->cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading defusedxml-0.7.1-py2.py3-none-any.whl.metadata (32 kB)
Collecting lark>=1.2.2 (from rfc3987-syntax>=1.1.0->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading lark-1.3.1-py3-none-any.whl.metadata (1.8 kB)
Collecting arrow>=0.15.0 (from isoduration->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading arrow-1.4.0-py3-none-any.whl.metadata (7.7 kB)
Collecting six (from rfc3339-validator->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Using cached six-1.17.0-py2.py3-none-any.whl.metadata (1.7 kB)
Collecting python-dateutil>=2.7.0 (from arrow>=0.15.0->isoduration->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Using cached python_dateutil-2.9.0.post0-py2.py3-none-any.whl.metadata (8.4 kB)
Collecting tzdata (from arrow>=0.15.0->isoduration->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard==0.3.0)
  Downloading tzdata-2026.3-py2.py3-none-any.whl.metadata (1.4 kB)
Downloading anthropic-1.0.0-py3-none-any.whl (1.2 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.2/1.2 MB 14.9 MB/s eta 0:00:00
Downloading black-26.5.1-cp311-cp311-win_amd64.whl (1.5 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.5/1.5 MB 31.2 MB/s eta 0:00:00
Downloading click-8.4.2-py3-none-any.whl (119 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 119.2/119.2 kB ? eta 0:00:00
Downloading cyclonedx_bom-7.3.1-py3-none-any.whl (60 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 60.9/60.9 kB 3.4 MB/s eta 0:00:00
Downloading flask-3.1.3-py3-none-any.whl (103 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 103.4/103.4 kB 5.8 MB/s eta 0:00:00
Downloading pytest-9.1.1-py3-none-any.whl (386 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 386.5/386.5 kB 23.5 MB/s eta 0:00:00
Downloading pytest_mock-3.15.1-py3-none-any.whl (10 kB)
Downloading pyyaml-6.0.3-cp311-cp311-win_amd64.whl (158 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 158.8/158.8 kB ? eta 0:00:00
Downloading requests-2.34.2-py3-none-any.whl (73 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 73.1/73.1 kB 4.2 MB/s eta 0:00:00
Downloading responses-0.26.2-py3-none-any.whl (35 kB)
Downloading rich-15.0.0-py3-none-any.whl (310 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 310.7/310.7 kB 18.8 MB/s eta 0:00:00
Downloading ruff-0.16.4-py3-none-win_amd64.whl (10.6 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 10.6/10.6 MB 29.7 MB/s eta 0:00:00
Downloading sqlalchemy-2.0.52-cp311-cp311-win_amd64.whl (2.2 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.2/2.2 MB 22.8 MB/s eta 0:00:00
Downloading anyio-4.14.2-py3-none-any.whl (125 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 125.8/125.8 kB 7.7 MB/s eta 0:00:00
Downloading blinker-1.9.0-py3-none-any.whl (8.5 kB)
Downloading certifi-2026.7.22-py3-none-any.whl (136 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 137.0/137.0 kB ? eta 0:00:00
Downloading chardet-5.2.0-py3-none-any.whl (199 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 199.4/199.4 kB 11.8 MB/s eta 0:00:00
Downloading charset_normalizer-3.5.1-cp311-cp311-win_amd64.whl (206 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 206.7/206.7 kB 12.3 MB/s eta 0:00:00
Downloading colorama-0.4.6-py2.py3-none-any.whl (25 kB)
Downloading cyclonedx_python_lib-11.12.0-py3-none-any.whl (529 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 529.5/529.5 kB 34.6 MB/s eta 0:00:00
Downloading docstring_parser-0.18.0-py3-none-any.whl (22 kB)
Downloading greenlet-3.5.5-cp311-cp311-win_amd64.whl (323 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 323.3/323.3 kB 9.8 MB/s eta 0:00:00
Downloading httpx2-2.12.0-py3-none-any.whl (95 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 95.4/95.4 kB 5.3 MB/s eta 0:00:00
Downloading httpcore2-2.12.0-py3-none-any.whl (83 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 83.1/83.1 kB 4.6 MB/s eta 0:00:00
Downloading idna-3.19-py3-none-any.whl (68 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 68.5/68.5 kB ? eta 0:00:00
Downloading iniconfig-2.3.0-py3-none-any.whl (7.5 kB)
Downloading itsdangerous-2.2.0-py3-none-any.whl (16 kB)
Downloading jinja2-3.1.6-py3-none-any.whl (134 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 134.9/134.9 kB ? eta 0:00:00
Downloading jiter-0.16.0-cp311-cp311-win_amd64.whl (199 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 199.2/199.2 kB 12.6 MB/s eta 0:00:00
Downloading markdown_it_py-4.2.0-py3-none-any.whl (91 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 91.7/91.7 kB ? eta 0:00:00
Downloading markupsafe-3.0.3-cp311-cp311-win_amd64.whl (15 kB)
Downloading mypy_extensions-1.1.0-py3-none-any.whl (5.0 kB)
Downloading packageurl_python-0.17.6-py3-none-any.whl (36 kB)
Downloading packaging-26.3-py3-none-any.whl (129 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 130.0/130.0 kB ? eta 0:00:00
Downloading pathspec-1.1.1-py3-none-any.whl (57 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 57.3/57.3 kB ? eta 0:00:00
Downloading pip_requirements_parser-32.0.1-py3-none-any.whl (35 kB)
Downloading platformdirs-4.11.3-py3-none-any.whl (23 kB)
Downloading pluggy-1.6.0-py3-none-any.whl (20 kB)
Downloading pydantic-2.13.4-py3-none-any.whl (472 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 472.3/472.3 kB 30.8 MB/s eta 0:00:00
Downloading pydantic_core-2.46.4-cp311-cp311-win_amd64.whl (2.1 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.1/2.1 MB 32.7 MB/s eta 0:00:00
Downloading pygments-2.21.0-py3-none-any.whl (1.3 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.3/1.3 MB 26.4 MB/s eta 0:00:00
Downloading pytokens-0.4.1-cp311-cp311-win_amd64.whl (103 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 103.3/103.3 kB ? eta 0:00:00
Downloading sniffio-1.3.1-py3-none-any.whl (10 kB)
Downloading typing_extensions-4.16.0-py3-none-any.whl (45 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 45.6/45.6 kB 2.2 MB/s eta 0:00:00
Downloading urllib3-2.7.0-py3-none-any.whl (131 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 131.1/131.1 kB 7.6 MB/s eta 0:00:00
Downloading werkzeug-3.1.8-py3-none-any.whl (226 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 226.5/226.5 kB 13.5 MB/s eta 0:00:00
Downloading annotated_types-0.8.0-py3-none-any.whl (13 kB)
Downloading jsonschema-4.26.0-py3-none-any.whl (90 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 90.6/90.6 kB ? eta 0:00:00
Downloading license_expression-30.4.4-py3-none-any.whl (120 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 120.6/120.6 kB 6.9 MB/s eta 0:00:00
Downloading lxml-6.1.2-cp311-cp311-win_amd64.whl (4.0 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.0/4.0 MB 32.2 MB/s eta 0:00:00
Downloading mdurl-0.1.2-py3-none-any.whl (10.0 kB)
Downloading py_serializable-2.1.0-py3-none-any.whl (23 kB)
Downloading referencing-0.37.0-py3-none-any.whl (26 kB)
Downloading sortedcontainers-2.4.0-py2.py3-none-any.whl (29 kB)
Downloading truststore-0.10.4-py3-none-any.whl (18 kB)
Downloading typing_inspection-0.4.4-py3-none-any.whl (14 kB)
Downloading pyparsing-3.3.2-py3-none-any.whl (122 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 122.8/122.8 kB ? eta 0:00:00
Downloading attrs-26.1.0-py3-none-any.whl (67 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 67.5/67.5 kB ? eta 0:00:00
Downloading boolean_py-5.0-py3-none-any.whl (26 kB)
Downloading defusedxml-0.7.1-py2.py3-none-any.whl (25 kB)
Downloading h11-0.16.0-py3-none-any.whl (37 kB)
Downloading jsonpointer-3.1.1-py3-none-any.whl (7.7 kB)
Downloading jsonschema_specifications-2025.9.1-py3-none-any.whl (18 kB)
Downloading rfc3986_validator-0.1.1-py2.py3-none-any.whl (4.2 kB)
Downloading rfc3987_syntax-1.1.0-py3-none-any.whl (8.0 kB)
Downloading rpds_py-2026.6.3-cp311-cp311-win_amd64.whl (223 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 223.2/223.2 kB 13.3 MB/s eta 0:00:00
Downloading webcolors-25.10.0-py3-none-any.whl (14 kB)
Downloading fqdn-1.5.1-py3-none-any.whl (9.1 kB)
Downloading isoduration-20.11.0-py3-none-any.whl (11 kB)
Downloading rfc3339_validator-0.1.4-py2.py3-none-any.whl (3.5 kB)
Downloading uri_template-1.3.0-py3-none-any.whl (11 kB)
Downloading arrow-1.4.0-py3-none-any.whl (68 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 68.8/68.8 kB 3.9 MB/s eta 0:00:00
Downloading lark-1.3.1-py3-none-any.whl (113 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 113.2/113.2 kB 6.9 MB/s eta 0:00:00
Using cached six-1.17.0-py2.py3-none-any.whl (11 kB)
Using cached python_dateutil-2.9.0.post0-py2.py3-none-any.whl (229 kB)
Downloading tzdata-2026.3-py2.py3-none-any.whl (348 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 348.2/348.2 kB 22.5 MB/s eta 0:00:00
Checking if build backend supports build_editable ... done
Building wheels for collected packages: supplyguard
  Building editable for supplyguard (pyproject.toml) ... done
  Created wheel for supplyguard: filename=supplyguard-0.3.0-0.editable-py3-none-any.whl size=9204 sha256=82a17f683cb8651bc2431607399979ea1e308cc9f14d67e0f588798800f90e15
  Stored in directory: C:\Users\Aryan Pandey\AppData\Local\Temp\pip-ephem-wheel-cache-ji0pnokv\wheels\ed\00\84\3f027e6a20119fbe244d7d21f2e38fb254a373f12629aee80d
Successfully built supplyguard
Installing collected packages: sortedcontainers, boolean.py, webcolors, urllib3, uri-template, tzdata, typing-extensions, truststore, sniffio, six, ruff, rpds-py, rfc3986-validator, pyyaml, pytokens, pyparsing, pygments, pluggy, platformdirs, pathspec, packaging, packageurl-python, mypy-extensions, mdurl, markupsafe, lxml, license-expression, lark, jsonpointer, jiter, itsdangerous, iniconfig, idna, h11, greenlet, fqdn, docstring-parser, defusedxml, colorama, charset_normalizer, chardet, certifi, blinker, attrs, annotated-types, werkzeug, typing-inspection, sqlalchemy, rfc3987-syntax, rfc3339-validator, requests, referencing, python-dateutil, pytest, pydantic-core, py-serializable, pip-requirements-parser, markdown-it-py, jinja2, httpcore2, click, anyio, rich, responses, pytest-mock, pydantic, jsonschema-specifications, httpx2, flask, cyclonedx-python-lib, black, arrow, jsonschema, isoduration, anthropic, cyclonedx-bom, supplyguard
  WARNING: The script pygmentize.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script idna.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script normalizer.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script chardetect.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The scripts py.test.exe and pytest.exe are installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script markdown-it.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script httpx2.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script flask.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The scripts black.exe and blackd.exe are installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script jsonschema.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script cyclonedx-py.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
  WARNING: The script supplyguard.exe is installed in 'C:\Users\Aryan Pandey\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
Successfully installed annotated-types-0.8.0 anthropic-1.0.0 anyio-4.14.2 arrow-1.4.0 attrs-26.1.0 black-26.5.1 blinker-1.9.0 boolean.py-5.0 certifi-2026.7.22 chardet-5.2.0 charset_normalizer-3.5.1 click-8.4.2 colorama-0.4.6 cyclonedx-bom-7.3.1 cyclonedx-python-lib-11.12.0 defusedxml-0.7.1 docstring-parser-0.18.0 flask-3.1.3 fqdn-1.5.1 greenlet-3.5.5 h11-0.16.0 httpcore2-2.12.0 httpx2-2.12.0 idna-3.19 iniconfig-2.3.0 isoduration-20.11.0 itsdangerous-2.2.0 jinja2-3.1.6 jiter-0.16.0 jsonpointer-3.1.1 jsonschema-4.26.0 jsonschema-specifications-2025.9.1 lark-1.3.1 license-expression-30.4.4 lxml-6.1.2 markdown-it-py-4.2.0 markupsafe-3.0.3 mdurl-0.1.2 mypy-extensions-1.1.0 packageurl-python-0.17.6 packaging-26.3 pathspec-1.1.1 pip-requirements-parser-32.0.1 platformdirs-4.11.3 pluggy-1.6.0 py-serializable-2.1.0 pydantic-2.13.4 pydantic-core-2.46.4 pygments-2.21.0 pyparsing-3.3.2 pytest-9.1.1 pytest-mock-3.15.1 python-dateutil-2.9.0.post0 pytokens-0.4.1 pyyaml-6.0.3 referencing-0.37.0 requests-2.34.2 responses-0.26.2 rfc3339-validator-0.1.4 rfc3986-validator-0.1.1 rfc3987-syntax-1.1.0 rich-15.0.0 rpds-py-2026.6.3 ruff-0.16.4 six-1.17.0 sniffio-1.3.1 sortedcontainers-2.4.0 sqlalchemy-2.0.52 supplyguard-0.3.0 truststore-0.10.4 typing-extensions-4.16.0 typing-inspection-0.4.4 tzdata-2026.3 uri-template-1.3.0 urllib3-2.7.0 webcolors-25.10.0 werkzeug-3.1.8

[notice] A new release of pip is available: 24.0 -> 26.2.1
[notice] To update, run: C:\Users\Aryan Pandey\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe -m pip install --upgrade pip
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard>
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard>
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> pip install supplyguard
Requirement already satisfied: supplyguard in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (0.3.0)
Requirement already satisfied: click>=8.1.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from supplyguard) (8.4.2)
Requirement already satisfied: flask>=3.0.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from supplyguard) (3.1.3)
Requirement already satisfied: sqlalchemy>=2.0.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from supplyguard) (2.0.52)
Requirement already satisfied: requests>=2.31.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from supplyguard) (2.34.2)
Requirement already satisfied: cyclonedx-bom>=3.11.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from supplyguard) (7.3.1)
Requirement already satisfied: rich>=13.0.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from supplyguard) (15.0.0)
Requirement already satisfied: pyyaml>=6.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from supplyguard) (6.0.3)
Requirement already satisfied: anthropic>=0.20.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from supplyguard) (1.0.0)
Requirement already satisfied: anyio<5,>=3.5.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from anthropic>=0.20.0->supplyguard) (4.14.2)
Requirement already satisfied: docstring-parser<1,>=0.15 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from anthropic>=0.20.0->supplyguard) (0.18.0)
Requirement already satisfied: httpx2<3,>=2.0.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from anthropic>=0.20.0->supplyguard) (2.12.0)
Requirement already satisfied: jiter<1,>=0.4.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from anthropic>=0.20.0->supplyguard) (0.16.0)
Requirement already satisfied: pydantic<3,>=1.9.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from anthropic>=0.20.0->supplyguard) (2.13.4)
Requirement already satisfied: sniffio<2,>=1 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from anthropic>=0.20.0->supplyguard) (1.3.1)
Requirement already satisfied: typing-extensions<5,>=4.14 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from anthropic>=0.20.0->supplyguard) (4.16.0)
Requirement already satisfied: colorama in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from click>=8.1.0->supplyguard) (0.4.6)
Requirement already satisfied: chardet<6.0,>=5.1 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-bom>=3.11.0->supplyguard) (5.2.0)
Requirement already satisfied: cyclonedx-python-lib<12,>=8.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (11.12.0)
Requirement already satisfied: packageurl-python<2,>=0.11 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-bom>=3.11.0->supplyguard) (0.17.6)
Requirement already satisfied: packaging<27,>=22 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-bom>=3.11.0->supplyguard) (26.3)
Requirement already satisfied: pip-requirements-parser<33.0,>=32.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-bom>=3.11.0->supplyguard) (32.0.1)
Requirement already satisfied: blinker>=1.9.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from flask>=3.0.0->supplyguard) (1.9.0)
Requirement already satisfied: itsdangerous>=2.2.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from flask>=3.0.0->supplyguard) (2.2.0)
Requirement already satisfied: jinja2>=3.1.2 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from flask>=3.0.0->supplyguard) (3.1.6)
Requirement already satisfied: markupsafe>=2.1.1 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from flask>=3.0.0->supplyguard) (3.0.3)
Requirement already satisfied: werkzeug>=3.1.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from flask>=3.0.0->supplyguard) (3.1.8)
Requirement already satisfied: charset_normalizer<4,>=2 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from requests>=2.31.0->supplyguard) (3.5.1)
Requirement already satisfied: idna<4,>=2.5 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from requests>=2.31.0->supplyguard) (3.19)
Requirement already satisfied: urllib3<3,>=1.26 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from requests>=2.31.0->supplyguard) (2.7.0)
Requirement already satisfied: certifi>=2023.5.7 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from requests>=2.31.0->supplyguard) (2026.7.22)
Requirement already satisfied: markdown-it-py>=2.2.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from rich>=13.0.0->supplyguard) (4.2.0)
Requirement already satisfied: pygments<3.0.0,>=2.13.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from rich>=13.0.0->supplyguard) (2.21.0)
Requirement already satisfied: greenlet>=1 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from sqlalchemy>=2.0.0->supplyguard) (3.5.5)
Requirement already satisfied: license-expression<31,>=30 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (30.4.4)
Requirement already satisfied: py-serializable<3.0.0,>=2.1.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (2.1.0)
Requirement already satisfied: sortedcontainers<3.0.0,>=2.4.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (2.4.0)
Requirement already satisfied: jsonschema<5.0,>=4.25 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (4.26.0)
Requirement already satisfied: lxml<7,>=4 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (6.1.2)
Requirement already satisfied: referencing>=0.28.4 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (0.37.0)
Requirement already satisfied: httpcore2==2.12.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from httpx2<3,>=2.0.0->anthropic>=0.20.0->supplyguard) (2.12.0)
Requirement already satisfied: truststore>=0.10 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from httpx2<3,>=2.0.0->anthropic>=0.20.0->supplyguard) (0.10.4)
Requirement already satisfied: h11>=0.16 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from httpcore2==2.12.0->httpx2<3,>=2.0.0->anthropic>=0.20.0->supplyguard) (0.16.0)
Requirement already satisfied: mdurl~=0.1 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from markdown-it-py>=2.2.0->rich>=13.0.0->supplyguard) (0.1.2)
Requirement already satisfied: pyparsing in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from pip-requirements-parser<33.0,>=32.0->cyclonedx-bom>=3.11.0->supplyguard) (3.3.2)
Requirement already satisfied: annotated-types>=0.6.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from pydantic<3,>=1.9.0->anthropic>=0.20.0->supplyguard) (0.8.0)
Requirement already satisfied: pydantic-core==2.46.4 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from pydantic<3,>=1.9.0->anthropic>=0.20.0->supplyguard) (2.46.4)
Requirement already satisfied: typing-inspection>=0.4.2 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from pydantic<3,>=1.9.0->anthropic>=0.20.0->supplyguard) (0.4.4)
Requirement already satisfied: attrs>=22.2.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema<5.0,>=4.25->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (26.1.0)
Requirement already satisfied: jsonschema-specifications>=2023.03.6 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema<5.0,>=4.25->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (2025.9.1)
Requirement already satisfied: rpds-py>=0.25.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema<5.0,>=4.25->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (2026.6.3)
Requirement already satisfied: fqdn in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (1.5.1)
Requirement already satisfied: isoduration in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (20.11.0)
Requirement already satisfied: jsonpointer>1.13 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (3.1.1)
Requirement already satisfied: rfc3339-validator in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (0.1.4)
Requirement already satisfied: rfc3986-validator>0.1.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (0.1.1)
Requirement already satisfied: rfc3987-syntax>=1.1.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (1.1.0)
Requirement already satisfied: uri-template in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (1.3.0)
Requirement already satisfied: webcolors>=24.6.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (25.10.0)
Requirement already satisfied: boolean.py>=4.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from license-expression<31,>=30->cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (5.0)
Requirement already satisfied: defusedxml<0.8.0,>=0.7.1 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from py-serializable<3.0.0,>=2.1.0->cyclonedx-python-lib<12,>=8.0->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (0.7.1)
Requirement already satisfied: lark>=1.2.2 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from rfc3987-syntax>=1.1.0->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (1.3.1)
Requirement already satisfied: arrow>=0.15.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from isoduration->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (1.4.0)
Requirement already satisfied: six in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from rfc3339-validator->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (1.17.0)
Requirement already satisfied: python-dateutil>=2.7.0 in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from arrow>=0.15.0->isoduration->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (2.9.0.post0)
Requirement already satisfied: tzdata in c:\users\aryan pandey\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\site-packages (from arrow>=0.15.0->isoduration->jsonschema[format-nongpl]<5.0,>=4.25; extra == "validation" or extra == "json-validation"->cyclonedx-python-lib[validation]<12,>=8.0->cyclonedx-bom>=3.11.0->supplyguard) (2026.3)

[notice] A new release of pip is available: 24.0 -> 26.2.1
[notice] To update, run: C:\Users\Aryan Pandey\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe -m pip install --upgrade pip
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> supplyguard init
supplyguard : The term 'supplyguard' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of
the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ supplyguard init
+ ~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (supplyguard:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> supplyguard scan .
supplyguard : The term 'supplyguard' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of
the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ supplyguard scan .
+ ~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (supplyguard:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> supplyguard scan . --threshold 40 --format sarif -o results.sarif
supplyguard : The term 'supplyguard' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of
the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ supplyguard scan . --threshold 40 --format sarif -o results.sarif
+ ~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (supplyguard:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> C:\Users\Aryan Pandey\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe -m pip install --upgrade pip
C:\Users\Aryan : The term 'C:\Users\Aryan' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the
spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ C:\Users\Aryan Pandey\AppData\Local\Microsoft\WindowsApps\PythonSoftw ...
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Aryan:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> supplyguard fix . --max-iterations 3
supplyguard : The term 'supplyguard' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of
the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ supplyguard fix . --max-iterations 3
+ ~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (supplyguard:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> supplyguard web --port 5000
supplyguard : The term 'supplyguard' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of
the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ supplyguard web --port 5000
+ ~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (supplyguard:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> # Run unit and integration tests
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> pytest tests/ -v
pytest : The term 'pytest' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name,
or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ pytest tests/ -v
+ ~~~~~~
    + CategoryInfo          : ObjectNotFound: (pytest:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard>
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> # Run linting
PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard> ruff check .
ruff : The term 'ruff' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or
if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ ruff check .
+ ~~~~
    + CategoryInfo          : ObjectNotFound: (ruff:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

PS C:\Users\Aryan Pandey\OneDrive\Documents\DemoVulnerableApp\Supplyguard>