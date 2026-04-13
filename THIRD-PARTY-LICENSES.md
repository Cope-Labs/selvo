# Third-party licenses

Snapshot of the licenses of every runtime and development dependency in
selvo's `pyproject.toml` closure, generated from a clean install of
`.[dev,api]`. Regenerate with:

```bash
pip install -e ".[dev,api]"
pip install pip-licenses
pip-licenses --from=mixed --format=markdown --with-urls --order=license
```

selvo itself is [Elastic License 2.0](LICENSE). The dependency closure
is primarily Apache-2.0 / MIT / BSD / MPL-2.0 / PSF / ISC — all freely
compatible with ELv2 redistribution.

**Two LGPL-licensed entries** appear in the list (`chardet` LGPLv2+,
`dominate` LGPLv3). Both are transitively pulled by test-suite extras
of packages selvo doesn't import at runtime, and LGPL is compatible
with ELv2 via dynamic linking (which is how Python imports work). No
action required, but noting it here so any future auditor sees it was
considered.

Regen and hostile-license check should move into CI on tagged release.
Fail the build if the list ever contains a full-GPL, AGPL, or
proprietary entry.

| Name                      | Version                           | License                                                 | URL                                                                   |
|---------------------------|-----------------------------------|---------------------------------------------------------|-----------------------------------------------------------------------|
| cyclonedx-python-lib      | 11.7.0                            | Apache Software License                                 | https://github.com/CycloneDX/cyclonedx-python-lib/#readme             |
| detect-secrets            | 1.5.0                             | Apache Software License                                 | https://github.com/Yelp/detect-secrets                                |
| pip-api                   | 0.0.34                            | Apache Software License                                 | http://github.com/di/pip-api                                          |
| pip_audit                 | 2.10.0                            | Apache Software License                                 | https://pypi.org/project/pip-audit/                                   |
| py-serializable           | 2.1.0                             | Apache Software License                                 | https://github.com/madpah/serializable#readme                         |
| requests                  | 2.33.0                            | Apache Software License                                 | https://github.com/psf/requests                                       |
| sortedcontainers          | 2.4.0                             | Apache Software License                                 | http://www.grantjenks.com/docs/sortedcontainers/                      |
| trove-classifiers         | 2026.1.14.14                      | Apache Software License                                 | https://github.com/pypa/trove-classifiers                             |
| python-dateutil           | 2.9.0.post0                       | Apache Software License; BSD License                    | https://github.com/dateutil/dateutil                                  |
| uvloop                    | 0.22.1                            | Apache Software License; MIT License                    | UNKNOWN                                                               |
| CacheControl              | 0.14.4                            | Apache-2.0                                              | https://pypi.org/project/CacheControl/                                |
| anytree                   | 2.13.0                            | Apache-2.0                                              | https://github.com/c0fec0de/anytree                                   |
| license-expression        | 30.4.4                            | Apache-2.0                                              | https://github.com/aboutcode-org/license-expression                   |
| msgpack                   | 1.1.2                             | Apache-2.0                                              | https://msgpack.org/                                                  |
| pytest-asyncio            | 1.3.0                             | Apache-2.0                                              | https://github.com/pytest-dev/pytest-asyncio                          |
| python-multipart          | 0.0.22                            | Apache-2.0                                              | https://github.com/Kludex/python-multipart                            |
| packaging                 | 26.0                              | Apache-2.0 OR BSD-2-Clause                              | https://github.com/pypa/packaging                                     |
| cryptography              | 46.0.6                            | Apache-2.0 OR BSD-3-Clause                              | https://github.com/pyca/cryptography                                  |
| httpx                     | 0.28.1                            | BSD License                                             | https://github.com/encode/httpx                                       |
| respx                     | 0.22.0                            | BSD License                                             | https://lundberg.github.io/respx/                                     |
| Pygments                  | 2.20.0                            | BSD-2-Clause                                            | https://pygments.org                                                  |
| boolean.py                | 5.0                               | BSD-2-Clause                                            | https://github.com/bastikr/boolean.py                                 |
| click                     | 8.3.1                             | BSD-3-Clause                                            | https://github.com/pallets/click/                                     |
| httpcore                  | 1.0.9                             | BSD-3-Clause                                            | https://www.encode.io/httpcore/                                       |
| idna                      | 3.11                              | BSD-3-Clause                                            | https://github.com/kjd/idna                                           |
| networkx                  | 3.6.1                             | BSD-3-Clause                                            | https://networkx.org/                                                 |
| pycparser                 | 3.0                               | BSD-3-Clause                                            | https://github.com/eliben/pycparser                                   |
| python-dotenv             | 1.2.2                             | BSD-3-Clause                                            | https://github.com/theskumar/python-dotenv                            |
| sse-starlette             | 3.3.2                             | BSD-3-Clause                                            | https://github.com/sysid/sse-starlette                                |
| starlette                 | 0.52.1                            | BSD-3-Clause                                            | https://github.com/Kludex/starlette                                   |
| uvicorn                   | 0.41.0                            | BSD-3-Clause                                            | https://uvicorn.dev/                                                  |
| websockets                | 16.0                              | BSD-3-Clause                                            | https://github.com/python-websockets/websockets                       |
| selvo                     | 0.1.10.dev12+gedecabd6f.d20260327 | Elastic-2.0                                             | https://github.com/sethc5/selvo-report                                |
| chardet                   | 5.2.0                             | GNU Lesser General Public License v2 or later (LGPLv2+) | https://github.com/chardet/chardet                                    |
| dominate                  | 2.9.1                             | GNU Lesser General Public License v3 (LGPLv3)           | https://github.com/Knio/dominate                                      |
| shellingham               | 1.5.4                             | ISC License (ISCL)                                      | https://github.com/sarugaku/shellingham                               |
| PyJWT                     | 2.12.1                            | MIT                                                     | https://github.com/jpadilla/pyjwt                                     |
| annotated-doc             | 0.0.4                             | MIT                                                     | https://github.com/fastapi/annotated-doc                              |
| anyio                     | 4.12.1                            | MIT                                                     | https://anyio.readthedocs.io/en/stable/versionhistory.html            |
| attrs                     | 25.4.0                            | MIT                                                     | https://www.attrs.org/en/stable/changelog.html                        |
| build                     | 1.4.0                             | MIT                                                     | https://build.pypa.io                                                 |
| cachetools                | 7.0.5                             | MIT                                                     | https://github.com/tkem/cachetools/                                   |
| cffi                      | 2.0.0                             | MIT                                                     | https://cffi.readthedocs.io/en/latest/whatsnew.html                   |
| charset-normalizer        | 3.4.6                             | MIT                                                     | https://github.com/jawah/charset_normalizer/blob/master/CHANGELOG.md  |
| fastapi                   | 0.135.1                           | MIT                                                     | https://github.com/fastapi/fastapi                                    |
| filelock                  | 3.25.2                            | MIT                                                     | https://github.com/tox-dev/py-filelock                                |
| hatch-vcs                 | 0.5.0                             | MIT                                                     | https://github.com/ofek/hatch-vcs                                     |
| hatchling                 | 1.29.0                            | MIT                                                     | https://hatch.pypa.io/latest/                                         |
| httptools                 | 0.7.1                             | MIT                                                     | https://github.com/MagicStack/httptools                               |
| httpx-sse                 | 0.4.3                             | MIT                                                     | https://github.com/florimondmanca/httpx-sse                           |
| iniconfig                 | 2.3.0                             | MIT                                                     | https://github.com/pytest-dev/iniconfig                               |
| johnnydep                 | 1.20.6                            | MIT                                                     | https://github.com/wimglenn/johnnydep                                 |
| jsonschema                | 4.26.0                            | MIT                                                     | https://github.com/python-jsonschema/jsonschema                       |
| jsonschema-specifications | 2025.9.1                          | MIT                                                     | https://github.com/python-jsonschema/jsonschema-specifications        |
| mypy_extensions           | 1.1.0                             | MIT                                                     | https://github.com/python/mypy_extensions                             |
| oyaml                     | 1.0                               | MIT                                                     | https://github.com/wimglenn/oyaml                                     |
| pip-requirements-parser   | 32.0.1                            | MIT                                                     | https://github.com/nexB/pip-requirements-parser                       |
| platformdirs              | 4.9.4                             | MIT                                                     | https://github.com/tox-dev/platformdirs                               |
| pydantic                  | 2.12.5                            | MIT                                                     | https://github.com/pydantic/pydantic                                  |
| pydantic-settings         | 2.13.1                            | MIT                                                     | https://github.com/pydantic/pydantic-settings                         |
| pydantic_core             | 2.41.5                            | MIT                                                     | https://github.com/pydantic/pydantic-core                             |
| pyparsing                 | 3.3.2                             | MIT                                                     | https://github.com/pyparsing/pyparsing/                               |
| pytest                    | 9.0.2                             | MIT                                                     | https://docs.pytest.org/en/latest/                                    |
| referencing               | 0.37.0                            | MIT                                                     | https://github.com/python-jsonschema/referencing                      |
| rpds-py                   | 0.30.0                            | MIT                                                     | https://github.com/crate-py/rpds                                      |
| tabulate                  | 0.10.0                            | MIT                                                     | https://github.com/astanin/python-tabulate                            |
| termcolor                 | 3.3.0                             | MIT                                                     | https://github.com/termcolor/termcolor                                |
| tomli                     | 2.4.1                             | MIT                                                     | https://github.com/hukkin/tomli                                       |
| typer                     | 0.24.1                            | MIT                                                     | https://github.com/fastapi/typer                                      |
| typing-inspection         | 0.4.2                             | MIT                                                     | https://github.com/pydantic/typing-inspection                         |
| urllib3                   | 2.6.3                             | MIT                                                     | https://github.com/urllib3/urllib3/blob/main/CHANGES.rst              |
| wimpy                     | 0.6                               | MIT                                                     | https://github.com/wimglenn/wimpy                                     |
| DataProperty              | 1.1.0                             | MIT License                                             | https://github.com/thombashi/DataProperty                             |
| PyYAML                    | 6.0.3                             | MIT License                                             | https://pyyaml.org/                                                   |
| annotated-types           | 0.7.0                             | MIT License                                             | https://github.com/annotated-types/annotated-types                    |
| h11                       | 0.16.0                            | MIT License                                             | https://github.com/python-hyper/h11                                   |
| h2                        | 4.3.0                             | MIT License                                             | https://github.com/python-hyper/h2/                                   |
| hpack                     | 4.1.0                             | MIT License                                             | https://github.com/python-hyper/hpack/                                |
| hyperframe                | 6.1.0                             | MIT License                                             | https://github.com/python-hyper/hyperframe/                           |
| librt                     | 0.8.1                             | MIT License                                             | https://github.com/mypyc/librt                                        |
| margin                    | 0.9.21                            | MIT License                                             | https://github.com/sethc5/margin                                      |
| markdown-it-py            | 4.0.0                             | MIT License                                             | https://github.com/executablebooks/markdown-it-py                     |
| mbstrdecoder              | 1.1.4                             | MIT License                                             | https://github.com/thombashi/mbstrdecoder                             |
| mcp                       | 1.26.0                            | MIT License                                             | https://modelcontextprotocol.io                                       |
| mdurl                     | 0.1.2                             | MIT License                                             | https://github.com/executablebooks/mdurl                              |
| mypy                      | 1.19.1                            | MIT License                                             | https://www.mypy-lang.org/                                            |
| packageurl-python         | 0.17.6                            | MIT License                                             | https://github.com/package-url/packageurl-python                      |
| pathvalidate              | 3.3.1                             | MIT License                                             | https://github.com/thombashi/pathvalidate                             |
| pluggy                    | 1.6.0                             | MIT License                                             | UNKNOWN                                                               |
| pyproject_hooks           | 1.2.0                             | MIT License                                             | https://github.com/pypa/pyproject-hooks                               |
| pytablewriter             | 1.2.1                             | MIT License                                             | https://github.com/thombashi/pytablewriter                            |
| pytz                      | 2026.1.post1                      | MIT License                                             | http://pythonhosted.org/pytz                                          |
| rich                      | 14.3.3                            | MIT License                                             | https://github.com/Textualize/rich                                    |
| ruff                      | 0.15.5                            | MIT License                                             | https://docs.astral.sh/ruff                                           |
| setuptools-scm            | 9.2.2                             | MIT License                                             | https://github.com/pypa/setuptools-scm/                               |
| six                       | 1.17.0                            | MIT License                                             | https://github.com/benjaminp/six                                      |
| stripe                    | 15.0.0                            | MIT License                                             | https://stripe.com/                                                   |
| tabledata                 | 1.3.4                             | MIT License                                             | https://github.com/thombashi/tabledata                                |
| tcolorpy                  | 0.1.7                             | MIT License                                             | https://github.com/thombashi/tcolorpy                                 |
| toml                      | 0.10.2                            | MIT License                                             | https://github.com/uiri/toml                                          |
| tomli_w                   | 1.2.0                             | MIT License                                             | https://github.com/hukkin/tomli-w                                     |
| typepy                    | 1.3.4                             | MIT License                                             | https://github.com/thombashi/typepy                                   |
| watchfiles                | 1.1.1                             | MIT License                                             | https://github.com/samuelcolvin/watchfiles                            |
| structlog                 | 25.5.0                            | MIT OR Apache-2.0                                       | https://github.com/hynek/structlog/blob/main/CHANGELOG.md             |
| certifi                   | 2026.2.25                         | Mozilla Public License 2.0 (MPL 2.0)                    | https://github.com/certifi/python-certifi                             |
| pathspec                  | 1.0.4                             | Mozilla Public License 2.0 (MPL 2.0)                    | https://python-path-specification.readthedocs.io/en/latest/index.html |
| typing_extensions         | 4.15.0                            | PSF-2.0                                                 | https://github.com/python/typing_extensions                           |
| defusedxml                | 0.7.1                             | Python Software Foundation License                      | https://github.com/tiran/defusedxml                                   |

