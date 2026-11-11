# Developing 

Use Python 3.11 or later with a virtual environment for development.
```shell
python3 -m venv .venv
source .venv/bin/activate
```

Install dev dependencies 
```shell
python -m pip install -e ".[docs,test]"
```


---

## Python package

### Linting and Testing

It is important NOT ONLY to get OK from all linters (or achieve score in the case of pylint), but also to write good code.    
P.S. It's hard to say what a Good Code is. Let's say that it should be simple, clear, commented, and so on.
```shell
python -m ruff check fastapi_jwt tests
python -m ruff format --check fastapi_jwt tests
ty check fastapi_jwt
```

Try NOT ONLY to achieve 100% coverage, but also to cover extreme cases, height load cases, multithreaded cases, incorrect input, and so on.
```shell
python -m pytest
```

You can fix some issues in auto mode.

* Use Ruff to sort imports and format code.
    ```shell
    python -m ruff check --fix fastapi_jwt tests
    python -m ruff format fastapi_jwt tests
    ```


### Publishing

Release Please opens a release PR after Conventional Commits reach `main`.
The release PR updates `VERSION` and `CHANGELOG.md`.
Before version 1.0, breaking changes increase the minor version. For example, 0.3.0 becomes 0.4.0.
Merge that PR to create the version tag and GitHub release.
The Publish workflow builds the tagged source and uploads both distributions to PyPI.
The workflow then publishes the documentation.

Configure these repository secrets before merging the workflow change:

- `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY`: the GitHub App credentials used by `k4black/hex`.
- `PYPI_TOKEN`: the existing PyPI token for this package.

Use the same GitHub App as `k4black/hex`:

1. Open GitHub account Settings > Developer settings > GitHub Apps and select that App.
2. Copy its App ID. Open Install App > Configure for the account and include `k4black/fastapi-jwt`.
3. Make sure that the App has Contents: Read and write and Pull requests: Read and write permissions.
4. Use the original private-key PEM file. If unavailable, generate another key under Private keys without revoking the existing key.
5. Open `k4black/fastapi-jwt` > Settings > Secrets and variables > Actions > New repository secret.
6. Add `RELEASE_APP_ID` with the App ID.
7. Add `RELEASE_APP_PRIVATE_KEY` with the complete PEM text, including its BEGIN and END lines.

GitHub does not reveal existing secret values. The values cannot be copied from the hex repository through its secret settings.
Keep the existing `PYPI_TOKEN`. No PyPI authentication change is required.
The App token lets release PRs trigger CI and GitHub releases trigger publishing.
The workflow does not change `main` or move existing tags.


---

## Docs

### Editing 

Edit it in `docs/`

`mkdocs` can be run as dev server with auto-reload.
```shell
mkdocs serve --config-file docs/mkdocs.yml
```

Note: Server will auto-restart for all changed `docs/*` files.  
If you want to edit `README.md` or `CONTRIBUTING.md` you should restart server on each change.  


### Building pkg docs (`TODO`)

Add python backend docs `TODO`
```shell
lazydocs \
    --output-path="./docs/references/backend" \
    --overview-file="index.md" \
    --src-base-url="https://github.com/k4black/flowingo/blob/master" \
    flowingo
```

### Deploy 

#### Without versioning (now)
Build and deploy docs itself
```shell
mkdocs build --config-file docs/mkdocs.yml
mkdocs gh-deploy --config-file docs/mkdocs.yml    
```

#### With `mike` as versioning tool (`TODO`)

Deploy with `mike` to github-pages with versioning support
```shell
mike deploy --config-file docs/mkdocs.yml 0.0.1 latest --push
mike alias --config-file docs/mkdocs.yml 0.0.1 0.0.x --push
mike set-default --config-file docs/mkdocs.yml latest --push
```

#### With `read-the-docs` as versioning tool (`TODO`)
Deploy with `mkdocs` to read-the-docs for versioning support
```shell
TODO
```

