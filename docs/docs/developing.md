# Developing 

Recommend to use venv for development.  
```shell
python3 -m venv .venv
source .venv/bin/activate
```

Install dev dependencies 
```shell
python -m pip install .[docs,test]  # \[docs,test\] in zsh
```


---

## Python package

### Linting and Testing

It is important NOT ONLY to get OK from all linters (or achieve score in the case of pylint), but also to write good code.    
P.S. It's hard to say what a Good Code is. Let's say that it should be simple, clear, commented, and so on.
```shell
python -m flake8 .
python -m mypy fastapi_jwt
python -m isort . --check
```

Try NOT ONLY to achieve 100% coverage, but also to cover extreme cases, height load cases, multithreaded cases, incorrect input, and so on.
```shell
python -m pytest
```

You can fix some issues in auto mode.

* Sorting imports and make autopep.
    ```shell
    python -m isort .
    ```


### Publishing 

Egg (deprecated) 
```shell
python3 setup.py build
python3 setup.py sdist
twine upload -r testpypi dist/*
twine upload dist/*
```

Build Wheel and see what inside
```shell
python3 -m pip wheel . --no-deps --wheel-dir dist
tar --list -f dist/fastapi-jwt-0.0.1-py3-none-any.whl  
```

Load dist to pypi
```shell
twine upload -r testpypi dist/*
twine upload dist/*
```


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

