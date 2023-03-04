# Contributing to fastapi-jwt

First, thanks for taking the time to contribute! 😍  
It's highly welcomed, and it can help the project to develop and become more usefully and suitable for everyone. 

## Styleguides

### Git Commit Messages

This project uses light version of [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/). 
tl;dr

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests in commit body
* When only changing documentation, include [ci skip] in the commit title
* Consider starting the commit message with an applicable tag:
    * `fix` - small bug fix
    * `docs` - docs changes 
    * `feat` - a new feature 
    * `chore` - changes that do not relate to a fix or feature and don't modify src or test files (for example updating dependencies) 
    * `refactor` - code refactor that neither fixes a bug nor adds a feature
    * `style` - changes that do not affect the meaning of the code
    * `perf` - changes that improve performance
    * `test` - including new or correcting previous tests
    * `ci` - continuous integration related

For example  

Good:
* `feat: create new api endpoint for student scores reporting`
* `perf: improve performance with lazy load implementation for images`
* `chore: update flask dependency to 2.1 version`

Bad:
* `some fixes`
* `oops`
* `fixed bug on landing page`
* `style changes and update`

### Python styleguide

All python code should follow [PEP8](https://www.python.org/dev/peps/pep-0008/) and be typed.   
The code linted with `flake8` and `isort`, as well as type checked with `mypy`.

TBA
