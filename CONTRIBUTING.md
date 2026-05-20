# Contributing

Thank you for contributing to NmapLens.

## Before You Start

- Keep changes focused and easy to review
- Use clear commit messages
- Prefer Python standard library only
- Make sure new behavior is covered by tests when practical

## Local Workflow

```bash
git clone https://github.com/erfan0181/nmaplens.git
cd nmaplens
python3 -m unittest discover -s tests -v
```

## Development Guidelines

- Follow the existing project structure
- Keep functions small and readable
- Add type hints where they improve clarity
- Preserve the security disclaimer in user-facing reports and docs
- Update `README.md` and `CHANGELOG.md` when behavior changes

## Pull Requests

Please include:

- A short description of the change
- Why the change is needed
- Test notes or command output when relevant
- Screenshots if the HTML report layout changes

## Security

This project is for educational and authorized security testing only.
Do not use it against systems without explicit permission.
