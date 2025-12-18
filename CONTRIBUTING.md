# Contributing to Guardrail

First off, thank you for considering contributing to Guardrail! It's people like you that make Guardrail such a great tool.

## Code of Conduct

By participating in this project, you are expected to uphold our code of conduct: be respectful, inclusive, and considerate to others.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title** for the issue
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** to demonstrate the steps
- **Describe the behavior you observed** and what you expected
- **Include your environment details** (OS, Node.js version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful**
- **List any alternative solutions** you've considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Install dependencies**: `npm install`
3. **Make your changes** following our coding standards
4. **Add tests** for any new functionality
5. **Ensure all tests pass**: `npm test`
6. **Ensure linting passes**: `npm run lint`
7. **Format your code**: `npm run format`
8. **Submit your pull request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/guardrail.git
cd guardrail

# Install dependencies
npm install

# Run tests
npm test

# Run linting
npm run lint

# Format code
npm run format

# Build
npm run build
```

## Coding Standards

- Write TypeScript with strict type checking
- Follow the existing code style (enforced by ESLint and Prettier)
- Write meaningful commit messages
- Add JSDoc comments for public APIs
- Keep functions focused and small
- Write tests for new functionality

## Testing

- Write unit tests using Vitest
- Ensure tests are deterministic and don't depend on external services
- Mock external dependencies when necessary
- Aim for good test coverage

## Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests when relevant

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

Thank you for contributing! 🎉
