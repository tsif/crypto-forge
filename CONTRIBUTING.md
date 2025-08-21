# Contributing to CryptoForge

Thank you for considering contributing to CryptoForge! We welcome contributions from everyone.

## How to Contribute

### Reporting Issues

Before creating an issue:
1. Check if the issue already exists
2. Include clear reproduction steps
3. Specify your browser and OS version
4. For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Suggesting Features

1. Check existing issues and discussions
2. Open a discussion for major features
3. Describe the use case and expected behavior
4. Consider implementation complexity

### Contributing Code

#### Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/key-wizard.git
   cd key-wizard
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

#### Development Process

1. Make your changes
2. Follow existing code style and patterns
3. Test your changes thoroughly:
   ```bash
   npm test
   npm run build
   ```
4. Ensure no security vulnerabilities are introduced
5. Update documentation if needed

#### Code Standards

- **JavaScript/React**: Follow existing component patterns
- **CSS**: Use CSS variables for theming
- **Security**: Never log or expose sensitive data
- **Accessibility**: Ensure features work with keyboard navigation
- **Performance**: Minimize bundle size, optimize renders

#### Commit Messages

Use clear, descriptive commit messages:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation
- `style:` for formatting changes
- `refactor:` for code restructuring
- `test:` for test additions/changes
- `chore:` for maintenance tasks

Example: `feat: add P-521 elliptic curve support`

#### Pull Request Process

1. Update the README.md with details of changes if needed
2. Ensure all tests pass and build succeeds
3. Update documentation for new features
4. Request review from maintainers
5. Address review feedback promptly

### Testing Guidelines

- Test all cryptographic operations in multiple browsers
- Verify JWT verification with various token formats
- Test certificate parsing with different certificate types
- Ensure x5c extraction works with certificate chains
- Test theme switching and font size changes
- Verify mobile responsiveness

### Documentation

- Document new features in README
- Add inline comments for complex logic
- Update type definitions if applicable
- Include examples for new functionality

## Key Areas for Contribution

### High Priority

- Additional JWT algorithm support
- Enhanced certificate chain validation
- Improved error messages and user guidance
- Performance optimizations
- Accessibility improvements

### Good First Issues

Look for issues labeled `good first issue` for beginner-friendly tasks.

### Feature Requests

- Additional key formats (PKCS#1, etc.)
- More certificate validation features
- Enhanced JWT debugging tools
- Key strength recommendations
- Batch operations support

## Development Setup

### Prerequisites

- Node.js 14+ and npm 6+
- Modern browser for testing
- Git for version control

### Local Development

```bash
# Install dependencies
npm install

# Start development server
npm start

# Run tests
npm test

# Build for production
npm run build

# Run linter
npm run lint
```

### Project Structure

```
key-wizard/
├── src/
│   ├── components/     # React components
│   ├── utils/          # Cryptographic utilities
│   ├── App.js          # Main application
│   └── App.css         # Styles
├── public/             # Static assets
└── package.json        # Dependencies
```

## Questions?

Feel free to:
- Open a GitHub discussion
- Check existing issues
- Review the documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Acknowledgments

Thank you to all contributors who help make CryptoForge better!