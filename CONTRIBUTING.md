# Contributing to Abyss

## Development Setup
```bash
git clone https://github.com/Real-Fruit-Snacks/Abyss.git
cd Abyss
cargo build
cargo test
```

## Code Style
- Run `cargo fmt` and `cargo clippy -- -D warnings` before committing
- All exported functions must have doc comments
- Unsafe code requires `// SAFETY:` comments

## Adding a New Extractor
1. Create extractor in appropriate crate (crypto, browser, memory)
2. Define finding type in `abyss-output`
3. Wire into the extraction pipeline in `abyss-target`
4. Add tests with sample artifacts

## Pull Request Process
1. Fork and create feature branch from `master`
2. Write tests for new functionality
3. Ensure `cargo test` passes
4. Submit PR with clear description
