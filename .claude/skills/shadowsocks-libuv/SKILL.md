```markdown
# shadowsocks-libuv Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `shadowsocks-libuv` TypeScript codebase. You'll learn about file naming, import/export styles, and how to write and run tests. The repository does not use a specific framework, so patterns are lightweight and focused on idiomatic TypeScript.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `serverConfig.ts`, `cryptoUtils.ts`

### Import Style
- Use **relative imports** for internal modules.
  - Example:
    ```typescript
    import { encrypt } from './cryptoUtils';
    ```

### Export Style
- Use **named exports** for functions, classes, or constants.
  - Example:
    ```typescript
    // cryptoUtils.ts
    export function encrypt(data: Buffer): Buffer { ... }
    export function decrypt(data: Buffer): Buffer { ... }
    ```

### Commit Patterns
- Commit messages are **freeform** (no enforced structure).
- Commonly use short, descriptive messages (~58 characters on average).
  - Example: `fix buffer overflow in decrypt function`

## Workflows

### Running Tests
**Trigger:** When you want to verify code correctness.
**Command:** `/run-tests`

1. Identify test files (pattern: `*.test.*`).
2. Use the appropriate test runner (framework is unknown; check for scripts in `package.json` or use `ts-node`/`node` if tests are plain TypeScript/JavaScript).
3. Run the tests and review the output.

### Adding a New Module
**Trigger:** When you need to add new functionality.
**Command:** `/add-module`

1. Create a new file using camelCase (e.g., `newFeature.ts`).
2. Use named exports for all public functions/classes.
3. Import dependencies using relative paths.
4. Write corresponding tests in a file named `newFeature.test.ts`.

### Refactoring Code
**Trigger:** When improving or restructuring existing code.
**Command:** `/refactor`

1. Update file and variable names to use camelCase.
2. Ensure all internal imports are relative.
3. Use named exports consistently.
4. Update or add tests as needed.

## Testing Patterns

- Test files follow the `*.test.*` naming convention (e.g., `cryptoUtils.test.ts`).
- The test framework is not specified; check for test scripts or conventions in the repository.
- Place tests alongside or near the modules they test.

**Example Test File:**
```typescript
// cryptoUtils.test.ts
import { encrypt, decrypt } from './cryptoUtils';

describe('cryptoUtils', () => {
  it('should encrypt and decrypt data correctly', () => {
    const data = Buffer.from('hello');
    const encrypted = encrypt(data);
    const decrypted = decrypt(encrypted);
    expect(decrypted.toString()).toBe('hello');
  });
});
```

## Commands
| Command      | Purpose                                 |
|--------------|-----------------------------------------|
| /run-tests   | Run all test files in the repository    |
| /add-module  | Add a new module following conventions  |
| /refactor    | Refactor code to match codebase style   |
```
