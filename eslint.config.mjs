import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**'] },
  { files: ['src/**/*.ts'], extends: [js.configs.recommended, ...tseslint.configs.recommended] },
  { files: ['test/**/*.cjs'], ...js.configs.recommended,
    languageOptions: { globals: { require: 'readonly', Buffer: 'readonly', setTimeout: 'readonly', fetch: 'readonly', Response: 'readonly' } } },
);
