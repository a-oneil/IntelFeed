module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react/recommended',
    'plugin:react/jsx-runtime',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', '.eslintrc.cjs'],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  plugins: ['react', '@typescript-eslint'],
  settings: {
    react: { version: 'detect' },
  },
  rules: {
    // The browser's own dialogs are unstyled, unthemeable and sit outside the
    // app's focus and keyboard handling. Use the app's dialogs instead.
    'no-restricted-globals': [
      'error',
      { name: 'confirm', message: 'Use confirmDialog() from @/utils/dialog instead of the browser dialog.' },
      { name: 'alert', message: 'Use alertDialog() from @/utils/dialog instead of the browser dialog.' },
      { name: 'prompt', message: 'Use promptDialog() from @/utils/dialog instead of the browser dialog.' },
    ],
    'no-restricted-properties': [
      'error',
      { object: 'window', property: 'confirm', message: 'Use confirmDialog() from @/utils/dialog.' },
      { object: 'window', property: 'alert', message: 'Use alertDialog() from @/utils/dialog.' },
      { object: 'window', property: 'prompt', message: 'Use promptDialog() from @/utils/dialog.' },
    ],
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    'react/prop-types': 'off',
    'react/no-unescaped-entities': 'off',
  },
};
