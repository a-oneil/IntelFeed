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

    // eslint-plugin-react-hooks v7 folded the React Compiler rules into
    // `recommended`. Eight of them pass on this tree and stay on, so they guard
    // new code: static-components, use-memo, error-boundaries,
    // set-state-in-render, config, gating, plus incompatible-library and
    // unsupported-syntax as warnings.
    //
    // The six below are off because they fire 118 times on code that predates
    // them. They are real signal, not noise -- turning each one on is its own
    // PR with its own refactor, the same way ruff's target-version bump is.
    // Counts are from v7.1.1 so a future PR can tell progress from drift.
    'react-hooks/set-state-in-effect': 'off', // 53
    'react-hooks/refs': 'off', // 37
    'react-hooks/immutability': 'off', // 12
    'react-hooks/purity': 'off', // 9
    'react-hooks/preserve-manual-memoization': 'off', // 5
    'react-hooks/globals': 'off', // 2
  },
};
