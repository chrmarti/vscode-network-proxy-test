const tsParser = require('@typescript-eslint/parser');
const stylistic = require('@stylistic/eslint-plugin');

module.exports = [
    {
        ignores: [
            'out/**',
            'dist/**',
            '**/*.d.ts'
        ]
    },
    {
        files: ['**/*.ts', '**/*.tsx'],
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaVersion: 6,
                sourceType: 'module'
            }
        },
        plugins: {
            '@stylistic': stylistic
        },
        rules: {
            '@stylistic/semi': 'warn',
            'curly': 'warn',
            'eqeqeq': 'warn',
            'no-throw-literal': 'warn'
        }
    }
];
