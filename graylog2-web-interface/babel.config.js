module.exports = {
	presets: [['@babel/preset-env', { modules: false, useBuiltIns : "usage", "corejs": 3  }], '@babel/react', '@babel/flow'],
  plugins: [
    '@babel/plugin-syntax-dynamic-import',
    '@babel/plugin-proposal-class-properties',
    'babel-plugin-styled-components',
    'lodash',
  ],
  env: {
    test: {
      presets: ['@babel/preset-envenv'],
      plugins: [
        'babel-plugin-dynamic-import-node',
        '@babel/plugin-transform-runtime',
      ],
    },
  },
};
