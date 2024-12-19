module.exports = {
	presets: [['@babel/preset-env', { modules: false, useBuiltIns : "usage", "corejs": 3  }], ['@babel/preset-react'],['@babel/preset-typescript'], ['@babel/flow']],
  plugins: [
    'babel-plugin-styled-components',
    'lodash',
  ],
  env: {
    test: {
      presets: ['@babel/preset-env'],
      plugins: [
        'babel-plugin-dynamic-import-node',
        '@babel/plugin-transform-runtime',
      ],
    },
  },
};
