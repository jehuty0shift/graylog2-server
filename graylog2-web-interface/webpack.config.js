const fs = require('fs');

const webpack = require('webpack');
const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CspHtmlWebpackPlugin = require('csp-html-webpack-plugin');
const {merge} = require('webpack-merge');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const CircularDependencyPlugin = require('circular-dependency-plugin')

const UniqueChunkIdPlugin = require('./webpack/UniqueChunkIdPlugin');

const ROOT_PATH = path.resolve(__dirname);
const APP_PATH = path.resolve(ROOT_PATH, 'src');
const BUILD_PATH = path.resolve(ROOT_PATH, 'target/web/build');
const MANIFESTS_PATH = path.resolve(ROOT_PATH, 'manifests');
const VENDOR_MANIFEST_PATH = path.resolve(MANIFESTS_PATH, 'vendor-manifest.json');
const TARGET = process.env.npm_lifecycle_event || 'build';
process.env.BABEL_ENV = TARGET;

const BABELRC = path.resolve(ROOT_PATH, 'babel.config.js');
const BABELOPTIONS = {
  cacheDirectory: 'target/web/cache',
  extends: BABELRC,
};

const BABELLOADER = { loader: 'babel-loader', options: BABELOPTIONS };

// eslint-disable-next-line import/no-dynamic-require
const BOOTSTRAPVARS = require(path.resolve(ROOT_PATH, 'public', 'stylesheets', 'bootstrap-config.json')).vars;



const getCssLoaderOptions = () => {
    const returnCssMode = (resourcePath) => {
    if (/node_modules/i.test(resourcePath)) {
        return "global";
    }
    return "local";
   }

    
    // Development
    if (TARGET === 'start') {
        return {
            modules : { 
                localIdentName: '[name]__[local]--[fullhash:base64:5]',
                mode: returnCssMode
            }
        }
    }

    return { 
        modules : {
            localIdentName: '[hash:base64]',
            mode: returnCssMode
        } 
    };

};

const chunksSortMode = (c1, c2) => {
  // Render the polyfill chunk first
  if (c1 === 'polyfill') {
    return -1;
  }

  if (c2 === 'polyfill') {
    return 1;
  }

  if (c1 === 'builtins') {
    return -1;
  }

  if (c2 === 'builtins') {
    return 1;
  }

  if (c1 === 'app') {
    return 1;
  }

  if (c2 === 'app') {
    return -1;
  }

  return 0;
};

const webpackConfig = {
  name: 'app',
  dependencies: ['vendor'],
  entry: {
    app: APP_PATH,
    builtins: [path.resolve(APP_PATH, 'injection', 'builtins.js')],
  },
  output: {
    path: BUILD_PATH,
    filename: '[name].[fullhash].js',
  },
  module: {
    rules: [
      { test: /\.js(x)?$/i, use: BABELLOADER, exclude: /node_modules|\.node_cache/ },
      { test: /\.(svg)(\?.+)?$/, use: { loader: 'file-loader' } },
//      {
//        test: /\.(woff(2)?|ttf)(\?.+)?$/,
//        use: [{
//          loader: 'file-loader', options: { esModule: false },
//        }],
//      },
      { test: /\.(png|gif|jpg)(\?.+)?$/, use: 'url-loader' },
      {
        test: /bootstrap\.less$/i,
        use: [
          {
            loader: 'style-loader',
            options: {
              insert: 'head',
            },
          },
            {loader: 'css-loader'},
          {
            loader: 'less-loader',
            options: {
                lessOptions: {
                    modifyVars: BOOTSTRAPVARS,
                }
            },
          },
        ],
      },
      { test: /\.less$/i, use: ['style-loader', 'css-loader', 'less-loader'], exclude: /bootstrap\.less$/i },
      {
        test: /\.css$/i,
        include: [ /node_modules/],
	    exclude: [ /\.lazy\.css$/i, /.*leaflet\.css$/i ],
        sideEffects: true,
        use: [
          {loader: 'style-loader'},
          {
            loader: 'css-loader',
            options: getCssLoaderOptions(),
          },
        ],
      },
      {
        test: /\.css$/i,
	    exclude: [ /\.lazy\.css$/i, /.*leaflet\.css$/i, /node_modules/ ],
        use: [
          {loader: 'style-loader'},
          {
            loader: 'css-loader',
            options: getCssLoaderOptions(),
          },
        ],
      },
      {
        test: [/\.lazy\.css$/i, /.*leaflet\.css$/i ],
        use: [
	   { loader : 'style-loader', options: { injectType: 'lazyStyleTag'}},
       { loader : 'css-loader'},
        ],
      },
    ],
  },
  resolve: {
    // you can now require('file') instead of require('file.coffee')
    extensions: ['.js', '.json', '.jsx'],
    modules: [APP_PATH, 'node_modules', path.resolve(ROOT_PATH, 'public')],
    alias: {
      theme: path.resolve(APP_PATH, 'theme'),
      'lodash-es':'lodash',
    },
  },
  resolveLoader: { modules: [path.join(ROOT_PATH, 'node_modules')]},
  plugins: [
    new UniqueChunkIdPlugin(),
    new webpack.DllReferencePlugin({ manifest: VENDOR_MANIFEST_PATH, context: ROOT_PATH }),
   new webpack.DefinePlugin({
      FEATURES: JSON.stringify(process.env.FEATURES),
    }),
  ],
};

if (TARGET === 'start') {
  // eslint-disable-next-line no-console
  console.error('Running in development (no HMR) mode');

  module.exports = merge(webpackConfig, {
//    stats: {
//    all: true,
//    // Examine all modules
//    //maxModules: 42,
//    // Display bailout reasons
//    optimizationBailout: true,
//  },
    mode: 'development',
    devtool: 'cheap-module-source-map',
    output: {
      path: BUILD_PATH,
      filename: '[name].js',
      publicPath: '/',
    },
    optimization: { 
	    runtimeChunk : 'single', 
	    moduleIds: 'named',
    },
    plugins: [
      new webpack.DefinePlugin({
        DEVELOPMENT: true,
        GRAYLOG_HTTP_PUBLISH_URI: JSON.stringify(process.env.GRAYLOG_HTTP_PUBLISH_URI),
      }),
      new HtmlWebpackPlugin({
          title: 'Graylog',
          favicon: path.resolve(ROOT_PATH, 'public/images/favicon.png'),
          filename: 'index.html',
          inject: false,
          template: path.resolve(ROOT_PATH, 'templates/index.html.template'),
          vendorModule: () => JSON.parse(fs.readFileSync(path.resolve(BUILD_PATH, 'vendor-module.json'), 'utf8')),
          chunksSortMode,
          cspPlugin: {
              enabled: false,
          }
        }),
        new HtmlWebpackPlugin({
          filename: 'module.json',
          inject: false,
          template: path.resolve(ROOT_PATH, 'templates/module.json.template'),
          excludeChunks: ['config'],
          chunksSortMode,
          cspPlugin: {
              enabled: false,
         }
        }),
      new CopyWebpackPlugin({ patterns: [{ from: 'config.js' }] }),
      new webpack.HotModuleReplacementPlugin(),
    ],
  });

}

if (TARGET.startsWith('build')) {
  // eslint-disable-next-line no-console
  console.error('Running in production mode');
  process.env.NODE_ENV = 'production';

  module.exports = merge(webpackConfig, {
    mode: 'production',
    devtool: false,
    optimization: {
        minimize: true,
//        splitChunks: {
//                chunks: 'all',
//            },
//            runtimeChunk: true,
//        runtimeChunk : 'single',
//        moduleIds: 'named',
        minimizer: [new TerserPlugin({
          parallel: true,
          terserOptions: {
            compress: {
              warnings: false,
            },
        },
      })],
//     moduleIds: 'deterministic',
    },
    plugins: [
      new webpack.DefinePlugin({
        'process.env.NODE_ENV': JSON.stringify('production'),
      }),
      new HtmlWebpackPlugin({
          title: 'Graylog',
          favicon: path.resolve(ROOT_PATH, 'public/images/favicon.png'),
          filename: 'index.html',
          inject: false,
          template: path.resolve(ROOT_PATH, 'templates/index.html.template'),
          vendorModule: () => JSON.parse(fs.readFileSync(path.resolve(BUILD_PATH, 'vendor-module.json'), 'utf8')),
          chunksSortMode,
          cspPlugin: {
              enabled: true,
              policy: {
                'script-src': ["'self'"],
                'style-src': [ "'self'"]
              },
              hashEnabled: {
                'script-src': true,
                'style-src': true
              },
              nonceEnabled: {
                'script-src': true,
                'style-src': true
              }
          }
        }),
        new HtmlWebpackPlugin({
          filename: 'module.json',
          inject: false,
          template: path.resolve(ROOT_PATH, 'templates/module.json.template'),
          excludeChunks: ['config'],
          chunksSortMode,
          cspPlugin: {
                    enabled: true,
                    policy: {
                      'script-src': ["'self'"],
                      'style-src': ["'self'", "'unsafe-inline'"]
                    },
                    hashEnabled: {
                      'script-src': true,
                      'style-src': true
                    },
                    nonceEnabled: {
                      'script-src': true,
                      'style-src': true
                    }
          }
        }),
        new CspHtmlWebpackPlugin({
          'script-src': ["'self'"],
          'style-src': ["'self'", "'unsafe-inline'"]
        }),       
    ],
  });
}

if (TARGET === 'test') {
  // eslint-disable-next-line no-console
  console.error('Running test/ci mode');

  module.exports = merge(webpackConfig, {
    module: {
      rules: [
        { test: /\.js(x)?$/, enforce: 'pre', loader: 'eslint-loader', exclude: /node_modules|public\/javascripts/ },
      ],
    },
  });
}

if (Object.keys(module.exports).length === 0) {
  module.exports = webpackConfig;
}
