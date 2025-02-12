const express = require('express');
const webpack = require('webpack');
const compress = require('compression');
const history = require('connect-history-api-fallback');
const http = require('http');
const fs = require('fs');
const https = require('https');
const yargs = require('yargs');
const webpackDevMiddleware = require('webpack-dev-middleware');
const webpackHotMiddleware = require('@lukeapage/webpack-hot-middleware');
const webpackConfig = require('./webpack.bundled');

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 8080;

const SSL_ENABLE=true

const app = express();
const vendorConfig = webpackConfig[0];
const appConfig = webpackConfig[1];
// Use two compilers to avoid re-compiling the vendor config on every change.
// We assume dependencies won't change while the server is running.
const vendorCompiler = webpack(vendorConfig);
const appCompiler = webpack(appConfig);


app.use(compress()); // Enables compression middleware
app.use(history()); // Enables HTML5 History API middleware

app.use(webpackDevMiddleware(vendorCompiler, {
  publicPath: appConfig.output.publicPath,
}));

app.use(webpackDevMiddleware(appCompiler, {
  publicPath: appConfig.output.publicPath,
}));

//app.use(webpackHotMiddleware(appCompiler));

app.use(
    webpackHotMiddleware(appCompiler, {
      log: console.log,
      path: '/__webpack_hmr',
      heartbeat: 10 * 1000,
    })
);

const server = http.createServer(app);

const argv = yargs.argv;
const host = argv.host || DEFAULT_HOST;
const port = argv.port || DEFAULT_PORT;


server
  .listen(port, host, () => {
    console.log(`Graylog web interface listening on http://${server.address().address}:${server.address().port}!\n`);
  })
  .on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      console.error(`Address http://${host}:${port} already in use, will use a random one instead...`);
      server.listen(0, host);
    } else {
      throw error;
    }
  });

if (SSL_ENABLE !== true) {
} else {

var privateKey = fs.readFileSync('sslCert/server.key', 'utf8');
var certificate = fs.readFileSync('sslCert/server.crt', 'utf8');

var credentials = {key: privateKey, cert: certificate}

const httpsServer = https.createServer(credentials, app);

httpsServer.listen(port+1,host, () => {
   console.log(`Graylog web secure interface listening on https://${httpsServer.address().address}:${httpsServer.address().port}!\n`);
  })
  .on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      console.error(`Address https://${host}:${port} already in use, will use a random one instead...`);
      server.listen(0, host);
    } else {
      throw error;
    }   
  });




}
