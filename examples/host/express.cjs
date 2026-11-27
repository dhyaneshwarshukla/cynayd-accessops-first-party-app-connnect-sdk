const express = require('express');
const path = require('node:path');
const { hostErrorResponse } = require('@cynayd/accessops-first-party-app-connnect-sdk');
const { basePath, host, nodeHandler } = require('./config.cjs');

const app = express();
app.use(basePath, nodeHandler);
const portal = process.env.ONE_PORTAL_ORIGIN;
app.get('/', (_req, res) => {
  res.set('Content-Security-Policy', "default-src 'self'; frame-src " + portal + "; object-src 'none'; base-uri 'none'");
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/reference-config', (_req, res) => res.set('Cache-Control', 'no-store').json({ onePortalOrigin: portal }));
app.get('/reference-browser.js', (_req, res) => res.sendFile(path.join(__dirname, 'reference-browser.js')));

app.get('/api/me', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    res.json(await host.status(req.get('Cookie')));
  } catch (error) {
    const response = hostErrorResponse(error);
    res.status(response.status).json(response.body);
  }
});
app.listen(3000, '127.0.0.1');
