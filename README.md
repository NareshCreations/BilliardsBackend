# nBilliardsNodeJS - Hello World App

A simple Node.js Express application for Railway testing.

## Features

- ✅ Hello World endpoint
- ✅ Health check endpoint
- ✅ CORS enabled
- ✅ TypeScript support
- ✅ Docker support

## Quick Start

### Local Development

1. Install dependencies:
```bash
npm install
```

2. Run in development mode:
```bash
npm run dev
```

3. Build and run:
```bash
npm run build
npm start
```

### Docker

```bash
docker build -t nBilliardsNodeJS .
docker run -p 3000:3000 nBilliardsNodeJS
```

## API Endpoints

- `GET /` - Hello World message
- `GET /health` - Health check

## Railway Deployment

This app is ready for Railway deployment. Just connect your GitHub repository to Railway and it will automatically deploy.

## Environment Variables

- `PORT` - Server port (default: 3000)
