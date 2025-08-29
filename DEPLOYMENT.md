# 🚀 WebSecPen Production Deployment Guide

This guide covers deploying WebSecPen to production using **Render** (backend) and **Vercel** (frontend).

## 📋 Prerequisites

- [x] **Git repository** (GitHub/GitLab)
- [x] **Render account** (render.com)
- [x] **Vercel account** (vercel.com)
- [x] **Domain name** (optional, for custom domains)

## 🏗️ Backend Deployment (Render)

### Step 1: Prepare Repository

1. **Push code to GitHub**:
   ```bash
   git add .
   git commit -m "Production deployment ready"
   git push origin main
   ```

### Step 2: Create Render Web Service

1. **Go to Render Dashboard** → "New" → "Web Service"
2. **Connect your GitHub repository**
3. **Configure service**:
   - **Name**: `websecpen-backend`
   - **Environment**: `Python 3`
   - **Build Command**: `cd backend && pip install -r requirements.txt`
   - **Start Command**: `cd backend && gunicorn --bind 0.0.0.0:$PORT app:app`
   - **Instance Type**: `Starter` (Free tier)

### Step 3: Add Environment Variables

In Render dashboard, add these environment variables:

```bash
FLASK_ENV=production
JWT_SECRET_KEY=your-super-secure-jwt-secret-key-here
DATABASE_URL=postgresql://user:pass@host:port/dbname
```

### Step 4: Create PostgreSQL Database

1. **Render Dashboard** → "New" → "PostgreSQL"
2. **Configure**:
   - **Name**: `websecpen-db`
   - **Database Name**: `websecpen`
   - **User**: `websecpen_user`
   - **Plan**: `Starter` (Free tier)

3. **Copy the Database URL** to your web service's `DATABASE_URL` environment variable

### Step 5: Deploy and Verify

1. **Deploy** the service (automatic after connecting repository)
2. **Check logs** for any errors
3. **Test health endpoint**: `https://your-app.onrender.com/health`

## ☁️ Frontend Deployment (Vercel)

### Step 1: Install Vercel CLI

```bash
npm install -g vercel
```

### Step 2: Deploy from Frontend Directory

```bash
cd frontend
vercel --prod
```

### Step 3: Configure Environment Variables

In Vercel dashboard, add:

```bash
VITE_API_URL=https://websecpen-backend.onrender.com
VITE_APP_VERSION=1.0.0
VITE_APP_NAME=WebSecPen
```

### Step 4: Configure Custom Domain (Optional)

1. **Vercel Dashboard** → Your project → "Settings" → "Domains"
2. **Add your domain** and follow DNS setup instructions

## 🔒 Production Security Checklist

### Backend Security

- [x] **JWT Secret**: Use a strong, randomly generated secret
- [x] **HTTPS**: Render provides SSL/TLS automatically
- [x] **CORS**: Configured for your frontend domain
- [x] **Environment Variables**: All secrets in environment, not code
- [x] **Database**: PostgreSQL with connection pooling
- [x] **Health Checks**: `/health` endpoint for monitoring

### Frontend Security

- [x] **HTTPS**: Vercel provides SSL/TLS automatically
- [x] **Security Headers**: Configured in `vercel.json`
- [x] **Environment Variables**: API URLs in environment
- [x] **Build Optimization**: Minification and tree-shaking enabled
- [x] **Content Security Policy**: Headers configured

## 🧪 Testing Production Deployment

### 1. Backend API Tests

```bash
# Health check
curl https://your-backend.onrender.com/health

# Authentication test
curl -X POST https://your-backend.onrender.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "test123"}'
```

### 2. Frontend Tests

1. **Visit your frontend URL**
2. **Test login/logout flow**
3. **Start a security scan**
4. **Verify mobile responsiveness**
5. **Test dark/light theme toggle**

### 3. E2E Tests

```bash
# Run Cypress tests against production
cd frontend
npx cypress run --config baseUrl=https://your-app.vercel.app
```

## 📊 Monitoring and Maintenance

### Monitoring Setup

1. **Render Monitoring**:
   - Built-in metrics dashboard
   - Log monitoring and alerts
   - Health check monitoring

2. **Vercel Analytics**:
   - Performance monitoring
   - Error tracking
   - Usage analytics

### Database Maintenance

```bash
# Backup database (PostgreSQL)
pg_dump $DATABASE_URL > backup.sql

# Monitor database size and performance
# Use Render's database dashboard
```

### Updates and Deployment

```bash
# Deploy updates
git push origin main  # Auto-deploys backend
vercel --prod         # Deploy frontend updates
```

## 🚨 Troubleshooting

### Common Backend Issues

1. **Database Connection Errors**:
   - Verify `DATABASE_URL` is correct
   - Check PostgreSQL service status
   - Review connection logs

2. **Build Failures**:
   - Check `requirements.txt` versions
   - Verify build command syntax
   - Review build logs in Render

3. **JWT Token Issues**:
   - Ensure `JWT_SECRET_KEY` is set
   - Check token expiration settings
   - Verify CORS configuration

### Common Frontend Issues

1. **API Connection Errors**:
   - Verify `VITE_API_URL` is correct
   - Check CORS headers
   - Test API endpoints directly

2. **Build Failures**:
   - Check Node.js version compatibility
   - Verify all dependencies installed
   - Review build logs

3. **Routing Issues**:
   - Verify `vercel.json` configuration
   - Check SPA routing setup
   - Test direct URL access

## 📈 Performance Optimization

### Backend Optimization

- **Database Query Optimization**: Add indexes, optimize queries
- **Caching**: Implement Redis for session and result caching
- **Load Balancing**: Scale to multiple instances
- **CDN**: Use Render's CDN for static assets

### Frontend Optimization

- **Code Splitting**: Implemented in Vite config
- **Image Optimization**: Use Vercel's image optimization
- **Caching**: Configure browser caching headers
- **Bundle Analysis**: Monitor bundle size

## 🔄 CI/CD Pipeline (Optional)

### GitHub Actions Example

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: cd frontend && npm ci
      - run: cd frontend && npm test
      - run: cd frontend && npm run build

  deploy-frontend:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: cd frontend && npm ci
      - run: cd frontend && npx vercel --prod --token ${{ secrets.VERCEL_TOKEN }}
```

## 📞 Support and Maintenance

### Regular Maintenance Tasks

- **Weekly**: Check error logs and performance metrics
- **Monthly**: Update dependencies and security patches
- **Quarterly**: Review and rotate JWT secrets
- **Annually**: Database cleanup and optimization

### Getting Help

- **Render Support**: https://render.com/docs
- **Vercel Support**: https://vercel.com/docs
- **WebSecPen Issues**: [GitHub Issues](link-to-your-repo)

---

## 🎉 Congratulations!

Your **WebSecPen AI-Powered Security Scanner** is now live in production!

- **Backend**: https://websecpen-backend.onrender.com
- **Frontend**: https://your-app.vercel.app
- **Status**: 🟢 Production Ready

**Your platform now provides enterprise-grade security scanning with AI analysis to users worldwide!** 🌍🛡️ 