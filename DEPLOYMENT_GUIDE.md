# FirewallX Deployment Guide - Vercel & Railway

Complete step-by-step guide to deploy FirewallX to Vercel (frontend) and Railway (backend API).

## 📋 Prerequisites

### For Vercel (Frontend)
- Vercel account (free tier works)
- Vercel CLI installed: `npm i -g vercel`
- Node.js 18+ installed

### For Railway (Backend)
- Railway account (free tier available)
- Railway CLI installed: `npm i -g @railway/cli`
- GitHub account for integration

---

## 🚀 Quick Deploy Commands

### Option 1: One-Click Deploy (Recommended)

```bash
# Run the automated deployment script
./scripts/deploy-all.sh
```

This script will:
1. Build the UI
2. Deploy frontend to Vercel
3. Deploy backend API to Railway
4. Configure environment variables
5. Provide you with deployment URLs

---

## 🎨 Manual Deployment

### Deploy Frontend to Vercel

#### Step 1: Install Vercel CLI
```bash
npm install -g vercel
```

#### Step 2: Login to Vercel
```bash
vercel login
```

#### Step 3: Deploy
```bash
# Navigate to project root
cd /Users/macbookpri/Downloads/firewallX

# Deploy to production
vercel --prod
```

#### Step 4: Configure Environment Variables
In Vercel dashboard, set:
```
VITE_API_URL=https://your-railway-app.railway.app
```

#### Step 5: Access Your Frontend
Your frontend will be live at:
```
https://firewallx-xxxx.vercel.app
```

---

### Deploy Backend to Railway

#### Step 1: Install Railway CLI
```bash
npm install -g @railway/cli
```

#### Step 2: Login to Railway
```bash
railway login
```

#### Step 3: Initialize Project
```bash
# Create new project on Railway
railway init

# Or link to existing project
railway link
```

#### Step 4: Configure Environment
```bash
# Set environment variables
railway variables set \
  RUST_LOG=info \
  PROMETHEUS_ENABLED=true \
  PROMETHEUS_PORT=9100 \
  AI_AGENT_ENABLED=false \
  CONFIG_PATH=/app/config.toml
```

#### Step 5: Deploy
```bash
# Deploy using Dockerfile.railway
railway up
```

#### Step 6: Add Custom Domain (Optional)
```bash
# Add railway.app subdomain
railway domain add firewallx

# Or add your own domain
railway domain add firewall.yourdomain.com
```

#### Step 7: Access Your API
Your backend API will be live at:
```
https://your-app.up.railway.app
```

Health check endpoint:
```
https://your-app.up.railway.app/health
```

Metrics endpoint:
```
https://your-app.up.railway.app:9100/metrics
```

---

## 🔧 Configuration Details

### Vercel Configuration (vercel.json)

```json
{
  "version": 2,
  "name": "firewallx",
  "builds": [
    {
      "src": "firewallx-ui/package.json",
      "use": "@vercel/static-build"
    }
  ],
  "routes": [...],
  "outputDirectory": "firewallx-ui/dist",
  "installCommand": "cd firewallx-ui && npm install",
  "buildCommand": "cd firewallx-ui && npm run build",
  "env": {
    "VITE_API_URL": "https://api.firewallx.example.com"
  }
}
```

**Key Settings:**
- **buildCommand**: Builds React UI with Vite
- **outputDirectory**: Where built files are located
- **env**: API URL for frontend to connect to backend

### Railway Configuration (railway.toml)

```toml
[build]
builder = "DOCKERFILE"
dockerfilePath = "Dockerfile.railway"

[deploy]
startCommand = "./target/release/firewallx start --api-only"
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 3
healthcheckPath = "/health"
healthcheckTimeout = 30

[service]
name = "FirewallX API"
port = 3000

[service.variables]
RUST_LOG = "info"
PROMETHEUS_ENABLED = "true"
PROMETHEUS_PORT = "9100"
AI_AGENT_ENABLED = "false"
CONFIG_PATH = "/app/config.toml"
```

**Key Settings:**
- **healthcheckPath**: Railway checks this endpoint for health
- **port**: API server listens on port 3000
- **restartPolicyType**: Auto-restart on failures

### Dockerfile.railway

Multi-stage build for optimal size:
- **Stage 1 (Builder)**: Compiles Rust binary (~1.5GB)
- **Stage 2 (Runtime)**: Minimal Debian image (~150MB)

Features:
- Non-root user for security
- Health checks enabled
- Prometheus metrics exposed
- Optimized for cloud (no eBPF)

---

## 🌐 Environment Variables

### Frontend (Vercel)

| Variable | Description | Example |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | `https://app.railway.app` |

### Backend (Railway)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `RUST_LOG` | Log level | `info` | No |
| `PROMETHEUS_ENABLED` | Enable metrics | `true` | No |
| `PROMETHEUS_PORT` | Metrics port | `9100` | No |
| `AI_AGENT_ENABLED` | Enable AI analyst | `false` | No |
| `OPENAI_API_KEY` | OpenAI API key | - | Only if AI enabled |
| `CONFIG_PATH` | Config file path | `/app/config.toml` | No |

---

## 📊 Post-Deployment Verification

### Check Frontend Status

```bash
# Visit your Vercel URL
curl https://firewallx-xxxx.vercel.app

# Should return HTML of React app
```

### Check Backend Status

```bash
# Health check
curl https://your-app.railway.app/health

# Expected response:
# {"status":"ok","uptime":123456}

# Get firewall stats
curl https://your-app.railway.app/api/stats

# List rules
curl https://your-app.railway.app/api/rules
```

### Test API Endpoints

```bash
# Add a rule
curl -X POST https://your-app.railway.app/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block SSH",
    "action": "drop",
    "port": 22,
    "protocol": "tcp",
    "direction": "inbound"
  }'

# View metrics
curl https://your-app.railway.app:9100/metrics
```

---

## 🔍 Monitoring & Debugging

### Vercel Frontend

1. **View Logs**
   ```bash
   vercel logs <deployment-url>
   ```

2. **Dashboard**
   - Visit: https://vercel.com/dashboard
   - Monitor builds, deployments, analytics

3. **Custom Domain**
   - Go to project settings → Domains
   - Add your custom domain

### Railway Backend

1. **View Logs**
   ```bash
   railway logs
   ```

2. **Real-time Logs**
   ```bash
   railway logs --follow
   ```

3. **Dashboard**
   - Visit: https://railway.app/dashboard
   - Monitor CPU, memory, network usage

4. **Prometheus Metrics**
   ```bash
   curl https://your-app.railway.app:9100/metrics
   ```

   Key metrics:
   - `firewallx_packets_total`: Packet counters
   - `firewallx_allowed`: Allowed packets
   - `firewallx_dropped`: Dropped packets
   - `firewallx_dpi_blocked`: DPI blocked threats

---

## ⚙️ Advanced Configuration

### Enable AI Security Analyst

Add to Railway environment variables:
```bash
railway variables set \
  AI_AGENT_ENABLED=true \
  OPENAI_API_KEY=sk-your-api-key-here \
  AI_MODEL=gpt-4-turbo-preview
```

### Import Threat Signatures

After deployment:
```bash
curl -X POST https://your-app.railway.app/api/rules/import \
  -H "Content-Type: application/json" \
  -d '{"file": "emerging-threats.rules"}'
```

### Configure Blocklist Feeds

```bash
curl -X POST https://your-app.railway.app/api/feed/add \
  -H "Content-Type: application/json" \
  -d '{"url": "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"}'
```

### Setup SIEM Integration

```bash
curl -X POST https://your-app.railway.app/api/siem/enable \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://splunk.internal:8088/services/collector",
    "key": "your-siem-api-key"
  }'
```

---

## 🚨 Troubleshooting

### Frontend Issues

**Problem:** Blank page after deployment
```bash
# Check build logs
vercel logs --since 1h

# Verify API URL is correct
cat firewallx-ui/.env.production
```

**Problem:** API calls failing
```bash
# Check CORS settings in backend
# Ensure VITE_API_URL points to correct Railway URL
```

### Backend Issues

**Problem:** Container won't start
```bash
# Check logs
railway logs --since 1h

# Common fix: Rebuild
railway up --rebuild
```

**Problem:** Health check failing
```bash
# Manually test health endpoint
curl https://your-app.railway.app/health

# Check if port is correct
railway variables get PORT
```

**Problem:** High memory usage
```bash
# Reduce rule count or DPI signatures
# Scale down resources in Railway dashboard
```

---

## 💰 Cost Estimates

### Vercel (Frontend)
- **Free Tier**: 
  - 100GB bandwidth/month
  - Unlimited deployments
  - Perfect for demos/small apps

- **Pro Tier** ($20/month):
  - More analytics
  - Priority support

### Railway (Backend)
- **Free Tier**:
  - $5 credit/month
  - ~500 hours of compute
  - Good for testing

- **Paid** ($5-20/month):
  - More CPU/RAM
  - Persistent storage
  - Production workloads

**Estimated Monthly Cost:**
- Hobby project: $0-10
- Small business: $20-50
- Production: $50-200

---

## 🎯 Best Practices

### Security
1. ✅ Use environment variables for secrets
2. ✅ Enable HTTPS everywhere
3. ✅ Restrict CORS to your domains
4. ✅ Use non-root users in containers
5. ✅ Regular dependency updates

### Performance
1. ✅ Enable CDN caching for static assets
2. ✅ Use gzip/brotli compression
3. ✅ Optimize Docker images (multi-stage builds)
4. ✅ Monitor resource usage
5. ✅ Scale horizontally if needed

### Reliability
1. ✅ Configure health checks
2. ✅ Set up auto-restart policies
3. ✅ Monitor logs and alerts
4. ✅ Backup configurations regularly
5. ✅ Test disaster recovery

---

## 📞 Support Resources

### Documentation
- **Vercel Docs**: https://vercel.com/docs
- **Railway Docs**: https://docs.railway.app
- **FirewallX Docs**: See ARCHITECTURE.md in repo

### Community
- **Vercel Discord**: https://vercel.community
- **Railway Discord**: https://discord.gg/railway
- **GitHub Issues**: Report bugs in FirewallX repo

### Monitoring Tools
- **Uptime Robot**: Free uptime monitoring
- **Better Stack**: Log aggregation
- **Grafana Cloud**: Prometheus dashboards

---

## 🎉 Success Checklist

After deployment, verify:

- [ ] Frontend loads successfully
- [ ] Backend API responds to /health
- [ ] Can add/list firewall rules via API
- [ ] Prometheus metrics accessible
- [ ] Logs visible in respective dashboards
- [ ] CORS configured correctly
- [ ] Environment variables set properly
- [ ] SSL certificates valid (HTTPS working)

**Congratulations! Your FirewallX is now deployed and protecting networks from the cloud! 🚀**
