# 🚀 Deploy FirewallX to Cloud - Quick Start

**Automated deployment to Vercel (Frontend) + Railway (Backend)**

---

## ⚡ One-Command Deploy

```bash
chmod +x scripts/deploy-all.sh
./scripts/deploy-all.sh
```

That's it! The script will:
1. ✅ Build the React UI
2. ✅ Deploy frontend to Vercel
3. ✅ Deploy backend API to Railway  
4. ✅ Configure environment variables
5. ✅ Connect frontend to backend

**Time:** ~5-10 minutes

---

## 📋 What You'll Get

After deployment:

### Frontend (Vercel)
- **URL**: `https://firewallx-xxxx.vercel.app`
- **Features**: Web dashboard, rule management, real-time stats
- **Cost**: Free tier (100GB/month bandwidth)

### Backend (Railway)
- **URL**: `https://your-app.railway.app`
- **API**: RESTful firewall management
- **Metrics**: Prometheus endpoint at port 9100
- **Health**: `/health` endpoint
- **Cost**: Free tier ($5 credit/month)

---

## 🎯 Manual Deployment (Optional)

### Deploy Frontend Only
```bash
chmod +x scripts/deploy-vercel.sh
./scripts/deploy-vercel.sh
```

### Deploy Backend Only
```bash
chmod +x scripts/deploy-railway.sh
./scripts/deploy-railway.sh
```

---

## 🔧 Prerequisites

Make sure you have:
- ✅ Node.js 18+ installed
- ✅ npm package manager
- ✅ GitHub account (for Railway)
- ✅ Vercel account (free)
- ✅ Railway account (free)

The deployment script will install CLI tools automatically.

---

## 📊 Architecture

```
┌─────────────────────┐
│   Users/Browsers    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Vercel Frontend    │  ← React + Vite
│  (Static CDN)       │     Edge caching
└──────────┬──────────┘
           │ API Calls
           ▼
┌─────────────────────┐
│  Railway Backend    │  ← Rust Firewall Engine
│  (Docker Container) │     REST API
└─────────────────────┘
```

---

## 🎨 Post-Deployment

### 1. Access Your Dashboard
```
Visit: https://firewallx-xxxx.vercel.app
```

### 2. Test API Endpoints
```bash
# Health check
curl https://your-app.railway.app/health

# Get stats
curl https://your-app.railway.app/api/stats

# Add a rule
curl -X POST https://your-app.railway.app/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block SSH",
    "action": "drop",
    "port": 22,
    "protocol": "tcp"
  }'
```

### 3. Monitor Metrics
```bash
# Prometheus metrics
curl https://your-app.railway.app:9100/metrics
```

---

## 💰 Cost Estimate

**Free Tier:**
- Vercel: $0 (100GB bandwidth)
- Railway: $0 ($5 credit)
- **Total: $0/month** for hobby projects

**Pro Tier:**
- Vercel Pro: $20/month
- Railway Paid: $5-20/month
- **Total: $25-40/month** for production use

---

## 🔍 Monitoring

### Vercel Dashboard
- Visit: https://vercel.com/dashboard
- View deployments, analytics, logs

### Railway Dashboard
- Visit: https://railway.app/dashboard
- View CPU, memory, network usage
- Real-time logs: `railway logs --follow`

---

## 🚨 Troubleshooting

### Frontend won't load
```bash
# Check build
cd firewallx-ui && npm run build

# Redeploy
vercel --prod
```

### Backend not responding
```bash
# Check logs
railway logs

# Restart service
railway restart
```

### CORS errors
```bash
# Ensure VITE_API_URL is set correctly in Vercel
vercel env ls
vercel env set VITE_API_URL https://your-app.railway.app production
```

---

## 📖 Full Documentation

- **DEPLOYMENT_GUIDE.md** - Complete step-by-step guide
- **ARCHITECTURE.md** - Technical deep dive
- **.qoder/README.md** - AI assistant features

---

## 🎉 Success Checklist

After deployment, verify:

- [ ] Frontend loads at Vercel URL
- [ ] Backend responds at Railway URL
- [ ] Can add/list rules via API
- [ ] Metrics accessible
- [ ] Logs visible in dashboards

**Congratulations! Your cloud firewall is now operational! 🚀**

---

## 💡 Pro Tips

1. **Custom Domain**: Add your domain in Railway/Vercel dashboards
2. **Environment Variables**: Use dashboard or CLI to manage secrets
3. **Auto-deploy**: Connect GitHub for automatic deployments on push
4. **Scaling**: Railway auto-scales with traffic
5. **Backups**: Regularly export configurations

---

## 🆘 Support

- **Documentation**: See DEPLOYMENT_GUIDE.md
- **Issues**: GitHub Issues
- **Community**: Discord channels

**Happy deploying! 🔥**
