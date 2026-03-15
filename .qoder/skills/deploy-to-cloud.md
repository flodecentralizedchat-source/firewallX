# Deploy FirewallX to Cloud Platforms

Automated deployment of FirewallX to major cloud providers (AWS, GCP, Azure) and container platforms (Railway, Vercel, Kubernetes).

## Purpose

Provide one-command deployments for FirewallX across different environments with proper security hardening, monitoring integration, and high-availability configurations.

## Deployment Targets

### 1. AWS EC2 Deployment

**Prerequisites:**
- AWS CLI configured: `aws configure`
- SSH key pair created
- VPC with public subnet

**Deployment Script:**

```bash
#!/bin/bash
# deploy-aws.sh

INSTANCE_TYPE="c6i.xlarge"  # 4 vCPU, optimized for networking
AMI_ID="ami-0c55b159cbfafe1f0"  # Ubuntu 22.04 LTS
KEY_NAME="firewallx-key"
SECURITY_GROUP_ID="sg-xxxxxxx"

# Launch instance
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type $INSTANCE_TYPE \
  --key-name $KEY_NAME \
  --security-group-ids $SECURITY_GROUP_ID \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=50,VolumeType=gp3}" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=FirewallX}]" \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "Launched instance: $INSTANCE_ID"

# Wait for instance to be running
aws ec2 wait instance-running --instance-ids $INSTANCE_ID

# Get public IP
PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

echo "Public IP: $PUBLIC_IP"

# Install FirewallX via SSH
ssh -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP << 'EOF'
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y curl wget iptables

# Download latest .deb package
wget https://github.com/yourusername/firewallx/releases/latest/download/firewallx_0.2.0-1_amd64.deb

# Install package
sudo dpkg -i firewallx_*.deb

# Configure default deny policy
sudo firewallx rule add --name "Default deny inbound" --action drop --protocol any --direction inbound
sudo firewallx rule add --name "Allow established" --action allow --protocol tcp --direction inbound --state established

# Allow SSH (critical!)
sudo firewallx rule add --name "Allow SSH" --action allow --port 22 --protocol tcp --direction inbound

# Enable eBPF (requires kernel 5.10+)
sudo modprobe bpf

# Start service
sudo systemctl enable firewallx
sudo systemctl start firewallx

# Verify status
sudo systemctl status firewallx --no-pager
EOF

echo "✅ FirewallX deployed to $PUBLIC_IP"
echo "SSH: ssh -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP"
echo "Monitor: ssh -i ~/.ssh/${KEY_NAME}.pem ubuntu@$PUBLIC_IP 'sudo firewallx logs --live'"
```

### 2. Google Cloud Platform (GCP)

**Deployment via Terraform:**

```hcl
# main.tf
provider "google" {
  project = "your-project-id"
  region  = "us-central1"
}

resource "google_compute_instance" "firewallx" {
  name         = "firewallx-primary"
  machine_type = "c2-standard-4"  # Compute-optimized
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 50
    }
  }

  network_interface {
    network = "default"
    access_config {}  # Ephemeral public IP
  }

  metadata_startup_script = <<-EOT
    #!/bin/bash
    set -e
    
    # Install FirewallX
    wget -q https://github.com/yourusername/firewallx/releases/latest/download/firewallx_0.2.0-1_amd64.deb
    dpkg -i firewallx_*.deb
    
    # Configure for GCP
    firewallx rule add --name "Allow GCP health checks" --action allow --src_ip "35.191.0.0/16" --protocol tcp --direction inbound
    firewallx rule add --name "Default deny" --action drop --protocol any --direction inbound
    
    systemctl enable firewallx
    systemctl start firewallx
  EOT

  tags = ["firewall", "security"]

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh-to-firewallx"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]  # Restrict to your IP in production!
  target_tags   = ["firewall"]
}

output "public_ip" {
  value = google_compute_instance.firewallx.network_interface[0].access_config[0].nat_ip
}
```

**Deploy:**
```bash
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

### 3. Microsoft Azure

**ARM Template Deployment:**

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Compute/virtualMachines",
      "apiVersion": "2021-07-01",
      "name": "firewallx-vm",
      "location": "[resourceGroup().location]",
      "properties": {
        "hardwareProfile": {
          "vmSize": "Standard_F4s_v2"
        },
        "osProfile": {
          "computerName": "firewallx",
          "adminUsername": "azureuser",
          "linuxConfiguration": {
            "disablePasswordAuthentication": true,
            "ssh": {
              "publicKeys": [
                {
                  "path": "/home/azureuser/.ssh/authorized_keys",
                  "keyData": "<YOUR_SSH_PUBLIC_KEY>"
                }
              ]
            }
          }
        },
        "storageProfile": {
          "imageReference": {
            "publisher": "Canonical",
            "offer": "UbuntuServer",
            "sku": "22_04-lts",
            "version": "latest"
          }
        },
        "networkProfile": {
          "networkInterfaces": [
            {
              "id": "[resourceId('Microsoft.Network/networkInterfaces', 'firewallx-nic')]"
            }
          ]
        }
      }
    }
  ]
}
```

### 4. Railway.app Deployment

**railway.toml Configuration:**

```toml
# railway.toml (already exists, enhanced version)
[build]
builder = "NIXPACKS"

[deploy]
startCommand = "cargo run --release -- start"
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 3

[service]
name = "FirewallX Engine"
description = "Stateful firewall with eBPF acceleration"

[service.variables]
RUST_LOG = "info"
PROMETHEUS_ENABLED = "true"
PROMETHEUS_PORT = "9100"
AI_AGENT_ENABLED = "false"  # Enable manually if needed

[[services]]
name = "FirewallX API"
port = 3000
healthcheckPath = "/health"
healthcheckTimeout = 30

[[services.domains]]
name = "firewallx.railway.app"
```

**Deployment Steps:**

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Deploy
railway up

# View logs
railway logs

# Open dashboard
railway open
```

### 5. Vercel Deployment (API-only Mode)

**vercel.json Configuration:**

```json
{
  "version": 2,
  "name": "firewallx-api",
  "builds": [
    {
      "src": "Cargo.toml",
      "use": "@vercel/static-build",
      "config": {
        "dist": ".vercel/output"
      }
    }
  ],
  "env": {
    "RUST_VERSION": "1.75.0",
    "DEPLOY_TARGET": "vercel"
  },
  "functions": {
    "api/*.rs": {
      "memory": 1024,
      "maxDuration": 30
    }
  },
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "/api/$1"
    }
  ]
}
```

**Note:** Vercel serverless functions have limitations for long-running processes like firewall engines. Use Railway or traditional VMs for full functionality.

### 6. Kubernetes Deployment

**Helm Chart Values:**

```yaml
# values.yaml
replicaCount: 2  # High availability

image:
  repository: ghcr.io/yourusername/firewallx
  tag: "0.2.0"
  pullPolicy: IfNotPresent

# Privileged mode required for eBPF
privileged: true

# Host network for packet inspection
hostNetwork: true

# Resource limits
resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 512Mi

# Persistent storage for blocklist
persistence:
  enabled: true
  size: 10Gi
  storageClass: "standard"

# Prometheus integration
prometheus:
  enabled: true
  port: 9100
  scrapeInterval: 15s

# SIEM integration
siem:
  enabled: false
  url: ""
  apiKeySecret: "siem-api-key"

# Default rules
defaultRules:
  - name: "Allow established connections"
    action: allow
    protocol: tcp
    direction: inbound
    state: established
    
  - name: "Default deny all inbound"
    action: drop
    protocol: any
    direction: inbound

# Node selector for bare-metal nodes
nodeSelector:
  kubernetes.io/os: linux
  node-type: security-appliance

# Tolerations for control-plane nodes
tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
```

**Kubernetes Manifest:**

```yaml
# firewallx-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: firewallx
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: firewallx
  template:
    metadata:
      labels:
        app: firewallx
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: firewallx
        image: ghcr.io/yourusername/firewallx:0.2.0
        securityContext:
          privileged: true
          capabilities:
            add:
            - SYS_ADMIN
            - NET_ADMIN
            - BPF
        volumeMounts:
        - name: config
          mountPath: /etc/firewallx
        - name: logs
          mountPath: /var/log/firewallx
        env:
        - name: RUST_LOG
          value: "info"
        - name: EBPF_ENABLED
          value: "true"
      volumes:
      - name: config
        configMap:
          name: firewallx-config
      - name: logs
        hostPath:
          path: /var/log/firewallx
          type: DirectoryOrCreate
```

**Deploy to Kubernetes:**

```bash
# Add Helm repo
helm repo add firewallx https://yourusername.github.io/firewallx-helm

# Install
helm install firewallx firewallx/firewallx \
  --namespace kube-system \
  -f values.yaml

# Check status
kubectl get pods -n kube-system -l app=firewallx

# View logs
kubectl logs -n kube-system -l app=firewallx --tail=50
```

## Post-Deployment Verification

After deploying to any platform:

```bash
# 1. Check service health
systemctl status firewallx

# 2. Verify eBPF attachment (Linux only)
sudo bpftool prog list | grep firewallx

# 3. Test basic connectivity
ping -c 3 <protected-host>

# 4. Check active rules
sudo firewallx rule list

# 5. Monitor live traffic
sudo firewallx logs --live

# 6. Export metrics endpoint
curl http://localhost:9100/metrics

# 7. Test IDS detection (optional - trigger alert)
nmap -sS localhost  # Should trigger port scan detection
```

## Rollback Procedures

If deployment fails:

```bash
# Stop current version
sudo systemctl stop firewallx

# Rollback to previous .deb version
sudo dpkg -i firewallx_0.1.9-1_amd64.deb

# Restore previous config
sudo cp /etc/firewallx/config.toml.backup /etc/firewallx/config.toml

# Restart
sudo systemctl start firewallx

# Verify
sudo systemctl status firewallx
```
