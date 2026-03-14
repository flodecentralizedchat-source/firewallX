# FirewallX Instructions

This document explains how to push your updated source code to GitHub and how end-users can install and run the FirewallX `.deb` package on their machines.

## 1. Pushing to GitHub

Since you have already cloned the repository from GitHub, you just need to stage all the changes we've made, commit them, and push them back up to the cloud.

Open a terminal in the `/Users/macbookpri/Downloads/firewallX` directory and run:

```bash
# 1. Stage all the files (this includes the new Dockerfiles, debian packages, and the eBPF refactor)
git add .

# 2. Commit the changes with a message describing the update
git commit -m "feat: eBPF XDP Integration & Debian Installer CLI"

# 3. Push the changes to your GitHub branch
git push origin main
```

*(Note: If you have a different default branch name like `master`, replace `main` with `master` in the last command).*

---

## 2. Installing the `.deb` Package (For Users)

If you or anyone else wants to run this blazing-fast firewall on a production Linux machine (like Ubuntu or Debian), you don't need to compile anything. You just need the `.deb` file we generated!

The installer file is located at `debian/firewallx_0.2.0-1_amd64.deb` in your repository.

Copy that file to the Linux machine and run:

```bash
# 1. Install the package using dpkg
sudo dpkg -i firewallx_0.2.0-1_amd64.deb

# 2. Run the FirewallX install command to generate the configuration directory
sudo firewallx install

# 3. Enable the systemd service so it runs on boot, and start it immediately
sudo systemctl enable --now firewallx

# 4. Check the status to ensure it attached to the eBPF hook
sudo systemctl status firewallx
```

---

## 3. Configuring the Firewall CLI

Once installed, FirewallX runs entirely via the Command Line Interface (CLI) and its persistent config file.

You can view the help menu by running:
```bash
firewallx --help
```

### Adding New Rules

You can add rules that will instantly take effect:

```bash
# Block all incoming SSH traffic
sudo firewallx rule add --name "Block SSH" --action drop --port 22 --protocol tcp --direction inbound

# Allow outgoing web traffic
sudo firewallx rule add --name "Allow HTTPS" --action allow --port 443 --protocol tcp --direction outbound
```

### Listing Active Rules

To see the rules currently loaded into the engine:

```bash
sudo firewallx rule list
```

### Manual Usage

If you don't want to use the background `systemd` service, you can start the engine in the foreground to watch the logs and packet drops in real-time:

```bash
sudo firewallx start
```
