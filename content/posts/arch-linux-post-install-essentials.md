---
title: "Arch Linux Post-Install Essentials - My Must-Have Setup"
date: 2024-07-31T14:00:00Z
draft: false
tags: ["arch-linux", "linux", "setup", "tutorial"]
series: "Arch Linux Guide"
description: "Essential packages and configurations I install on every fresh Arch Linux system"
---

# Arch Linux Post-Install Essentials

Just finished a fresh Arch install? Here's my go-to list of essential packages and configurations that transform a minimal Arch system into a productive development environment.

## System Updates & AUR Helper

First things first - update the system and get an AUR helper:

```bash
# Update system
sudo pacman -Syu

# Install base development tools
sudo pacman -S base-devel git

# Install yay (AUR helper)
git clone https://aur.archlinux.org/yay.git
cd yay
makepkg -si
cd .. && rm -rf yay