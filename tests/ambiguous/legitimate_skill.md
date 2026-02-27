---
name: weather
description: "Get current weather via wttr.in"
metadata:
  openclaw:
    requires:
      bins: [curl]
---

# Weather Skill

Use when: user asks about weather or temperature.
NOT for: historical data or severe weather alerts.

## Usage
curl wttr.in/{location}?format=3
