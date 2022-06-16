# Hikvision AX Pro ISAPI Integration

Wrapper for hikvision ax pro alarm kit ISAPI commands.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install hikaxpro.

```bash
pip install hikaxpro
```

## Usage

```python
from hikaxpro import HikAxPro

axpro = HikAxPro("{host}", "{username}", "{password}")

# returns 'True or False'
axpro.arm_away()

#returns 'True or False'
axpro.disarm()

# returns 'True or False'
axpro.arm_home()

axpro.disarm()
```