"""All file locations. Override with environment variables."""
import os
RB = os.environ.get('RB_ROOT', os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/')    # this release folder
DATA = os.environ.get('RB_DATA', RB + 'data/')     # attack_stix/enterprise-attack.json, tie/, cisa_laptop/, fulltext_manifest.csv
TEXTS = os.environ.get('RB_TEXTS', RB + 'texts')   # extracted report texts (not redistributed)
