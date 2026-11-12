"""Explicit local configuration. Importing this module performs no filesystem I/O.

Copy the disabled example to config/deployment.json, edit every destination,
chmod 600, and enable it deliberately. Never commit that private configuration.
A separate production.json must still bind the approved scope to source hashes.
"""
from pathlib import Path
import ipaddress
import urllib.parse
from .cli import PROJECT

DEPLOYMENT = PROJECT / 'config/deployment.json'


def example_deployment(project=None):
    project = Path(project or PROJECT).absolute()
    root = project / 'runtime'
    scope = dict(root=str(root), database=str(root/'data/pihole-history/history.sqlite'),
        report=str(root/'memory/pihole-domain-review.md'), site='Primary',
        pihole_base='https://pihole.example.invalid', pihole_ip='192.0.2.53',
        pihole_tls_name='pihole.example.invalid', pihole_ca=str(root/'config/pihole-ca.pem'),
        pihole_password_file=str(root/'secrets/pihole-password'),
        smtp_host='smtp.example.invalid', smtp_port=587, smtp_sender='sender@example.invalid',
        smtp_recipient='recipient@example.invalid', smtp_password_file=str(root/'secrets/smtp-password'),
        backup_account='owner@example.invalid', backup_root=str(root/'OneDrive'),
        backup_destination=str(root/'OneDrive/Pi-hole Backups/Primary'),
        backup_preferences=str(root/'config/onedrive-preferences.plist'), backup_retention=14,
        research_mode='cache-only', unifi_mode='cached-only', legacy_stdout=str(root/'logs/legacy.log'),
        state_directory=str(project/'state/production'))
    scheduler=dict(project=str(project),manifest=str(project/'config/production.json'),
        database=scope['database'],wrapper=str(root/'bin/run-daily-review'),
        plist=str(root/'config/org.example.pihole-domain-review.plist'),python='/usr/local/bin/python3')
    return dict(schema='pihole-deployment.v1',enabled=False,scope=scope,scheduler=scheduler)


def load_deployment():
    from .production import _private_json, _reject_links
    value = _private_json(DEPLOYMENT)
    template = example_deployment()
    if (not isinstance(value,dict) or set(value)!=set(template)
            or value['schema']!='pihole-deployment.v1' or value['enabled'] is not True
            or not isinstance(value['scope'],dict) or set(value['scope'])!=set(template['scope'])
            or not isinstance(value['scheduler'],dict) or set(value['scheduler'])!=set(template['scheduler'])):
        raise ValueError('Explicit enabled local deployment configuration required')
    scope, schedule = value['scope'], value['scheduler']
    for key, item in scope.items():
        if key in ('smtp_port','backup_retention'):
            if type(item) is not int or item <= 0: raise ValueError('Positive integer required')
        elif not isinstance(item,str) or not item or any(c in item for c in '\r\n\0'):
            raise ValueError('Nonempty single-line configuration required')
    paths=('root','database','report','pihole_ca','pihole_password_file','smtp_password_file',
           'backup_root','backup_destination','backup_preferences','legacy_stdout','state_directory')
    for item in [scope[k] for k in paths]+list(schedule.values()):
        if not isinstance(item,str) or not Path(item).is_absolute() or '..' in Path(item).parts:
            raise ValueError('Absolute canonical deployment paths required')
        # Interpreter symlinks are common and are fingerprinted by migration.
        if item != schedule['python']: _reject_links(Path(item))
    project=Path(schedule['project'])
    if (schedule['manifest']!=str(project/'config/production.json')
            or schedule['database']!=scope['database']
            or scope['state_directory']!=str(project/'state/production')
            or scope['research_mode']!='cache-only' or scope['unifi_mode']!='cached-only'):
        raise ValueError('Deployment scope is inconsistent')
    parsed=urllib.parse.urlsplit(scope['pihole_base'])
    if (parsed.scheme!='https' or parsed.hostname!=scope['pihole_tls_name']
            or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment):
        raise ValueError('Verified HTTPS Pi-hole endpoint required')
    ipaddress.ip_address(scope['pihole_ip'])
    if scope['smtp_port'] > 65535 or parsed.port not in (None,443):
        raise ValueError('Unsupported endpoint port')
    for field in ('smtp_sender','smtp_recipient','backup_account'):
        if scope[field].count('@') != 1 or any(c.isspace() for c in scope[field]):
            raise ValueError('Explicit account email address required')
    if not Path(scope['backup_destination']).is_relative_to(Path(scope['backup_root'])):
        raise ValueError('Backup destination must be inside its declared root')
    if project != PROJECT:
        raise ValueError('Deployment must match this installed project')
    return value
