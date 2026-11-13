"""Frozen research-needed hostnames, exported locally without external research."""
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from .delivery import BackupConfig, DeliveryError, preflight_backup, run_backup_worker

from .domains import registrable_domain

LEGACY_COLUMNS=('domain','hostname','cache_status','new_to_history','review_reason','review_action',
         'window_start_utc','window_end_exclusive_utc','Block')
COLUMNS=LEGACY_COLUMNS[:-1]+('RecommendedBlock','MatchedSources','SourceCheckStatus','SourcesCheckedAt','Block')


def safe_cell(value):
    text=str(value)
    if '\0' in text:
        raise ValueError('Single-line spreadsheet values required')
    if text.lstrip().startswith(('=','+','-','@')) or text.startswith(('\t','\r','\n')):
        text="'"+text
    return text


def render_csv(detail, snapshot_id, *, schema_version=3):
    if type(schema_version) is not int or schema_version not in (1, 2, 3):
        raise ValueError("Unsupported CSV schema")
    research=detail['research']; rows=research['research_needed']; totals=detail['daily_totals']
    if not isinstance(rows,list) or type(research['research_needed_count']) is not int or len(rows)!=research['research_needed_count']:
        raise ValueError('Research row count mismatch')
    start,end=totals['window_start'],totals['window_end_exclusive']
    parsed=[]
    for stamp in (start,end):
        instant=datetime.fromisoformat(stamp.replace('Z','+00:00'))
        if instant.tzinfo is None: raise ValueError('Timezone required')
        parsed.append(instant)
    if parsed[0]>=parsed[1]: raise ValueError('Invalid report window')
    if not isinstance(snapshot_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',snapshot_id):
        raise ValueError('Invalid snapshot identity')
    names=[r['hostname'] for r in rows]
    if len(set(names))!=len(names) or any(not isinstance(n,str) or not n for n in names):
        raise ValueError('Unique nonempty hostnames required')
    out=io.StringIO(newline=''); writer=csv.writer(out,lineterminator='\r\n',quoting=csv.QUOTE_ALL);writer.writerow(COLUMNS if schema_version == 3 else LEGACY_COLUMNS if schema_version == 2 else LEGACY_COLUMNS[1:])
    for row in sorted(rows,key=lambda r:r['hostname']):
        new=row['new_to_history']
        if new is not None and type(new) is not bool: raise ValueError('Invalid history flag')
        values=(row['hostname'],row['cache_status'],
            'unknown' if new is None else 'yes' if new else 'no',row['reason'],row['action'],start,end,'')
        if schema_version >= 2: values=(registrable_domain(row['hostname']),)+values
        if schema_version == 3:
            check=detail.get('source_check',{}); match=check.get('rows',{}).get(row['hostname'],{})
            values=values[:-1]+(match.get('recommended_block',''),'; '.join(match.get('matched_sources',[])),
                match.get('check_status',check.get('status','not_checked')),check.get('checked_at',''),'')
        writer.writerow([safe_cell(v) for v in values])
    data=out.getvalue().encode('utf-8-sig')
    name=f"pihole-research-needed-{parsed[1].astimezone(timezone.utc).date().isoformat()}-{snapshot_id[:16]}.csv"
    return dict(schema_version=schema_version,data=data,filename=name,sha256=hashlib.sha256(data).hexdigest(),row_count=len(rows),
                window_start_utc=start,window_end_exclusive_utc=end)


def inspect_csv(path, data):
    from .production import _reject_links
    _reject_links(path)
    try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError:return False
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_size!=len(data) or stream.read(len(data)+1)!=data:
            raise DeliveryError('csv_destination_collision',uncertain=True)
    return True


def export_csv(data, filename, config, *, export=False, runner=subprocess.run):
    if type(export) is not bool: raise ValueError('Boolean export flag required')
    if not isinstance(data,bytes) or not re.fullmatch(r'pihole-research-needed-\d{4}-\d{2}-\d{2}-[A-Za-z0-9_-]{1,16}\.csv',filename):
        raise ValueError('Invalid frozen CSV')
    result=dict(status='dry_run',exported=False,cloud_upload_confirmed=False)
    if not export:return result
    preflight_backup(config,runner=runner)
    target=Path(config.destination)/filename
    if inspect_csv(target,data):return dict(result,status='published_locally',exported=True,path=str(target),reconciled=True)
    fd,name=tempfile.mkstemp(prefix='.pihole-research-',dir=target.parent)
    temp=Path(name); published=False
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(data);stream.flush();os.fsync(stream.fileno())
        preflight_backup(config,runner=runner)
        try:os.link(temp,target);published=True
        except FileExistsError:
            if not inspect_csv(target,data):raise DeliveryError('csv_publication_uncertain',uncertain=True)
        dfd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        if not inspect_csv(target,data):raise DeliveryError('csv_publication_uncertain',uncertain=True)
        return dict(result,status='published_locally',exported=True,path=str(target),reconciled=not published)
    except DeliveryError:raise
    except Exception:raise DeliveryError('csv_publication_failed',uncertain=published) from None
    finally:
        temp.unlink(missing_ok=True)


def run_csv_worker(request, **kwargs):
    return run_backup_worker(request,_worker_module='pihole_report.research_csv',**kwargs)


def worker_main():
    import sys
    from .production import load_manifest,_private_json,_frozen_context
    try:
        scope=load_manifest()['scope'];request=json.loads(sys.stdin.read(16385))
        if set(request)!={'local_date','sha256'} or not re.fullmatch(r'[a-f0-9]{64}',request['sha256']):
            raise ValueError('Invalid request')
        day=datetime.strptime(request['local_date'],'%Y-%m-%d').date().isoformat()
        state=Path(scope['state_directory']);entry=_private_json(state/'delivery-state.json',max_bytes=16*1024*1024)['dates'][day]
        _,context=_frozen_context(entry,state,day)
        artifact=render_csv(context['detail'],entry['artifact']['snapshot_id'],
            schema_version=entry['csv'].get('schema_version',1))
        if artifact['sha256']!=request['sha256'] or entry['csv']['sha256']!=artifact['sha256']:
            raise ValueError('Frozen CSV identity changed')
        frozen=state/'artifacts'/day/'research-needed.csv'
        if not inspect_csv(frozen,artifact['data']):raise ValueError('Frozen CSV missing')
        config=BackupConfig(scope['backup_account'],Path(scope['backup_root']),Path(scope['backup_destination']),Path(scope['backup_preferences']),scope['backup_retention'])
        result=export_csv(artifact['data'],artifact['filename'],config,export=True)
        print(json.dumps(result));return 0
    except DeliveryError as error:result=dict(error_code=error.code,uncertain=error.uncertain)
    except Exception:result=dict(error_code='csv_worker_failed',uncertain=True)
    print(json.dumps(result));return 0

if __name__=='__main__':
    import sys
    if sys.argv[1:]!=['--backup-worker']:raise SystemExit('Use the production runner')
    raise SystemExit(worker_main())
