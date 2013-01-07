-- name       : layout.sql
-- date       : 23-Jul-2001
-- Author     : Pentest Limited
-- Description: Prints out details of the key database file locations.
-- limitation : need to have access to v$controlfile,v$log,v$logfile,
--              dba_data_files,dba_tablespaces,v$rollname,v$rollstat
--              and dba_rollback_segs
--
-- useage     : SQL> @layout

clear cols
set headoff feedback off pagesize 80 linesize 80
col filen    head "Filename"          for a45
col grp      head "Group"             for 99
col sizn     head "Size (K)"          for 999990
col tblsp    head "Tablespace"        for a18
col minextst head "Min|ext"           for 999
col maxxt    head "Max|ext"           for 99990
col pinc     head "Pct|Inc"           for 99990
col rseg     head 'Rollback|Segment'  for a10  trunc
col ts       head 'Tablespace|'       for a10
col inxtt    head 'Init|(K)'          for 9999999
col nxt      head 'Next|(K)'          for 9999999
col exts     head 'ext|(#)'           for 99990
col sz       head 'Size|(K)'          for 999999
col bk                               for 999
col typ      head 'type|'             for a7
col megb     head 'Size (MB)'         for 9999
--
-- spool file
--
spool db.lis


prompt	Control Files

select 	name 
from 	v$controlfile;
set head on


prompt	Redo Log Files

select 	a.group# grp, 
	b.member filen, 
	a.bytes/1024 sizn
from 	v$log a, v$logfile b
where 	a.group# = b.group#;


prompt	Data Files

select 	tablespace_name tblsp, 
	file_name filen, 
	bytes/1048576 megb
from 	sys.dba_data_files
order by tablespace_name;


prompt	Tablespace Storage

select 	tablespace_name tblsp, 
	initial_extent/1024 inxtt, 
	next_extent/1024 nxt,
  	min_extents minextst, 
	max_extents maxxt, 
	pct_increase pinc
from 	sys.dba_tablespaces
order by tablespace_name;

select 	n.name rseg, 
	r.tablespace_name ts,
  	decode(r.owner,'SYS','PRIVATE',r.owner) typ,
  	r.initial_extent/1024 inxtt, 
	r.next_extent/1024 nxt, 
	r.min_extents minextst,
  	r. max_extents maxxt, 
	s.extents exts, 
	s.rssize/1024 sz
from 	v$rollname n, 
	v$rollstat s, 
	sys.dba_rollback_segs r
where 	n.usn = s.usn 
and	s.usn = r.segment_id;

set head off

select 	segment_name rseg, 
	tablespace_name ts,
  	decode(owner,'SYS','PRIVATE',owner) typ,
  	initial_extent/1024 inxtt, 
	next_extent/1024 nxt, 
	min_extents minextst,
  	max_extents maxxt, 
	0 bk, 
	status
from 	sys.dba_rollback_segs
where 	status != 'ONLINE';

spool off
