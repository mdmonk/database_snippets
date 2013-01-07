-- name       : hidden.sql
-- date       : 14-Nov-2001
-- Author     : Pentest Limited
-- Description: This script shows all of the hidden initialisation
--              parameters.
-- limitation : needs access to x$ksppi
--
-- useage     : SQL> @hidden

set pages 50
set feed off
set verify off
set linesize 80

spool hidden.lis

col name head "Name" for a40
col descr head "Description" for a35

select	ksppinm  name,
	ksppdesc  descr
from	sys.x$ksppi
where	inst_id = userenv('Instance') 
and	translate(ksppinm,'_','#') like '#%'
order by ksppinm;

spool off

set pages 24
set feed on
set verify on
set lines 80
