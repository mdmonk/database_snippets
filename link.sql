-- name       : link.sql
-- date       : 14-Nov-2001
-- Author     : Pentest Limited
-- Description: Show database link details including the passwords
-- limitation : needs access to sys.link$
--
-- useage     : SQL> @link

set pages 50
set feed off
set verify off
set linesize 200

spool link.lis

col name head "Link Name" for a15
col host head "Host" for a15
col userid head "Username" for a30
col password head "Password" for a30

select	name,
	host,
	userid,
	password
from	sys.link$;

spool off

set pages 24
set feed on
set verify on
set lines 80
