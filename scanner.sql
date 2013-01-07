-- ----------------------------------------------------------------------------
--                                                                           --
--                               PENTEST LIMITED                             --
--                               ---------------                             --
--                                                                           --
--   File Name  : %M%.%R%                                                    --
--   Author     : Pentest Limited                                            --
--   Date       : November 2001                                              --
--                                                                           --
--   Description                                                             --
--   -----------                                                             --
--                                                                           --
--   Simple Oracle scanner to review some basic aspects of an Oracle         --
--   installation.                                                           --
--                                                                           --
--   Version History                                                         --
--   ===============                                                         --
--                                                                           --
--   Who	Ver	Date		Description                          --
--   -------	-----	--------	------------------------------       --
--   PF		1.0	Dec 2001	First Issue                          --

-- ----------------------------------------------------------------------------
-- set up SQL*PLUS
-- ----------------------------------------------------------------------------

whenever sqlerror exit rollback

set head on
set feed on
set linesize 80
set termout on
set serveroutput on size 1000000

-- ----------------------------------------------------------------------------
-- capture the output
-- ----------------------------------------------------------------------------
spool scanner.lis

-- ----------------------------------------------------------------------------
-- create an anonymouse block to scan with
-- ----------------------------------------------------------------------------

declare
	type user_tab is table of varchar2(30) index by binary_integer;
	type pwd_tab is table of varchar2(30) index by binary_integer;
	type hash_tab is table of varchar2(16) index by binary_integer;
	
	username user_tab;
	password pwd_tab;
	hash hash_tab;
	
	tab_key binary_integer:=1;
	i binary_integer:=1;
	--
	cursor  c_user is
	select 	username,
		password
	from	dba_users;
	--
	cursor  c_utl_cur is
	select	rtrim(name) name,
		rtrim(value) value
	from	v$parameter
	where	name='utl_file_dir';
	--
	cursor  c_trace is
	select	rtrim(name) name,
		decode(rtrim(value),NULL,'NULL',rtrim(value)) value
	from	v$parameter
	where	name like '%dest%';
	--
	cursor  c_utl_trace is
	select 	rtrim(a.name) name
	from	v$parameter a,
		v$parameter b
	where	a.name='utl_file_dir'
	and	b.name like '%dest%'
	and	a.value=b.value;
	--
	cursor 	c_sys_priv  (cp_priv in dba_sys_privs.privilege%type) is
	select	grantee,
		privilege
	from	dba_sys_privs
	where	privilege like cp_priv;
	--
	cursor 	c_admin is
	select	grantee,
		privilege priv
	from	dba_sys_privs
	where	admin_option='YES'
	union
	select	grantee,
		granted_role priv
	from	dba_role_privs
	where	admin_option='YES';
	--
	cursor	c_grant is
	select	grantee,
		privilege,
		table_name
	from	dba_tab_privs
	where	grantable='YES'
	union
	select	grantee,
		privilege,
		table_name
	from	dba_col_privs
	where	grantable='YES';
	--
	cursor	c_ext is
	select	username
	from	dba_users
	where	password='EXTERNAL';
	--
	cursor	c_dba is
	select	grantee
	from	dba_role_privs
	where	granted_role='DBA';
	--
	cursor	c_links is
	select	name,
		host,
		userid,
		password,
		authusr,
		authpwd
	from	sys.link$
	where	password is not null;
	--
	lv_sys_priv c_sys_priv%rowtype;
	lv_utl_cur c_utl_cur%rowtype;
	lv_trace c_trace%rowtype;
	lv_utl_trace c_utl_trace%rowtype;
	--
	found 	number:=0;
	--
begin
	-- --------------------------------------------------------------------
	-- manually load the user list into the tables
	-- --------------------------------------------------------------------
	
	tab_key:=1;                                                                                         
	username(tab_key):='ADAMS';                                                                         
	password(tab_key):='WOOD';                                                                          
	hash(tab_key):='72CDEF4A3483F60D';                                                                  
	--                                                                                                  
	tab_key:=2;                                                                                         
	username(tab_key):='ADLDEMO';                                                                       
	password(tab_key):='ADLDEMO';                                                                       
	hash(tab_key):='147215F51929A6E8';                                                                  
	--                                                                                                  
	tab_key:=3;                                                                                         
	username(tab_key):='APPLSYS';                                                                       
	password(tab_key):='FND';                                                                           
	hash(tab_key):='0F886772980B8C79';                                                                  
	--                                                                                                  
	tab_key:=4;                                                                                         
	username(tab_key):='APPLYSYSPUB';                                                                   
	password(tab_key):='PUB';                                                                           
	hash(tab_key):='A5E09E84EC486FC9';                                                                  
	--                                                                                                  
	tab_key:=5;                                                                                         
	username(tab_key):='APPS';                                                                          
	password(tab_key):='APPS';                                                                          
	hash(tab_key):='D728438E8A5925E0';                                                                  
	--                                                                                                  
	tab_key:=6;                                                                                         
	username(tab_key):='AQDEMO';                                                                        
	password(tab_key):='AQDEMO';                                                                        
	hash(tab_key):='5140E342712061DD';                                                                  
	--                                                                                                  
	tab_key:=7;                                                                                         
	username(tab_key):='AQJAVA';                                                                        
	password(tab_key):='AQJAVA';                                                                        
	hash(tab_key):='8765D2543274B42E';                                                                  
	--                                                                                                  
	tab_key:=8;                                                                                         
	username(tab_key):='AQUSER';                                                                        
	password(tab_key):='AQUSER';                                                                        
	hash(tab_key):='4CF13BDAC1D7511C';                                                                  
	--                                                                                                  
	tab_key:=9;                                                                                         
	username(tab_key):='AUDIOUSER';                                                                     
	password(tab_key):='AUDIOUSER';                                                                     
	hash(tab_key):='CB4F2CEC5A352488';                                                                  
	--                                                                                                  
	tab_key:=10;                                                                                        
	username(tab_key):='AURORA$ORB$UNAUTHENTICATED';                                                    
	password(tab_key):='INVALID';                                                                       
	hash(tab_key):='80C099F0EADF877E';                                                                  
	--                                                                                                  
	tab_key:=11;                                                                                        
	username(tab_key):='BLAKE';                                                                         
	password(tab_key):='PAPER';                                                                         
	hash(tab_key):='9435F2E60569158E';                                                                  
	--                                                                                                  
	tab_key:=12;                                                                                        
	username(tab_key):='CATALOG';                                                                       
	password(tab_key):='CATALOG';                                                                       
	hash(tab_key):='397129246919E8DA';                                                                  
	--                                                                                                  
	tab_key:=13;                                                                                        
	username(tab_key):='CDEMO82';                                                                       
	password(tab_key):='CDEMO83';                                                                       
	hash(tab_key):='7299A5E2A5A05820';                                                                  
	--                                                                                                  
	tab_key:=14;                                                                                        
	username(tab_key):='CDEMOCOR';                                                                      
	password(tab_key):='CDEMOCOR';                                                                      
	hash(tab_key):='3A34F0B26B951F3F';                                                                  
	--                                                                                                  
	tab_key:=15;                                                                                        
	username(tab_key):='CDEMOUCB';                                                                      
	password(tab_key):='CDEMOUCB';                                                                      
	hash(tab_key):='CEAE780F25D556F8';                                                                  
	--                                                                                                  
	tab_key:=16;                                                                                        
	username(tab_key):='CDEMORID';                                                                      
	password(tab_key):='CDEMORID';                                                                      
	hash(tab_key):='E39CEFE64B73B308';                                                                  
	--                                                                                                  
	tab_key:=17;                                                                                        
	username(tab_key):='CENTRA';                                                                        
	password(tab_key):='CENTRA';                                                                        
	hash(tab_key):='63BF5FFE5E3EA16D';                                                                  
	--                                                                                                  
	tab_key:=18;                                                                                        
	username(tab_key):='CLARK';                                                                         
	password(tab_key):='CLOTH';                                                                         
	hash(tab_key):='7AAFE7D01511D73F';                                                                  
	--                                                                                                  
	tab_key:=19;                                                                                        
	username(tab_key):='COMPANY';                                                                       
	password(tab_key):='COMPANY';                                                                       
	hash(tab_key):='402B659C15EAF6CB';                                                                  
	--                                                                                                  
	tab_key:=20;                                                                                        
	username(tab_key):='CSMIG';                                                                         
	password(tab_key):='CSMIG';                                                                         
	hash(tab_key):='09B4BB013FBD0D65';                                                                  
	--                                                                                                  
	tab_key:=21;                                                                                        
	username(tab_key):='CTXDEMO';                                                                       
	password(tab_key):='CTXDEMO';                                                                       
	hash(tab_key):='CB6B5E9D9672FE89';                                                                  
	--                                                                                                  
	tab_key:=22;                                                                                        
	username(tab_key):='CTXSYS';                                                                        
	password(tab_key):='CTXSYS';                                                                        
	hash(tab_key):='24ABAB8B06281B4C';                                                                  
	--                                                                                                  
	tab_key:=23;                                                                                        
	username(tab_key):='DBSNMP';                                                                        
	password(tab_key):='DBSNMP';                                                                        
	hash(tab_key):='E066D214D5421CCC';                                                                  
	--                                                                                                  
	tab_key:=24;                                                                                        
	username(tab_key):='DEMO';                                                                          
	password(tab_key):='DEMO';                                                                          
	hash(tab_key):='4646116A123897CF';                                                                  
	--                                                                                                  
	tab_key:=25;                                                                                        
	username(tab_key):='DEMO8';                                                                         
	password(tab_key):='DEMO9';                                                                         
	hash(tab_key):='0E7260738FDFD678';                                                                  
	--                                                                                                  
	tab_key:=26;                                                                                        
	username(tab_key):='EMP';                                                                           
	password(tab_key):='EMP';                                                                           
	hash(tab_key):='B40C23C6E2B4EA3D';                                                                  
	--                                                                                                  
	tab_key:=27;                                                                                        
	username(tab_key):='EVENT';                                                                         
	password(tab_key):='EVENT';                                                                         
	hash(tab_key):='7CA0A42DA768F96D';                                                                  
	--                                                                                                  
	tab_key:=28;                                                                                        
	username(tab_key):='FINANCE';                                                                       
	password(tab_key):='FINANCE';                                                                       
	hash(tab_key):='6CBBF17292A1B9AA';                                                                  
	--                                                                                                  
	tab_key:=29;                                                                                        
	username(tab_key):='FND';                                                                           
	password(tab_key):='FND';                                                                           
	hash(tab_key):='0C0832F8B6897321';                                                                  
	--                                                                                                  
	tab_key:=30;                                                                                        
	username(tab_key):='GPFD';                                                                          
	password(tab_key):='GPFD';                                                                          
	hash(tab_key):='BA787E988F8BC424';                                                                  
	--                                                                                                  
	tab_key:=31;                                                                                        
	username(tab_key):='GPLD';                                                                          
	password(tab_key):='GPLD';                                                                          
	hash(tab_key):='9D561E4D6585824B';                                                                  
	--                                                                                                  
	tab_key:=32;                                                                                        
	username(tab_key):='HR';                                                                            
	password(tab_key):='HR';                                                                            
	hash(tab_key):='4C6D73C3E8B0F0DA';                                                                  
	--                                                                                                  
	tab_key:=33;                                                                                        
	username(tab_key):='HLW';                                                                           
	password(tab_key):='HLW';                                                                           
	hash(tab_key):='855296220C095810';                                                                  
	--                                                                                                  
	tab_key:=34;                                                                                        
	username(tab_key):='IMAGEUSER';                                                                     
	password(tab_key):='IMAGEUSER';                                                                     
	hash(tab_key):='E079BF5E433F0B89';                                                                  
	--                                                                                                  
	tab_key:=35;                                                                                        
	username(tab_key):='IMEDIA';                                                                        
	password(tab_key):='IMEDIA';                                                                        
	hash(tab_key):='8FB1DC9A6F8CE827';                                                                  
	--                                                                                                  
	tab_key:=36;                                                                                        
	username(tab_key):='JONES';                                                                         
	password(tab_key):='STEEL';                                                                         
	hash(tab_key):='B9E99443032F059D';                                                                  
	--                                                                                                  
	tab_key:=37;                                                                                        
	username(tab_key):='JMUSER';                                                                        
	password(tab_key):='JMUSER';                                                                        
	hash(tab_key):='063BA85BF749DF8E';                                                                  
	--                                                                                                  
	tab_key:=38;                                                                                        
	username(tab_key):='LBACSYS';                                                                       
	password(tab_key):='LBACSYS';                                                                       
	hash(tab_key):='AC9700FD3F1410EB';                                                                  
	--                                                                                                  
	tab_key:=39;                                                                                        
	username(tab_key):='MDSYS';                                                                         
	password(tab_key):='MDSYS';                                                                         
	hash(tab_key):='9AAEB2214DCC9A31';                                                                  
	--                                                                                                  
	tab_key:=40;                                                                                        
	username(tab_key):='MFG';                                                                           
	password(tab_key):='MFG';                                                                           
	hash(tab_key):='FC1B0DD35E790847';                                                                  
	--                                                                                                  
	tab_key:=41;                                                                                        
	username(tab_key):='MIGRATE';                                                                       
	password(tab_key):='MIGRATE';                                                                       
	hash(tab_key):='5A88CE52084E9700';                                                                  
	--                                                                                                  
	tab_key:=42;                                                                                        
	username(tab_key):='MILLER';                                                                        
	password(tab_key):='MILLER';                                                                        
	hash(tab_key):='D0EFCD03C95DF106';                                                                  
	--                                                                                                  
	tab_key:=43;                                                                                        
	username(tab_key):='MMO2';                                                                          
	password(tab_key):='MMO3';                                                                          
	hash(tab_key):='AE128772645F6709';                                                                  
	--                                                                                                  
	tab_key:=44;                                                                                        
	username(tab_key):='MODTEST';                                                                       
	password(tab_key):='YES';                                                                           
	hash(tab_key):='BBFF58334CDEF86D';                                                                  
	--                                                                                                  
	tab_key:=45;                                                                                        
	username(tab_key):='MOREAU';                                                                        
	password(tab_key):='MOREAU';                                                                        
	hash(tab_key):='CF5A081E7585936B';                                                                  
	--                                                                                                  
	tab_key:=46;                                                                                        
	username(tab_key):='NAMES';                                                                         
	password(tab_key):='NAMES';                                                                         
	hash(tab_key):='9B95D28A979CC5C4';                                                                  
	--                                                                                                  
	tab_key:=47;                                                                                        
	username(tab_key):='MTSSYS';                                                                        
	password(tab_key):='MTSSYS';                                                                        
	hash(tab_key):='6465913FF5FF1831';                                                                  
	--                                                                                                  
	tab_key:=48;                                                                                        
	username(tab_key):='MXAGENT';                                                                       
	password(tab_key):='MXAGENT';                                                                       
	hash(tab_key):='C5F0512A64EB0E7F';                                                                  
	--                                                                                                  
	tab_key:=49;                                                                                        
	username(tab_key):='OCITEST';                                                                       
	password(tab_key):='OCITEST';                                                                       
	hash(tab_key):='C09011CB0205B347';                                                                  
	--                                                                                                  
	tab_key:=50;                                                                                        
	username(tab_key):='ODS';                                                                           
	password(tab_key):='ODS';                                                                           
	hash(tab_key):='89804494ADFC71BC';                                                                  
	--                                                                                                  
	tab_key:=51;                                                                                        
	username(tab_key):='ODSCOMMON';                                                                     
	password(tab_key):='ODSCOMMON';                                                                     
	hash(tab_key):='59BBED977430C1A8';                                                                  
	--                                                                                                  
	tab_key:=52;                                                                                        
	username(tab_key):='OE';                                                                            
	password(tab_key):='OE';                                                                            
	hash(tab_key):='D1A2DFC623FDA40A';                                                                  
	--                                                                                                  
	tab_key:=53;                                                                                        
	username(tab_key):='OEMADM';                                                                        
	password(tab_key):='OEMADM';                                                                        
	hash(tab_key):='9DCE98CCF541AAE6';                                                                  
	--                                                                                                  
	tab_key:=54;                                                                                        
	username(tab_key):='OLAPDBA';                                                                       
	password(tab_key):='OLAPDBA';                                                                       
	hash(tab_key):='1AF71599EDACFB00';                                                                  
	--                                                                                                  
	tab_key:=55;                                                                                        
	username(tab_key):='OLAPSVR';                                                                       
	password(tab_key):='INSTANCE';                                                                      
	hash(tab_key):='AF52CFD036E8F425';                                                                  
	--                                                                                                  
	tab_key:=56;                                                                                        
	username(tab_key):='OLAPSYS';                                                                       
	password(tab_key):='MANAGER';                                                                       
	hash(tab_key):='3FB8EF9DB538647C';                                                                  
	--                                                                                                  
	tab_key:=57;                                                                                        
	username(tab_key):='ORAREGSYS';                                                                     
	password(tab_key):='ORAREGSYS';                                                                     
	hash(tab_key):='28D778112C63CB15';                                                                  
	--                                                                                                  
	tab_key:=58;                                                                                        
	username(tab_key):='ORDPLUGINS';                                                                    
	password(tab_key):='ORDPLUGINS';                                                                    
	hash(tab_key):='88A2B2C183431F00';                                                                  
	--                                                                                                  
	tab_key:=59;                                                                                        
	username(tab_key):='ORDSYS';                                                                        
	password(tab_key):='ORDSYS';                                                                        
	hash(tab_key):='7EFA02EC7EA6B86F';                                                                  
	--                                                                                                  
	tab_key:=60;                                                                                        
	username(tab_key):='OUTLN';                                                                         
	password(tab_key):='OUTLN';                                                                         
	hash(tab_key):='4A3BA55E08595C81';                                                                  
	--                                                                                                  
	tab_key:=61;                                                                                        
	username(tab_key):='PERFSTAT';                                                                      
	password(tab_key):='PERFSTAT';                                                                      
	hash(tab_key):='AC98877DE1297365';                                                                  
	--                                                                                                  
	tab_key:=62;                                                                                        
	username(tab_key):='PM';                                                                            
	password(tab_key):='PM';                                                                            
	hash(tab_key):='C7A235E6D2AF6018';                                                                  
	--                                                                                                  
	tab_key:=63;                                                                                        
	username(tab_key):='PO';                                                                            
	password(tab_key):='PO';                                                                            
	hash(tab_key):='355CBEC355C10FEF';                                                                  
	--                                                                                                  
	tab_key:=64;                                                                                        
	username(tab_key):='PO8';                                                                           
	password(tab_key):='PO8';                                                                           
	hash(tab_key):='7E15FBACA7CDEBEC';                                                                  
	--                                                                                                  
	tab_key:=65;                                                                                        
	username(tab_key):='PO7';                                                                           
	password(tab_key):='PO7';                                                                           
	hash(tab_key):='6B870AF28F711204';                                                                  
	--                                                                                                  
	tab_key:=66;                                                                                        
	username(tab_key):='PORTAL30';                                                                      
	password(tab_key):='PORTAL31';                                                                      
	hash(tab_key):='D373ABE86992BE68';                                                                  
	--                                                                                                  
	tab_key:=67;                                                                                        
	username(tab_key):='PORTAL30_DEMO';                                                                 
	password(tab_key):='PORTAL30_DEMO';                                                                 
	hash(tab_key):='CFD1302A7F832068';                                                                  
	--                                                                                                  
	tab_key:=68;                                                                                        
	username(tab_key):='PORTAL30_PUBLIC';                                                               
	password(tab_key):='PORTAL30_PUBLIC';                                                               
	hash(tab_key):='42068201613CA6E2';                                                                  
	--                                                                                                  
	tab_key:=69;                                                                                        
	username(tab_key):='PORTAL30_SSO';                                                                  
	password(tab_key):='PORTAL30_SSO';                                                                  
	hash(tab_key):='882B80B587FCDBC8';                                                                  
	--                                                                                                  
	tab_key:=70;                                                                                        
	username(tab_key):='PORTAL30_SSO_PS';                                                               
	password(tab_key):='PORTAL30_SSO_PS';                                                               
	hash(tab_key):='F2C3DC8003BC90F8';                                                                  
	--                                                                                                  
	tab_key:=71;                                                                                        
	username(tab_key):='PORTAL30_SSO_PUBLIC';                                                           
	password(tab_key):='PORTAL30_SSO_PUBLIC';                                                           
	hash(tab_key):='98741BDA2AC7FFB2';                                                                  
	--                                                                                                  
	tab_key:=72;                                                                                        
	username(tab_key):='POWERCARTUSER';                                                                 
	password(tab_key):='POWERCARTUSER';                                                                 
	hash(tab_key):='2C5ECE3BEC35CE69';                                                                  
	--                                                                                                  
	tab_key:=73;                                                                                        
	username(tab_key):='PRIMARY';                                                                       
	password(tab_key):='PRIMARY';                                                                       
	hash(tab_key):='70C3248DFFB90152';                                                                  
	--                                                                                                  
	tab_key:=74;                                                                                        
	username(tab_key):='PUBSUB';                                                                        
	password(tab_key):='PUBSUB';                                                                        
	hash(tab_key):='80294AE45A46E77B';                                                                  
	--                                                                                                  
	tab_key:=75;                                                                                        
	username(tab_key):='QS';                                                                            
	password(tab_key):='QS';                                                                            
	hash(tab_key):='4603BCD2744BDE4F';                                                                  
	--                                                                                                  
	tab_key:=76;                                                                                        
	username(tab_key):='QS_ADM';                                                                        
	password(tab_key):='QS_ADM';                                                                        
	hash(tab_key):='3990FB418162F2A0';                                                                  
	--                                                                                                  
	tab_key:=77;                                                                                        
	username(tab_key):='QS_CB';                                                                         
	password(tab_key):='QS_CB';                                                                         
	hash(tab_key):='870C36D8E6CD7CF5';                                                                  
	--                                                                                                  
	tab_key:=78;                                                                                        
	username(tab_key):='QS_CBADM';                                                                      
	password(tab_key):='QS_CBADM';                                                                      
	hash(tab_key):='20E788F9D4F1D92C';                                                                  
	--                                                                                                  
	tab_key:=79;                                                                                        
	username(tab_key):='QS_CS';                                                                         
	password(tab_key):='QS_CS';                                                                         
	hash(tab_key):='2CA6D0FC25128CF3';                                                                  
	--                                                                                                  
	tab_key:=80;                                                                                        
	username(tab_key):='QS_ES';                                                                         
	password(tab_key):='QS_ES';                                                                         
	hash(tab_key):='9A5F2D9F5D1A9EF4';                                                                  
	--                                                                                                  
	tab_key:=81;                                                                                        
	username(tab_key):='QS_OS';                                                                         
	password(tab_key):='QS_OS';                                                                         
	hash(tab_key):='0EF5997DC2638A61';                                                                  
	--                                                                                                  
	tab_key:=82;                                                                                        
	username(tab_key):='QS_WS';                                                                         
	password(tab_key):='QS_WS';                                                                         
	hash(tab_key):='0447F2F756B4F460';                                                                  
	--                                                                                                  
	tab_key:=83;                                                                                        
	username(tab_key):='RE';                                                                            
	password(tab_key):='RE';                                                                            
	hash(tab_key):='933B9A9475E882A6';                                                                  
	--                                                                                                  
	tab_key:=84;                                                                                        
	username(tab_key):='REPADMIN';                                                                      
	password(tab_key):='REPADMIN';                                                                      
	hash(tab_key):='915C93F34954F5F8';                                                                  
	--                                                                                                  
	tab_key:=85;                                                                                        
	username(tab_key):='RMAIL';                                                                         
	password(tab_key):='RMAIL';                                                                         
	hash(tab_key):='DA4435BBF8CAE54C';                                                                  
	--                                                                                                  
	tab_key:=86;                                                                                        
	username(tab_key):='RMAN';                                                                          
	password(tab_key):='RMAN';                                                                          
	hash(tab_key):='E7B5D92911C831E1';                                                                  
	--                                                                                                  
	tab_key:=87;                                                                                        
	username(tab_key):='SAMPLE';                                                                        
	password(tab_key):='SAMPLE';                                                                        
	hash(tab_key):='E74B15A3F7A19CA8';                                                                  
	--                                                                                                  
	tab_key:=88;                                                                                        
	username(tab_key):='SCOTT';                                                                         
	password(tab_key):='TIGER';                                                                         
	hash(tab_key):='F894844C34402B67';                                                                  
	--                                                                                                  
	tab_key:=89;                                                                                        
	username(tab_key):='SDOS_ICSAP';                                                                    
	password(tab_key):='SDOS_ICSAP';                                                                    
	hash(tab_key):='C789210ACC24DA16';                                                                  
	--                                                                                                  
	tab_key:=90;                                                                                        
	username(tab_key):='SECDEMO';                                                                       
	password(tab_key):='SECDEMO';                                                                       
	hash(tab_key):='009BBE8142502E10';                                                                  
	--                                                                                                  
	tab_key:=91;                                                                                        
	username(tab_key):='SH';                                                                            
	password(tab_key):='SH';                                                                            
	hash(tab_key):='54B253CBBAAA8C48';                                                                  
	--                                                                                                  
	tab_key:=92;                                                                                        
	username(tab_key):='SYS';                                                                           
	password(tab_key):='CHANGE_ON_INSTALL';                                                             
	hash(tab_key):='D4C5016086B2DC6A';                                                                  
	--                                                                                                  
	tab_key:=93;                                                                                        
	username(tab_key):='SYSADM';                                                                        
	password(tab_key):='SYSADM';                                                                        
	hash(tab_key):='BA3E855E93B5B9B0';                                                                  
	--                                                                                                  
	tab_key:=94;                                                                                        
	username(tab_key):='SYSTEM';                                                                        
	password(tab_key):='MANAGER';                                                                       
	hash(tab_key):='D4DF7931AB130E37';                                                                  
	--                                                                                                  
	tab_key:=95;                                                                                        
	username(tab_key):='TAHITI';                                                                        
	password(tab_key):='TAHITI';                                                                        
	hash(tab_key):='F339612C73D27861';                                                                  
	--                                                                                                  
	tab_key:=96;                                                                                        
	username(tab_key):='TDOS_ICSAP';                                                                    
	password(tab_key):='TDOS_ICSAP';                                                                    
	hash(tab_key):='7C0900F751723768';                                                                  
	--                                                                                                  
	tab_key:=97;                                                                                        
	username(tab_key):='TRACESVR';                                                                      
	password(tab_key):='TRACE';                                                                         
	hash(tab_key):='F9DA8977092B7B81';                                                                  
	--                                                                                                  
	tab_key:=98;                                                                                        
	username(tab_key):='TSDEV';                                                                         
	password(tab_key):='TSDEV';                                                                         
	hash(tab_key):='29268859446F5A8C';                                                                  
	--                                                                                                  
	tab_key:=99;                                                                                        
	username(tab_key):='TSUSER';                                                                        
	password(tab_key):='TSUSER';                                                                        
	hash(tab_key):='90C4F894E2972F08';                                                                  
	--                                                                                                  
	tab_key:=100;                                                                                       
	username(tab_key):='USER0';                                                                         
	password(tab_key):='USER0';                                                                         
	hash(tab_key):='8A0760E2710AB0B4';                                                                  
	--                                                                                                  
	tab_key:=101;                                                                                       
	username(tab_key):='USER1';                                                                         
	password(tab_key):='USER1';                                                                         
	hash(tab_key):='BBE7786A584F9103';                                                                  
	--                                                                                                  
	tab_key:=102;                                                                                       
	username(tab_key):='USER2';                                                                         
	password(tab_key):='USER2';                                                                         
	hash(tab_key):='1718E5DBB8F89784';                                                                  
	--                                                                                                  
	tab_key:=103;                                                                                       
	username(tab_key):='USER3';                                                                         
	password(tab_key):='USER3';                                                                         
	hash(tab_key):='94152F9F5B35B103';                                                                  
	--                                                                                                  
	tab_key:=104;                                                                                       
	username(tab_key):='USER4';                                                                         
	password(tab_key):='USER4';                                                                         
	hash(tab_key):='2907B1BFA9DA5091';                                                                  
	--                                                                                                  
	tab_key:=105;                                                                                       
	username(tab_key):='USER5';                                                                         
	password(tab_key):='USER5';                                                                         
	hash(tab_key):='6E97FCEA92BAA4CB';                                                                  
	--                                                                                                  
	tab_key:=106;                                                                                       
	username(tab_key):='USER6';                                                                         
	password(tab_key):='USER6';                                                                         
	hash(tab_key):='F73E1A76B1E57F3D';                                                                  
	--                                                                                                  
	tab_key:=107;                                                                                       
	username(tab_key):='USER7';                                                                         
	password(tab_key):='USER7';                                                                         
	hash(tab_key):='3E9C94488C1A3908';                                                                  
	--                                                                                                  
	tab_key:=108;                                                                                       
	username(tab_key):='USER8';                                                                         
	password(tab_key):='USER8';                                                                         
	hash(tab_key):='D148049C2780B869';                                                                  
	--                                                                                                  
	tab_key:=109;                                                                                       
	username(tab_key):='USER9';                                                                         
	password(tab_key):='USER9';                                                                         
	hash(tab_key):='0487AFEE55ECEE66';                                                                  
	--                                                                                                  
	tab_key:=110;                                                                                       
	username(tab_key):='UTLBSTATU';                                                                     
	password(tab_key):='UTLESTAT';                                                                      
	hash(tab_key):='C42D1FA3231AB025';                                                                  
	--                                                                                                  
	tab_key:=111;                                                                                       
	username(tab_key):='VIDEOUSER';                                                                     
	password(tab_key):='VIDEOUSER';                                                                     
	hash(tab_key):='29ECA1F239B0F7DF';                                                                  
	--                                                                                                  
	tab_key:=112;                                                                                       
	username(tab_key):='VIF_DEVELOPER';                                                                 
	password(tab_key):='VIF_DEV_PWD';                                                                   
	hash(tab_key):='9A7DCB0C1D84C488';                                                                  
	--                                                                                                  
	tab_key:=113;                                                                                       
	username(tab_key):='VIRUSER';                                                                       
	password(tab_key):='VIRUSER';                                                                       
	hash(tab_key):='404B03707BF5CEA3';                                                                  
	--                                                                                                  
	tab_key:=114;                                                                                       
	username(tab_key):='VRR1';                                                                          
	password(tab_key):='VRR2';                                                                          
	hash(tab_key):='811C49394C921D66';                                                                  
	--                                                                                                  
	tab_key:=115;                                                                                       
	username(tab_key):='WEBDB';                                                                         
	password(tab_key):='WEBDB';                                                                         
	hash(tab_key):='D4C4DCDD41B05A5D';                                                                  
	--                                                                                                  
	tab_key:=116;                                                                                       
	username(tab_key):='WKSYS';                                                                         
	password(tab_key):='WKSYS';                                                                         
	hash(tab_key):='545E13456B7DDEA0';                                                                  
	--                                                                                                  	

	-- --------------------------------------------------------------------
	-- check all users in the database and see if defaults are set still
	-- --------------------------------------------------------------------
	dbms_output.put_line('Check default user passwords');
	dbms_output.put_line('============================');
	for lv_user in c_user loop
		for i in 1..tab_key loop
			if lv_user.username=username(i) then
				if lv_user.password=hash(i) then
					dbms_output.put_line('Default : '
						||username(i)||' passwd is :'
						||password(i));
					exit;
				end if;
			end if;
		end loop;
	end loop;
	-- --------------------------------------------------------------------
	-- check for some of the dangerous privileges
	-- 
	-- 	ALTER SYSTEM
	-- --------------------------------------------------------------------
	found:=0;
	dbms_output.put_line('.');
	dbms_output.put_line('Display Users that have the "ALTER SYSTEM" privilege');
	dbms_output.put_line('====================================================');
	for lv_sys_priv in c_sys_priv('ALTER SYSTEM') loop
		dbms_output.put_line(lv_sys_priv.privilege||' :'||lv_sys_priv.grantee);
	end loop;
	-- --------------------------------------------------------------------
	-- check for CREATE LIBRARY
	-- --------------------------------------------------------------------
	dbms_output.put_line('.');
	dbms_output.put_line('Display Users that have the "CREATE LIBRARY" privilege');
	dbms_output.put_line('======================================================');
	for lv_sys_priv in c_sys_priv('CREATE%LIBRARY') loop
		dbms_output.put_line(lv_sys_priv.privilege||' :'||lv_sys_priv.grantee);
	end loop;
	
	-- --------------------------------------------------------------------
	-- check the location of utl_file_dir and ensure its not the same as 
	-- the trace directories
	-- --------------------------------------------------------------------
	found:=0;
	dbms_output.put_line('.');
	dbms_output.put_line('Dislay utl_file_dir');
	dbms_output.put_line('===================');
	open c_utl_cur;
	loop
		fetch c_utl_cur into lv_utl_cur;
		if c_utl_cur%notfound then
			if found=0 then
				dbms_output.put_line('utl_file_dir is not set');
			end if;
			exit;
		else
			found:=1;
			dbms_output.put_line('utl_file_dir is '||rtrim(lv_utl_cur.value));
		end if;
	end loop;
	close c_utl_cur;
	dbms_output.put_line('.');
	dbms_output.put_line('Dislay destinations');
	dbms_output.put_line('===================');
	found:=0;
	open c_trace;
	loop
		fetch c_trace into lv_trace;
		if c_trace%notfound then
			if found=0 then
				dbms_output.put_line('no trace directories set');
			end if;
			exit;
		else 
			found:=1;
			dbms_output.put_line(rtrim(lv_trace.name)
				||' is '||rtrim(lv_trace.value));
		end if;
	end loop;
	close c_trace;
	-- --------------------------------------------------------------------
	-- check if the utl_file_dir clashes with any of the dest directions
	-- --------------------------------------------------------------------
	dbms_output.put_line('.');
	dbms_output.put_line('Display any clash between utl_file_dir and destination direcories');
	dbms_output.put_line('=================================================================');
	found:=0;
	open c_utl_trace;
	loop
		fetch c_utl_trace into lv_utl_trace;
		if c_utl_trace%notfound then
			if found=0 then
				dbms_output.put_line('No apparent match between utl_file_dir and dest directories');
			end if;
			exit;
		else
			dbms_output.put_line(lv_utl_trace.name||' matches utl_file_dir');
		end if;
	end loop;
	close c_utl_trace;
	-- --------------------------------------------------------------------
	-- check for users with the DBA privilege
	-- --------------------------------------------------------------------
	dbms_output.put_line('.');
	dbms_output.put_line('Check for users with "DBA" privilege');
	dbms_output.put_line('====================================');
	for lv_dba in c_dba loop
		dbms_output.put_line(lv_dba.grantee);
	end loop;
	-- --------------------------------------------------------------------
	-- check out which users have ANY
	-- --------------------------------------------------------------------
	dbms_output.put_line('.');
	dbms_output.put_line('Check for users with "ANY" privilege');
	dbms_output.put_line('====================================');
	for lv_sys_priv in c_sys_priv('%ANY%') loop
		dbms_output.put_line(lv_sys_priv.privilege||' :'||lv_sys_priv.grantee);
	end loop;
	
	-- --------------------------------------------------------------------
	-- check out users or roles that have "with admin"
	-- --------------------------------------------------------------------	
	dbms_output.put_line('.');
	dbms_output.put_line('Check for users or roles the have "with admin"');
	dbms_output.put_line('==============================================');
	for lv_admin in c_admin loop
		dbms_output.put_line(lv_admin.priv||' :'||lv_admin.grantee);
	end loop;
	-- --------------------------------------------------------------------
	-- check out which privileges have with with grant
	-- --------------------------------------------------------------------	
	dbms_output.put_line('.');
	dbms_output.put_line('Check for users and roles that have "grantable"');
	dbms_output.put_line('===============================================');
	for lv_grant in c_grant loop
		dbms_output.put_line(lv_grant.privilege||' :'
			||lv_grant.table_name||' :'||lv_grant.grantee);
	end loop;
	-- --------------------------------------------------------------------
	-- check out external users
	-- --------------------------------------------------------------------
	dbms_output.put_line('.');
	dbms_output.put_line('Display External Users');
	dbms_output.put_line('======================');
	for lv_ext in c_ext loop
		dbms_output.put_line(lv_ext.username);
	end loop;
	-- --------------------------------------------------------------------
	-- check out database links where there is a password set.
	-- --------------------------------------------------------------------
	dbms_output.put_line('.');
	dbms_output.put_line('Display Database links where there is a password set');
	dbms_output.put_line('====================================================');
	for lv_links in c_links loop
		dbms_output.put_line(lv_links.name||' :'||lv_links.host||' :'
			||lv_links.userid||' :'||lv_links.password
			||' :'||lv_links.authusr||' :'||lv_links.authpwd);
	end loop;
end;
/

spool off 
