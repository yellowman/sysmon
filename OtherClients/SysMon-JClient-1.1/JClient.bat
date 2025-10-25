rem @echo off

rem #######################################################
rem # Edit these...
rem #######################################################

set JAVAPROG = 'c:\windows\jview'
set JCLIENT_PATH = 'p:\public_html\java\MonitorClient\SysMon-JClient-1.1.classes.zip'
set DEFAULT_HOST = 'monitor.hq.cic.net'
set DEFAULT_PORT = '1345'

rem #######################################################
rem # No more editing...
rem #######################################################

set CLASSPATH = $JCLIENT_PATH;$CLASSPATH

$JAVAPROG MonitorClient Host=$DEFAULT_HOST Port=$DEFAULT_PORT
