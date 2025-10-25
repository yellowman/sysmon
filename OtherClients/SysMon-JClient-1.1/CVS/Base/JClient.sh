#!/bin/sh

#######################################################
# Edit these...
#######################################################
JAVAPROG='/usr/local/bin/java'
JCLIENT_PATH='/path/to/zip/file/SysMon-JClient-1.1.classes.zip'
DEFAULT_HOST='monitor.hq.cic.net'
DEFAULT_PORT='1345'

#######################################################
# No more editing...
#######################################################

CLASSPATH=$JCLIENT_PATH:$CLASSPATH

$JAVAPROG MonitorClient Host=$DEFAULT_HOST Port=$DEFAULT_PORT
