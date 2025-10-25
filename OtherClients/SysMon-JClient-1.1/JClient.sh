#!/bin/sh

#######################################################
# Edit these...
#######################################################
JAVAPROG='/usr/bin/java'
JCLIENT_PATH='SysMon-JClient-1.1.classes.zip'
DEFAULT_HOST='localhost.nether.net'
DEFAULT_PORT='1345'

#######################################################
# No more editing...
#######################################################

CLASSPATH=$JCLIENT_PATH:$CLASSPATH

$JAVAPROG -classpath $CLASSPATH MonitorClient Host=$DEFAULT_HOST Port=$DEFAULT_PORT
