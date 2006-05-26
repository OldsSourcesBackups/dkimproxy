#!/bin/sh
#
# Copyright (c) 2005-2006 Messiah College.
#
### BEGIN INIT INFO
# Default-Start:  3 4 5
# Default-Stop:   0 1 2 6
# Description:    Runs dkimproxy
### END INIT INFO

DKFILTERUSER=dkfilter
DKFILTERGROUP=dkfilter
DKFILTERDIR=/usr/local/dkfilter

HOSTNAME=`hostname -f`
DOMAIN=`hostname -d`
DKFILTER_IN_ARGS="--hostname=$HOSTNAME 127.0.0.1:10025 127.0.0.1:10026"
DKFILTER_OUT_ARGS="--keyfile=$DKFILTERDIR/private.key --selector=selector1 --domain=$DOMAIN --method=nofws --headers 127.0.0.1:10027 127.0.0.1:10028"

DKFILTER_IN_BIN="$DKFILTERDIR/bin/dkfilter.in"
DKFILTER_OUT_BIN="$DKFILTERDIR/bin/dkfilter.out"

case "$1" in
	start)
		echo -n "Starting inbound DomainKeys-filter (dkfilter.in)..."
		startproc -u $DKFILTERUSER -g $DKFILTERGROUP -l /dev/null \
			$DKFILTER_IN_BIN $DKFILTER_IN_ARGS
		RETVAL=$?
		if [ $RETVAL -eq 0 ]; then
			echo done.
		else
			echo failed.
			exit $RETVAL
		fi
		echo -n "Starting outbound DomainKeys-filter (dkfilter.out)..."
		startproc -u $DKFILTERUSER -g $DKFILTERGROUP -l /dev/null \
			$DKFILTER_OUT_BIN $DKFILTER_OUT_ARGS
		RETVAL=$?
		if [ $RETVAL -eq 0 ]; then
			echo done.
		else
			echo failed.
			exit $RETVAL
		fi
		;;

	stop)
		echo -n "Shutting down inbound DomainKeys-filter (dkfilter.in)..."
		killproc $DKFILTER_IN_BIN
		RETVAL=$?
		if [ $RETVAL -eq 0 ]; then
			echo done.
		else
			echo failed.
		fi
		echo -n "Shutting down outbound DomainKeys-filter (dkfilter.out)..."
		killproc $DKFILTER_OUT_BIN
		RETVAL=$?
		if [ $RETVAL -eq 0 ]; then
			echo done.
		else
			echo failed.
			exit $RETVAL
		fi
		;;
	restart)
		$0 stop
		$0 start
		;;
	*)
		echo "Usage: $0 {start|stop|restart}"
		exit 1
		;;
esac
