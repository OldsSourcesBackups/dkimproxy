#!/bin/sh
#
# Copyright (c) 2005-2006 Messiah College.
#
### BEGIN INIT INFO
# Default-Start:  3 4 5
# Default-Stop:   0 1 2 6
# Description:    Runs dkfilter
### END INIT INFO

DKFILTERUSER=dkfilter
DKFILTERGROUP=dkfilter
DKFILTERDIR=/usr/local/dkfilter

HOSTNAME=`hostname -f`
DOMAIN=`hostname -d`
DKFILTER_IN_ARGS="
	--hostname=$HOSTNAME
	127.0.0.1:10025 127.0.0.1:10026"
DKFILTER_OUT_ARGS="
	--keyfile=$DKFILTERDIR/private.key
	--selector=selector1
	--domain=$DOMAIN
	--method=nofws
	--headers
	127.0.0.1:10027 127.0.0.1:10028"

DKFILTER_COMMON_ARGS="
	--user=$DKFILTERUSER
	--group=$DKFILTERGROUP
	--daemonize"

DKFILTER_IN_BIN="$DKFILTERDIR/bin/dkfilter.in"
DKFILTER_OUT_BIN="$DKFILTERDIR/bin/dkfilter.out"

PIDDIR=$DKFILTERDIR/var/run
DKFILTER_IN_PID=$PIDDIR/dkfilter_in.pid
DKFILTER_OUT_PID=$PIDDIR/dkfilter_out.pid

case "$1" in
	start-in)
		echo -n "Starting inbound DomainKeys-filter (dkfilter.in)..."

		# create directory for pid files if necessary
		test -d $PIDDIR || mkdir -p $PIDDIR || exit 1

		# start the filter
		$DKFILTER_IN_BIN $DKFILTER_COMMON_ARGS --pidfile=$DKFILTER_IN_PID $DKFILTER_IN_ARGS
		RETVAL=$?
		if [ $RETVAL -eq 0 ]; then
			echo done.
		else
			echo failed.
			exit $RETVAL
		fi
		;;

	start-out)
		echo -n "Starting outbound DomainKeys-filter (dkfilter.out)..."

		# create directory for pid files if necessary
		test -d $PIDDIR || mkdir -p $PIDDIR || exit 1

		# start the filter
		$DKFILTER_OUT_BIN $DKFILTER_COMMON_ARGS --pidfile=$DKFILTER_OUT_PID $DKFILTER_OUT_ARGS
		RETVAL=$?
		if [ $RETVAL -eq 0 ]; then
			echo done.
		else
			echo failed.
			exit $RETVAL
		fi
		;;

	stop-in)
		echo -n "Shutting down inbound DomainKeys-filter (dkfilter.in)..."
		if [ -f $DKFILTER_IN_PID ]; then
			kill `cat $DKFILTER_IN_PID` && rm -f $DKFILTER_IN_PID
			RETVAL=$?
			[ $RETVAL -eq 0 ] && echo done. || echo failed.
			exit $RETVAL
		else
			echo not running.
		fi
		;;
	stop-out)
		echo -n "Shutting down outbound DomainKeys-filter (dkfilter.out)..."
		if [ -f $DKFILTER_OUT_PID ]; then
			kill `cat $DKFILTER_OUT_PID` && rm -f $DKFILTER_OUT_PID
			RETVAL=$?
			[ $RETVAL -eq 0 ] && echo done. || echo failed.
			exit $RETVAL
		else
			echo not running.
		fi
		;;
	start)
		$0 start-in && $0 start-out || exit $?
		;;
	stop)
		$0 stop-in && $0 stop-out || exit $?
		;;
	restart)
		$0 stop && $0 start || exit $?
		;;
	status)
		echo -n "dkfilter.in..."
		if [ -f $DKFILTER_IN_PID ]; then
			pid=`cat $DKFILTER_IN_PID`
			if ps -ef |grep -v grep |grep -q "$pid"; then
				echo " running (pid=$pid)"
			else
				echo " stopped (pid=$pid not found)"
			fi
		else
			echo " stopped"
		fi
		echo -n "dkfilter.out..."
		if [ -f $DKFILTER_OUT_PID ]; then
			pid=`cat $DKFILTER_OUT_PID`
			if ps -ef |grep -v grep |grep -q "$pid"; then
				echo " running (pid=$pid)"
			else
				echo " stopped (pid=$pid not found)"
			fi
		else
			echo " stopped"
		fi
		;;
	*)
		echo "Usage: $0 {start|stop|restart|status}"
		exit 1
		;;
esac
