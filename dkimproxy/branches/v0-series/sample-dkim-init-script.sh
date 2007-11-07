#!/bin/sh
#
# Copyright (c) 2005-2006 Messiah College.
#
### BEGIN INIT INFO
# Default-Start:  3 4 5
# Default-Stop:   0 1 2 6
# Description:    Runs dkimproxy
### END INIT INFO

DKIMPROXYUSER=dkfilter
DKIMPROXYGROUP=dkfilter
DKIMPROXYDIR=/usr/local/dkfilter

HOSTNAME=`hostname -f`
DOMAIN=`hostname -d`
DKIMPROXY_IN_ARGS="
	--hostname=$HOSTNAME
	127.0.0.1:10025 127.0.0.1:10026"
DKIMPROXY_OUT_ARGS="
	--keyfile=$DKIMPROXYDIR/private.key
	--selector=selector1
	--domain=$DOMAIN
	--method=relaxed
	127.0.0.1:10027 127.0.0.1:10028"

DKIMPROXY_COMMON_ARGS="
	--user=$DKIMPROXYUSER
	--group=$DKIMPROXYGROUP
	--daemonize"

DKIMPROXY_IN_BIN="$DKIMPROXYDIR/bin/dkimproxy.in"
DKIMPROXY_OUT_BIN="$DKIMPROXYDIR/bin/dkimproxy.out"

PIDDIR=$DKIMPROXYDIR/var/run
DKIMPROXY_IN_PID=$PIDDIR/dkimproxy_in.pid
DKIMPROXY_OUT_PID=$PIDDIR/dkimproxy_out.pid

case "$1" in
	start-in)
		echo -n "Starting inbound DKIM-proxy (dkimproxy.in)..."

		# create directory for pid files if necessary
		test -d $PIDDIR || mkdir -p $PIDDIR || exit 1

		# start the daemon
		$DKIMPROXY_IN_BIN $DKIMPROXY_COMMON_ARGS --pidfile=$DKIMPROXY_IN_PID $DKIMPROXY_IN_ARGS
		RETVAL=$?
		if [ $RETVAL -eq 0 ]; then
			echo done.
		else
			echo failed.
			exit $RETVAL
		fi
		;;

	start-out)
		echo -n "Starting outbound DKIM-proxy (dkimproxy.out)..."

		# create directory for pid files if necessary
		test -d $PIDDIR || mkdir -p $PIDDIR || exit 1

		# start the daemon
		$DKIMPROXY_OUT_BIN $DKIMPROXY_COMMON_ARGS --pidfile=$DKIMPROXY_OUT_PID $DKIMPROXY_OUT_ARGS
		RETVAL=$?
		if [ $RETVAL -eq 0 ]; then
			echo done.
		else
			echo failed.
			exit $RETVAL
		fi
		;;

	stop-in)
		echo -n "Shutting down inbound DKIM-proxy (dkimproxy.in)..."
		if [ -f $DKIMPROXY_IN_PID ]; then
			kill `cat $DKIMPROXY_IN_PID` && rm -f $DKIMPROXY_IN_PID
			RETVAL=$?
			[ $RETVAL -eq 0 ] && echo done. || echo failed.
			exit $RETVAL
		else
			echo not running.
		fi
		;;
	stop-out)
		echo -n "Shutting down outbound DKIM-proxy (dkimproxy.out)..."
		if [ -f $DKIMPROXY_OUT_PID ]; then
			kill `cat $DKIMPROXY_OUT_PID` && rm -f $DKIMPROXY_OUT_PID
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
		echo -n "dkimproxy.in..."
		if [ -f $DKIMPROXY_IN_PID ]; then
			pid=`cat $DKIMPROXY_IN_PID`
			if ps -ef |grep -v grep |grep -q "$pid"; then
				echo " running (pid=$pid)"
			else
				echo " stopped (pid=$pid not found)"
			fi
		else
			echo " stopped"
		fi
		echo -n "dkimproxy.out..."
		if [ -f $DKIMPROXY_OUT_PID ]; then
			pid=`cat $DKIMPROXY_OUT_PID`
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
