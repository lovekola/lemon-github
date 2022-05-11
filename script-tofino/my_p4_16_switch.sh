#!/bin/bash
#This script includes the following functions (only for P4_16): 
##1) configure, build, install P4 program
##2) run ptf for specified P4 program
##3) stop and clean P4 program  

function print_help(){
	echo "USAGE:$(basename""$0""){-b|-p|-t|-c}<P4_program_name>"
	echo "-h"
	echo "  print this help"
	echo "-b"
	echo "  configure, make and install your P4 programs"
	echo "-t"
	echo "  run python test for P4 program"
	echo "-p"
	echo "  run P4 program"	
	echo "-bp"
	echo "  -b && -p"	
	echo "-pt"
	echo "  -p && -t"	
	echo "-a"
	echo "  -b && -p && -t"
	echo "-c"
	echo "  stop given P4 program"
	echo "-i"
	echo "  show P4 visualization though p4i, you can acess it by any brower after this program starts"	
	echo "-k"
	echo "  kill running programs which contain given name"	
	exit 0
}

function build_p4(){
	#cd $P4_PATH/$P4_NAME
	$SDE/p4_build.sh \
		--with-graphs \
		--with-p4c=bf-p4c \
		$P4_PATH/$P4_NAME/$P4_NAME.p4 \
		P4_NAME=$P4_NAME 
	#cd $SDE
}

function run_p4_and_ptf(){
	screen -dmS test
	echo "##########################################################"
	SCREEN_ID=`screen -ls|grep test|cut -c 1-11`
	echo "your P4 program runing in screen: $SCREEN_ID"
	echo "##########################################################"
	screen -S test -p 0 -X stuff "$SDE/run_switchd.sh -p $P4_NAME\n"
	$SDE/run_p4_tests.sh -t $P4_PATH/$P4_NAME/
	ps aux|grep "SCREEN -dmS test"|grep -v grep|cut -c 9-16|xargs kill -9
	screen -wipe
}

function check(){
	flag=`lsmod |grep bf| cut -c 31-32`
	echo $flag
	if [ "$flag" != "0" ] ; then
		echo "A run_switch process already exists, wait and try again."
		FLAG=true
	fi
}

P4_NAME=""
SCREEN_ID=""
P4_PATH="$SDE/pkgsrc/p4-examples/p4_16_programs"
HELP=false
BUILD=false
TEST=false
RUN=false
CLEAN=false
VISUALIZATION=false
KILL=false
LEMON=false
FLAG=false
while [ "$1" ] ; do
	case "$1" in
		-h)  HELP=true;shift 1;;
		-b)  BUILD=true;shift 1;;
		-t)  TEST=true;shift 1;;
		-p)  RUN=true;shift 1;;
		-bp) BUILD=true;RUN=true;shift 1;;
		-pt) RUN=true;TEST=true;shift 1;;
		-a)  BUILD=true;RUN=true;TEST=true;shift 1;;
		-c)  CLEAN=true;shift 1;;
		-i)  VISUALIZATION=true;shift 1;;
		-k) KILL=true;shift 1;;
		--lemon) LEMON=true;shift 1;;
		*)   P4_NAME="$1";shift 1;;
	esac 
done

echo "P4_NAME=${P4_NAME}"
#check
if [ $FLAG = true ] ; then
	exit
fi

if [ $HELP = true ] ; then
	print_help
fi

if [ $LEMON = true ] ; then
	P4_PATH="/root/lemon/my_p4/tasks"
fi

if [ -z $P4_NAME ] ; then
	echo "cann't run without P4_program_name" && exit 1
fi

if ( [ $BUILD = true ] &&  [ $RUN = true ] && [ $TEST = true ] ) ; then
	check
	if [ $FLAG = true ] ; then
		exit
	fi
	build_p4
	run_p4_and_ptf
	stty echo
	exit 0
fi

if ( [ $RUN = true ] &&  [ $TEST = true ] ) ; then
	check
	if [ $FLAG = true ] ; then
		exit
	fi
	run_p4_and_ptf
	stty echo
	exit 0
fi

if ( [ $BUILD = true ] &&  [ $RUN = true ] ) ; then
	build_p4
	$SDE/run_switchd.sh -p $P4_NAME
	stty echo
	exit 0
fi

if [ $BUILD = true ] ; then
	build_p4
fi

if [ $RUN = true ] ; then
	check
	if [ $FLAG = true ] ; then
		exit
	fi
	$SDE/run_switchd.sh -p $P4_NAME --skip-port-add
fi

if [ $TEST = true ] ; then
	$SDE/run_p4_tests.sh -t $P4_PATH/$P4_NAME/ 
fi

if [ $CLEAN = true ] ; then
	ps aux|grep $P4_NAME|grep -v grep|cut -c 9-16|xargs kill -9
fi

if ( [ $VISUALIZATION = true ] ); then
	p4i -w $SDE/build/p4-build/$P4_NAME/tofino/$P4_NAME
fi

if ( [ $KILL = true ] ); then
	ps aux|grep $P4_NAME| grep -v grep|cut -c 9-15| xargs kill -9
fi

if ( [ $BUILD = false ] && [ $RUN = false ] && [ $TEST = false ] && [ $CLEAN = false ] && [ $KILL = false ] && [ $VISUALIZATION = false ] ); then
	echo "no target find; please use '-h' for help" && exit 1
fi
stty echo
