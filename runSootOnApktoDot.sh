#!/bin/bash

ANDROID_JARS_PATH="/home/soot_test/android-platforms"

JAVA_CLASSPATH="\
/home/soot_test/tools/sootclasses-trunk-jar-with-dependencies.jar:\
/home/soot_test/tools/AXMLPrinter2_zixie.jar:\
/home/soot_test/tools/baksmali-2.3.4.jar:\
"

APK_FILE=APP/$1
BASE_APK_NAME=`basename -s .apk $APK_FILE`
SOOT_OUT_DIR=MySootOutput/$BASE_APK_NAME-dots
mkdir $SOOT_OUT_DIR

PROCESS_THIS=" -process-dir $APK_FILE" 
SOOT_CLASSPATH="\
"${APK_FILE}":\
"
SOOT_CMD="soot.tools.CFGViewer \
 --graph=BriefUnitGraph \
 -d $SOOT_OUT_DIR \
 -android-jars $ANDROID_JARS_PATH \
 -android-api-version 28 \
 -allow-phantom-refs \
 -src-prec apk \
 -ire \
 -f J \
 $PROCESS_THIS
"

java \
 -Xss100m \
 -Xmx3500m \
 -classpath  ${JAVA_CLASSPATH} \
 ${SOOT_CMD}\

cd $SOOT_OUT_DIR

rename 's/[ ]+/./g' *

rename 's/[\$]+/./g' *
