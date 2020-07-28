#!/bin/sh

PROGRAM_BIN=router_config_learning_tool
PROGRAM_BUILD_DIR=build


if [ -d ${PROGRAM_BUILD_DIR}/ ]; then
	rm -rf ${PROGRAM_BUILD_DIR}/
fi
mkdir -p ${PROGRAM_BUILD_DIR}/


cd ${PROGRAM_BUILD_DIR}/
cmake ..
make
cd - > /dev/null

cp ${PROGRAM_BUILD_DIR}/bin/${PROGRAM_BIN} .

echo ""
echo "----------------------------------------------------------"
echo "--- finish build program: ${PROGRAM_BIN}"
echo "----------------------------------------------------------"
echo ""

ls -l ${PROGRAM_BIN}
echo ""

