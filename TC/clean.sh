. ./_export_env.sh                              # setting environment variables

echo PATH=$PATH
echo LD_LIBRARY_PATH=$LD_LIBRARY_PATH
echo TET_ROOT=$TET_ROOT
echo TET_SUITE_ROOT=$TET_SUITE_ROOT
echo ARCH=$ARCH

RESULT_DIR=results-$ARCH
HTML_RESULT=$RESULT_DIR/build-tar-result-$FILE_NAME_EXTENSION.html
JOURNAL_RESULT=$RESULT_DIR/build-tar-result-$FILE_NAME_EXTENSION.journal

mkdir $RESULT_DIR

tcc -c -p ./                                # executing tcc, with clean option (-c)

rm -rf $RESULT_DIR
rm -rf tet_tmp_dir
rm -rf results
