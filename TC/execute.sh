. ./_export_target_env.sh                    # setting environment variables

echo PATH=$PATH
echo LD_LIBRARY_PATH=$LD_LIBRARY_PATH
echo TET_ROOT=$TET_ROOT
echo TET_SUITE_ROOT=$TET_SUITE_ROOT
echo ARCH=$ARCH

RESULT_DIR=results-$ARCH
HTML_RESULT=$RESULT_DIR/exec-tar-result-$FILE_NAME_EXTENSION.html
JOURNAL_RESULT=$RESULT_DIR/exec-tar-result-$FILE_NAME_EXTENSION.journal

mkdir $RESULT_DIR

tcc -e -j $JOURNAL_RESULT -p ./             # executing tcc, with –e option
grw -c 3 -f chtml -o $HTML_RESULT $JOURNAL_RESULT # reporting the result

