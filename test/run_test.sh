#!/bin/bash

# Copy gg_pb2.py and gg_sdk.py into test directory
cp ../gg_pb2.py ../gg_sdk.py .

# Check that test_program.cc exists
if [ ! -f test_program.cc ]; then
    echo "test_program.cc not found."
    exit
fi

# Check that test_program.cc exists
if [ ! -f test_program ]; then
    g++ -static test_program.cc -o test_program
fi

# Check that test_lines.txt exists
if [ ! -f test_lines.txt ]; then
    echo "test_lines.txt not found."
    exit
fi

# Check that test_gg_gen.py exists
if [ ! -f test_gg_gen.py ]; then
    echo "test_gg_gen.py not found..."
    exit
fi

# Clean environment from previous runs
rm -rf .gg *.out

# Call test_gg_gen.py
./test_gg_gen.py

# Walk through test_lines.txt and each output file to check for correctness
file_ind=0
num_passed=0
num_failed=0

echo
while IFS='' read -r line || [[ -n "$line" ]]; do
    next_file="test_"${file_ind}".out"
    echo "Now testing output of "${next_file}
    if [ ! -f ${next_file} ]; then
        echo "TEST FAILED: "${next_file}" not found"
        exit
    fi
    check_line=$(head -n 1 ${next_file})
    gold_line="Thunk "${file_ind}" read: "${line}
    if [ "${gold_line}" == "${check_line}" ]; then
        num_passed=$[$num_passed + 1]
        echo "PASS"
        echo "---"
    else
        num_failed=$[$num_failed + 1]
        echo "TEST FAILED"
        echo "Expected: "${gold_line} 
        echo "Read: "${check_line}
        echo "---"
    fi 
    file_ind=$[$file_ind + 1]
done < test_lines.txt

# Output results
echo
echo "All tests completed"
echo "==="
echo ${num_passed}" tests passed"
echo ${num_failed}" tests failed"
echo "==="

# Clean up environment for next run
rm -rf .gg *.out gg_pb2.py* gg_sdk.py*

