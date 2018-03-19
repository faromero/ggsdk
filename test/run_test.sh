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
while IFS='' read -r line || [[ -n "$line" ]]; do
    next_file="test_"${file_ind}".out"
    echo "Now testing output of "${next_file}
    if [ ! -f ${next_file} ]; then
        echo "TEST FAILED: "${next_file}" not found"
        exit
    fi
    check_line=$(head -n 1 ${next_file})
    gold_line="Thunk "${file_ind}" read: "${line}
    echo "Gold line: "${gold_line}
    echo "Text read from line: "${check_line}
    echo "PASS"
    echo "---"
done < test_lines.txt

echo "All tests passed!"

# Clean up environment for next run
rm -rf .gg *.out gg_pb2.py* gg_sdk.py*

