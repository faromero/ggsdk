#! /usr/bin/python

from gg_sdk import GG, GGThunk

test_prog_bin = 'test_program'
test_lines = 'test_lines.txt'

def main():
    gg = GG()
    all_thunks = []
    for i in range(10):
        next_thunk = GGThunk(exe=test_prog_bin, outname='test_%d.out'%i,
                exe_args=[test_lines, '%d' % i], args_infiles=False)
        next_thunk.add_infile(test_lines)
        all_thunks.append(next_thunk)

    gg.create_and_force(all_thunks, showcomm=False, showstatus=False, numjobs=10)

if __name__ == '__main__':
    main()

