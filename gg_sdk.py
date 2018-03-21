import sys
import os
import stat
import shutil
import numpy as np
import subprocess as sp
import json
import hashlib
import base64
import multiprocessing as mp # For getting number of cores
import magic # pip install python_magic
import gg_pb2 # User may need to build gg.proto

from threading import Thread
from concurrent.futures import Future
from timeit import default_timer as now

gg_magic_hash = '@@GG_HASH@@'
gg_magic_num = '##GGTHUNK##'

"""
Function used in conjunction with threaded for returning values
"""
def call_with_future(fn, future, args, kwargs):
    try:
        result = fn(*args, **kwargs)
        future.set_result(result)
    except Exception as exc:
        future.set_exception(exc)

"""
Function for multithreading thunk generation in force()
"""
def threaded(fn):
    def wrapper(*args, **kwargs):
        future = Future()
        Thread(target=call_with_future, args=(fn, future, args, kwargs)).start()
        return future
    return wrapper

# TODO: add GGThunk constructor for taking in groups of inputs and batch num

"""
GGThunk class. Each function is represented through this IR.

If args_infiles=True, GGThunk will denote all arguments that are not flags
as infiles. Sometimes, this will lead to incorrect infiles (e.g. -o <out>
will see <out> as an infile). Thus, the user can tell GG not to do this,
and instead pass the infiles in manually. May be a point of optimization.
"""
class GGThunk(object):
    def __init__(self, exe, envars=[], num_out=1, outname='', exe_args=[],
                 args_infiles=True):
        self.num_outputs = num_out
        self.exe = exe
        self.thunk_hash = ''
        self.args = exe_args
        self.envars = envars
        self.order = 0
        self.outname = outname
        self.file_infiles = {}
        self.ggth_infiles = []

        # Function is also an infile
        self.add_infile([exe])

        if not isinstance(self.envars, list):
            self.envars = [self.envars]
        if not isinstance(exe_args, list):
            self.args = [self.args]
        if args_infiles:
            for ea in self.args:
                # Only add if a GGThunk or a string but not a flag
                if (isinstance(ea, GGThunk) or
                    (isinstance(ea, str) and 
                    '--' not in ea and
                    '-o' not in ea)):
                    self.add_infile([ea])

    """
    Function to add an infile once the thunk is created
    """
    # if_type is optional: should be able to predict file type
    def add_infile(self, all_inf, if_type='INVALID'):
        if not isinstance(all_inf, list):
            all_inf = [all_inf]
        for new_inf in all_inf:
            new_inf_file_flag = False
            if isinstance(new_inf, str):
                new_inf_file_flag = True
            elif not isinstance(new_inf, GGThunk):
                self.__inv_file_print()

            _if_type = if_type

            if if_type != 'INVALID':
                if ( if_type != 'FILE' or 
                     if_type != 'EXECUTABLE' or
                     if_type != 'GGTHUNK' ):
                    self.__inv_file_print()
                    return
            else:
                if new_inf_file_flag:
                    # Check if file exists before attempting to predict
                    check_file = os.path.isfile(new_inf)
                    if not check_file:
                        print(new_inf + " not found")
                        sys.exit(1) 

                    # If it is not an x86 ELF executable or a Python script,
                    # predict it to be a regular FILE
                    pred_type = magic.from_file(new_inf)
                    if "ELF" in pred_type:
                        if "statically linked" in pred_type:
                            _if_type = 'EXECUTABLE'
                        else:
                            print("Only statically linked binaries supported")
                            sys.exit(1)
                    else:
                        _if_type = 'FILE'
                else:
                    _if_type = 'GGTHUNK'

            assert _if_type != 'INVALID'

            if new_inf_file_flag:
                self.file_infiles[new_inf] = _if_type
            else:
                self.ggth_infiles.append(new_inf)

    """
    Function called by the GG class to generate and
    serialize the thunk
    """
    def generate_thunk(self, outnum):
        # Go through GGThunk infiles and recursively generate
        for inf in self.ggth_infiles:
            if inf.outname == '':
                inf.set_outname('output_' + str(outnum))
            inf.generate_thunk(outnum + 1)

            # Accounts for user passing in GGThunk as exe_arg
            if inf in self.args:
                self.args[self.args.index(inf)] = inf.get_outname()

        self.__compute_order()

        # Special case if there are no ggth_infiles: the order
        # is then 1
        if not self.ggth_infiles:
            self.order = 1

        self.__proto_ser_thunk()

    """-------- Helper and accessor functions --------"""
    """
    Function for generating json for printing thunk. 
    Originally also meant for generating thunks,
    but now only used for printing.
    """
    def __gen_thunk_json(self):
        all_infiles = self.__comb_infiles()
        data = { 'function': {
                                'exe': self.exe,
                                'args': self.args,
                                'hash': self.__file_hash(self.exe),
                                'envars': self.envars,
                             },
                 'infiles': [{
                                'filename': inf[0],
                                'hash': inf[1],
                                'order': inf[2],
                                'size': inf[3],
                                'type': inf[4]
                             } for inf in all_infiles],
                'outfile': self.outname
        }
        return data

    """
    Create protobuf and serialize thunk
    """
    def __proto_ser_thunk(self):
        all_infiles = self.__comb_infiles()
        thunk_proto = gg_pb2.Thunk()

        # Add Function
        func_proto = thunk_proto.function
        func_proto.exe = self.exe
        func_proto.hash = self.__file_hash(self.exe)
        func_proto.args.extend(self.args)
        func_proto.envars.extend(self.envars)

        # Add Infiles
        all_inf = []
        for inf in all_infiles:
            inf_proto = gg_pb2.InFile()
            inf_proto.filename = inf[0]
            inf_proto.hash = inf[1]
            inf_proto.order = inf[2]
            inf_proto.size = inf[3]
            inf_type = inf[4]
            if inf_type == 'FILE':
                inf_proto.type = gg_pb2.InFile.FILE
            elif inf_type == 'EXECUTABLE':
                inf_proto.type = gg_pb2.InFile.EXECUTABLE
            elif inf_type == 'DUMMY_DIRECTORY':
                inf_proto.type = gg_pb2.InFile.DUMMY_DIRECTORY
            else:
                print("Unknown type: " + inf_type + ", setting to FILE")
                inf_proto.type = gg_pb2.InFile.FILE

            all_inf.append(inf_proto)

        thunk_proto.infiles.extend(all_inf)

        # Add Outfile
        thunk_proto.outfile = self.outname

        # Serialize to string
        ser_thunk = thunk_proto.SerializeToString()

        # Generate hash, and write to file
        self.thunk_hash = self.__gen_hash_bytes(str.encode(gg_magic_num) + ser_thunk)
        check_file = os.path.isfile('.gg/blobs/' + self.thunk_hash)

        if not check_file:
            fd = open('.gg/blobs/' + self.thunk_hash, "wb")
            fd.write(str.encode(gg_magic_num) + ser_thunk)
            fd.close()

        """
        print("--ORDER: " + str(self.order) + "--")
        print(str(thunk_proto))
        """

    """
    Function for printing thunks
    """
    def print_thunk(self):
        print("--ORDER: " + str(self.order) + "--")
        print(json.dumps(self.__gen_thunk_json(),
                    indent=2, separators=(',', ': ')))

    """
    Thunk hash accessor
    """
    def get_hash(self):
        if self.thunk_hash == '':
            self.thunk_hash = __file_hash(self.exe)

        return self.thunk_hash

    """
    Thunk outfile name accessor
    """
    def get_outname(self):
        return self.outname

    """
    Thunk order accessor
    """
    def get_order(self):
        return self.order

    """
    Function to set the Thunk's outfile name
    """
    def set_outname(self, new_name):
        self.outname = new_name

    """
    Function to either look up hash from hash_cache, or
    generate hash and make a hash_cache entry.

    NOTE: Python does not have a timespec struct, so the
    comparisons are only done with seconds, not nanoseconds.
    The nanoseconds entries are INCORRECT, but are implemented
    to maintain valid file format. However, since ggLang
    generates its own thunks, this should not be a problem.
    """
    def __file_hash(self, filename):
        f_fd = os.open(filename, os.O_RDONLY)
        info = os.fstat(f_fd)
        os.close(f_fd)

        hash_name = "%d-%d-%s" % (info.st_dev, info.st_ino, filename)
        hash_path = '.gg/hash_cache/' + hash_name

        if os.path.exists(hash_path):
            h_fd = open(hash_path, 'r')
            h_file_cont = h_fd.readlines()[0].split()
            h_fd.close()

            if len(h_file_cont) != 6:
                print("Bad cache entry:", hash_path)
                sys.exit(1)
            
            if (h_file_cont[0] == str(int(info.st_size)) and
               h_file_cont[1] == str(int(info.st_mtime)) and
               h_file_cont[3] == str(int(info.st_ctime))):
                  return h_file_cont[5]

        # File not in cache, compute hash and add to hash_cache
        next_hash = self.__gen_hash_file(filename)
        outstr = "%d %d %d %d %d %s" % (info.st_size, info.st_mtime, 100, info.st_ctime, 101, next_hash)
        h_fd = open(hash_path, 'w')
        h_fd.write(outstr)
        h_fd.close() 

        return next_hash 

    """
    Function to merge infiles (since they can be a mix of
    external files and other GGThunks
    """
    def __comb_infiles(self):
        # Combine all infiles
        all_infiles = []
        for k, v in self.file_infiles.items():
            next_hash = self.__file_hash(k)
            if not os.path.exists('.gg/blobs/' + next_hash):
                shutil.copy(k, '.gg/blobs/' + next_hash)
            next_size = os.path.getsize('.gg/blobs/' + next_hash)
            next_tuple = (k, next_hash, 0, next_size, v)
            all_infiles.append(next_tuple)

            # Also need to replace filename in args with magicnum + hash
            if k in self.args:
                self.args[self.args.index(k)] = (
                        gg_magic_hash + next_hash)
        for ig in self.ggth_infiles:
            next_tuple = (ig.get_outname(), ig.get_hash(), ig.get_order(),
                    0, 'FILE')
            all_infiles.append(next_tuple)

            # Also need to replace filename in args with magicnum + hash
            if ig.get_outname() in self.args:
                self.args[self.args.index(ig.get_outname())] = (
                        gg_magic_hash + ig.get_hash())

        return all_infiles

    """
    Function to compute Thunk's order
    """
    def __compute_order(self):
        self.order = 0
        for inf in self.ggth_infiles:
            self.order = max(inf.get_order(), self.order)
        self.order += 1

    """
    Infile usage function
    """
    def __inv_file_print(self):
        print("Invalid file type. Options:")
        print("\tFILE: file/library input")
        print("\tEXECUTABLE: x86 ELF binary")
        print("\tGGTHUNK: GGThunk object")

    """
    Generate hash from a string
    """
    def __gen_hash_string(self, h_str):
        hasher = hashlib.sha256()
        hasher.update(str.encode(h_str))
        cont_hash = hasher.digest()
        dec_hash = base64.b64encode(cont_hash).decode().replace('+','.').replace('/', '_')
        # Remove last character (=)
        dec_hash = dec_hash[:-1]
        suffix = '%08x' % len(h_str)
        return dec_hash + suffix

    """
    Generate hash from a string of bytes
    """
    def __gen_hash_bytes(self, h_bytes):
        hasher = hashlib.sha256()
        hasher.update(h_bytes)
        cont_hash = hasher.digest()
        dec_hash = base64.b64encode(cont_hash).decode().replace('+','.').replace('/', '_')
        dec_hash = dec_hash[:-1]
        suffix = '%08x' % len(h_bytes)
        return dec_hash + suffix

    """
    Generate hash from a file
    """
    def __gen_hash_file(self, h_file):
        fd = os.open(h_file, os.O_RDONLY)
        content = b''
        eof_check = False
        while not eof_check:
            next_read = os.read(fd, 1024*1024)

            if next_read != b'':
                content += next_read
            else:
                eof_check = True

        os.close(fd)
        return self.__gen_hash_bytes(content)

"""
GG class. Interfaces with the GG platform, creates GGThunk placeholders,
and creates graph.
"""
class GG(object):
    def __init__(self, cleanenv=True):
        if cleanenv:
            self.clean_env()

        self.initialize()

    """
    Function to clean gg environment
    """
    def clean_env(self, deepClean=False):
        if deepClean:
            if os.path.exists('.gg'):
                shutil.rmtree('.gg')
        else:
            if os.path.exists('.gg/reductions'):
                shutil.rmtree('.gg/reductions')
            if os.path.exists('.gg/remote'):
                shutil.rmtree('.gg/remote')

    """
    Initialize gg directories
    """
    def initialize(self):
        # Make blobs and hash_cache directory as well
        if not os.path.exists('.gg/hash_cache'):
            os.makedirs('.gg/hash_cache')

        if not os.path.exists('.gg/blobs'):
            os.makedirs('.gg/blobs')
            print("Initialized gg directory at: " + os.getcwd() + "/.gg")

    """
    Infer build from make builds
    """
    def infer_build_make(self, np=-1):
        make_cmd = 'make -j'
        if nproc != -1:
            if nproc == 0:
                make_cmd += '1'
            else:
                make_cmd += str(np)
        in_proc = sp.Popen(['gg-infer', make_cmd], stdout=sp.PIPE)
        out = in_proc.communicate()[0]
        return out

    """
    Infer builds using model-gcc
    """
    def infer_build_mgcc(self, gcc_cmd):
        cmd = ['model-gcc'] + gcc_cmd.split()
        in_proc = sp.Popen(cmd, stdout=sp.PIPE)
        out = in_proc.communicate()[0]
        return out

    """
    Generate gg-force command
    """
    def __get_force_comm(self, inputs, showstatus, env, genfunc, numjobs):
        if env == 'lambda':
            os.environ['GG_LAMBDA'] = '1'
        elif env == 'remote':
            os.environ['GG_REMOTE'] = '1'

        if genfunc:
            os.environ['GG_GENERIC_FUNCTION'] = '1'

        nj_inp = ['--jobs', str(numjobs)]

        cmd_start = ['gg-force']
        if showstatus:
            cmd_start.append('--status')

        cmd = cmd_start + nj_inp + inputs
        return cmd

    """
    Multi-threading function for creating placeholders in parallel
    """
    @threaded
    def __distr_thunk_gen(self, my_chunk):
        for c in my_chunk:
            c.generate_thunk(0)

        return self.__create_placeholder(my_chunk)

    """
    Function called by user to create thunks.
    Function will first create placeholders if needed
    by first creating all thunks (i.e. generating graph).
    This function will NOT execute the thunks
    """
    def create_thunks(self, inputs):
        start = now()
        # Perform sanity checks
        if not inputs:
            print("List of inputs is empty!")
            return

        if not isinstance(inputs, list):
            inputs = [inputs]

        # Check for valid inputs
        # If input type is GGThunk, the actual thunks need to be created
        # along with a placeholder per input
        cmd_inp = []
        if isinstance(inputs[0], GGThunk):
            # Set the input name before generating...needed to be
            # consistent with placeholder
            out_index = 0
            for inp in inputs:
                if inp.get_outname() == '':
                    next_filename = 'my_output_' + str(out_index) + '.out'
                    inp.set_outname(next_filename)
                    out_index += 1

            # Multithread thunk generation
            all_threads = []
            num_cores = mp.cpu_count()
            if len(inputs) < num_cores:
                for inp in inputs:
                    all_threads.append(self.__distr_thunk_gen([inp]))
            else:
                batch_size = int(len(inputs) / num_cores)
                for i in range(num_cores):
                    if i < num_cores-1:
                        all_threads.append(self.__distr_thunk_gen(inputs[i*batch_size:i*batch_size+batch_size]))
                    else:
                        all_threads.append(self.__distr_thunk_gen(inputs[i*batch_size:]))

            for at in all_threads:
                cmd_inp.extend(at.result())

            if len(cmd_inp) != len(inputs):
                print("Error: cmd_inp != inputs")
                sys.exit(1)
        elif isinstance(inputs[0], str):
            print("Nothing to generate...")
            cmd_inp = inputs
        else:
            print("invalid input: must be a GGThunk object")
            sys.exit(1)

        end = now()
        delta = end - start
        print("Time to generate thunks: %.3f seconds" % delta)
        return cmd_inp

    """
    Function called by user to execute thunks
    Function will first create placeholders if needed
    by first creating all thunks (i.e. generating graph)
    """
    def create_and_force(self, inputs, showstatus=True, showcomm=True,
                        env='lambda', numjobs=100, genfunc=True):
        cmd_inp = self.create_thunks(inputs)

        cmd = self.__get_force_comm(cmd_inp, showstatus, env, genfunc, numjobs)
        if showcomm:
            jcomm = ' '.join(cmd)
            print("Env variables already set. Command being run:", jcomm)

        start = now()
        in_proc = sp.Popen(cmd)
        out = in_proc.communicate()[0]
        end = now()
        delta = end - start
        print("Time to execute thunks: %.3f seconds" % delta)
        return out

    """
    Function to create placeholders
    """
    def __create_placeholder(self, inputs):
        header = '#!/usr/bin/env gg-force-and-run'
        placeholder_thunks = []
        for inp in inputs:
            next_filename = inp.get_outname()
            fd = open(next_filename, 'w')
            content_hash = inp.get_hash()
            order = str(inp.get_order())
            size = str(os.path.getsize('.gg/blobs/' + content_hash))
            fd.write(header + '\n')
            fd.write(content_hash + ' ' + order + ' ' + size + '\n')
            fd.write('*/\n')
            fd.close()
            # Make executable
            st = os.stat(next_filename)
            os.chmod(next_filename, st.st_mode | stat.S_IEXEC)    

            placeholder_thunks.append(next_filename)

        return placeholder_thunks


