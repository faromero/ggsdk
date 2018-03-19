# ggSDK
```ggSDK``` is a Python SDK for interfacing with [```gg```](https://github.com/StanfordSNR/gg). It allows applications developers to create computation graphs and pipelines in native Python code that are eventually executable on ```gg```.

The outline of this README is as follows:
- ```ggSDK``` API
- Setting up ```ggSDK```
- Examples

Note: In this README, ```gg``` refers to the execution platform while GG refers to the ```ggSDK``` class.

## ggSDK API
### GG Class
```GG(env=’lambda’, numjobs=100, cleanenv=True, isgen=True)```: Class Constructor
- **env**: Environment to execute thunks in. Currently supports *lambda* (default) and *local*
- **numjobs**: Maximum number of workers executing thunks. For lambda environment, this means maximum number of lambda that are running at any given time. Default is 100
- **cleanenv**: Setting this to True (default) will remove the reductions and remote directories from .gg, which is the local directory used by gg to keep track of thunks and their reductions. This will allow ```gg``` to perform a “fresh” experiment run each time it runs. Setting this to False will maintain previous runs, which means that gg will likely not have to do any new thunk executions when rerun.
- **isgen**: Is a generic function. By default, this is set to True since almost all pipelines and graphs written in ```ggSDK``` are not software builds. However, if you wish to do a software build graph with ```ggSDK```, set this to False.

```set_env(env)```: Function to change the environment after class object creation.

```set_numjobs(numjobs)```: Function to change the number of workers executing thunks after class object creation.

```clean_env(deepClean=False)```: Function to clean gg environment. By default, this gets called by the GG constructor with deepClean=False (i.e. only remove the reductions and remote directories). User can call this method with deepClean=True to remove all directories from .gg and start the ```gg``` environment from scratch.

```force(inputs, showstatus=True, showcomm=True)```: Creates all thunks recursively and calls on ```gg``` to execute them.
- **inputs**: one or more thunks to be executed. For multiple thunks, pass in as a list. Function call will block until execution is completed.
- **showstatus**: Append the status flag to ```gg```’s command arguments to show the thunk execution progress. Defaults to True.
- **showcomm**: Print the command that ```ggSDK``` will use to invoke ```gg```. Defaults to True.

Users almost always will only need to call ```force```.

### GGThunk Class
```GGThunk(exe, envars=[], outname=’’, exe_args=’’, args_infiles=True)```: Class Constructor
- **exe**: Name of binary that will be run when the thunk is forced by ```gg```. Currently, this function must be a statically linked binary.
- **envars**: List of environment variables that should be set by gg to execute this thunk’s function. Defaults to empty. If there are no environment variables that need to be set, this can be left empty.
- **outname**: Name of output file. If no output name is given, ```gg``` will create one. Important: if your program produces an output file, it must have the same name as this outname, since ```gg``` will search for a file with this name upon completion of this thunk’s execution. It will also be used as an infile name into thunks that reference this thunk. Thus, it is best to pass a name for outname.
- **exe_args**: Executable arguments (such as flags, input files, output files, etc.). Pass in as a string (i.e. as it would be typed into the command line). Defaults to an empty string. If there are no executable arguments that need to be set, this can be left empty.
- **args_infiles**: By default, ```gg``` will attempt to take all exe_args and turn them into infiles. This is especially useful if the executable’s arguments are all input files/data with no flags. However, for programs that mix flags with input files, ```ggSDK``` will not be able to differentiate between the two. Thus, if your exe_args are a mix of flags with input files, or if you prefer to explicitly pass in all infiles, set this parameter to be False.

```add_infile(all_inf, if_type=’INVALID’)```: Function to add an infile once the thunk is created.
- **all_inf**: one or more infiles to be added as dependencies. For multiple infiles, pass in as a list. Infiles can be a) the name of a file, b) the name of an executable, and/or c) a GGThunk object (thus creating a graph/pipeline). Infile types can be mixed within the all_inf list.
- **if_type**: infile type. This parameter is optional, and can be left as INVALID (the default) since ```ggSDK``` will automatically infer the type (which is especially useful when mixing different infile types).

```print_thunk(numjobs)```: Function to print out the thunk in json format.

Users almost always will only need to call ```add_infile```.

## Setting up ggSDK
- Ensure ```gg``` is installed by cloning its project repository and following the installation instructions.
Once ```gg``` is installed, no further action needs to be performed to make it work with ```ggSDK```.

- ```ggSDK``` requires a few Python libraries that may not be installed on your machine: ```numpy``` and ```python_magic```. To install these two using pip3, you can run the command:
```sudo pip3 install numpy python_magic```

- ```ggSDK``` uses the same gg_pb2.py as ```gg``` to generate thunks. It requires gg_pb2.py to be in the working directory (i.e. the same directory as gg_sdk.py).

- To use ```ggSDK```, simply add the following line to the top of your python script:
```from gg_sdk import GG, GGThunk```

## Examples
### Excamera
```
cd excamera-example
./fetch-deps.sh
./excam_ex.py <start> <end> <batch-size> <cq-level> <num-workers>
Example: ./excam_ex.py 0 4 2 32 50
```
Further information about the [Excamera](https://www.usenix.org/conference/nsdi17/technical-sessions/presentation/fouladi) [project](https://github.com/excamera).

### Video Decoding + Image Recognition
```
cd viddec-example
./fetch-deps.sh
./ffmpeg_gg.py to run with default parameters, or ./ffmpeg_gg.py -h for information on optional parameters. Optional parameters are:
-j: number of workers (default is 50)
-e: execution environment. Can be lambda (default) or local
-v: video chunks to process (default is the included 4kvid chunks)
Example: ./ffmpeg_gg.py -j 1000
```
