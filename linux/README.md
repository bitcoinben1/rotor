## Linux building

1. Install libgmp-dev
2. Install CUDA 11.7
 
 - Or pass them as variables to `make` command.
 - Install libgmp: ```sudo apt install -y libgmp-dev```


    ```make
    CUDA       = /usr/local/cuda-11.7
    CXXCUDA    = /usr/bin/g++
    ```
 - To build CPU-only version (without CUDA support):
    ```sh
    $ make all
    ```
 - To build with CUDA: pass CCAP value according to your GPU compute capability
    ```sh
    $ cd Rotor-Cuda
    $ make gpu=1 CCAP=75 all
    ```
    <hr>
    FOR RTX 3060, 3070, 3080, 3090, A5000, A6000, A100 - use CCAP=86 (CUDA 11.7)</br>
    FOR RTX 2070, 2080 - use CCAP=75 (CUDA 11.7)</br>
    FOR GTX 1060, 1070, 1080 - use CCAP=61 (CUDA 10.2)</br>
