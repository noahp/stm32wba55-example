mkdir -p memfault_wba55_port/include
mkdir -p memfault_wba55_port/src
cp Core/Inc/memfault* memfault_wba55_port/include/
cp STM32CubeIDE/memfault_port/*.c memfault_wba55_port/src
zip memfault_wba55_port.zip memfault_wba55_port

git show > ble_p2pserver_mflt.patch
