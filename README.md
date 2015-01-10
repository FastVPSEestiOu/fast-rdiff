 // Вот так можно перетереть 1 байт в начале файла:
 // dd if=/dev/urandom count=1 bs=1 of=64zero conv=notrunc 

How to build?

got clone ..
cd fastrdiff
mkdir build
cd build
cmake ..
make
