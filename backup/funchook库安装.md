## 编译 funchook 静态库
`
mkdir build && cd build
cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON
make
sudo make install

-DCMAKE_POSITION_INDEPENDENT_CODE=ON  它会让 libfunchook.a 内部的目标文件都加上 -fPIC，这样才能安全地被 .so 使用
`