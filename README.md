# symbol-bls

Symbol-bls is experimental BLS-12-381 implementation based on apache millagro cpp library.

## Building

```
mkdir _build
cd _build
conan install --build missing
cmake -G "<GENERATOR>" -DUSE_CONAN=ON -DENABLE_TESTS=ON ..
# build according to your generator
```


[catapult-server]: https://github.com/nemtech/catapult-server
