# Tests of the fork

| Kind | Where | ctest | How it is registered |
|---|---|---|---|
| GUI tests (`testxca`, QTest, label `gui`) | `test/*.cpp`, slots of `test_main` in `test/main.h` | `testxca`, `test_automation_ids` | every `.cpp`/`.h` directly in `test/` by `file(GLOB)` |
| service tests (label `service`) | `test/service/test_service_<area>.cpp` | `test_service_<area>` | `file(GLOB)`, see `test/service/README.md` |
| CMake script tests of `xca --no-gui` | `test/service/cli_<name>.cmake` | `test_cli_<name>` | `file(GLOB)`, see `test/service/README.md` |
| command line `bxc-pki` | `cli/test/` | `test_cli_*` | `CliTest()` in `cli/CMakeLists.txt` |
| unit tests of single classes | `lib/test_*.cpp` | `test_*` | `Test()` in `lib/CMakeLists.txt` |

## Adding a test (BTD-256)

Registration goes by file name, so that branches that add tests at the same time do not edit the
same lines and do not conflict on merge.

**A GUI test in `testxca`:**

1. Add a new file `test/<topic>.cpp` with the test functions as members of `test_main`
   (`void test_main::myTest() { ... }`). The file is found by `file(GLOB)`; re-run CMake (the
   build does it).
2. Declare the slots in `test/main.h`, in the `private slots:` section, as a block of their own
   headed `/* <topic>.cpp */` and placed by file name among the other blocks. A test added to an
   existing file goes into that file's block. QTest runs the slots in declaration order.
3. Run `ctest -R testxca` in the build container; `testxca -functions` lists the slots.

**A service test** or **a CMake script test:** see `test/service/README.md`, section "Adding tests
for a service ticket". Neither needs a line in a CMakeLists.

The command line tests (`CliTest()` in `cli/CMakeLists.txt`) and the unit tests (`Test()` in
`lib/CMakeLists.txt`) still need a line each; add it at its alphabetical place rather than at the
end, which keeps parallel additions apart.
