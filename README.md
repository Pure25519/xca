# XCA - X Certificate and Key Management

[![CMake](https://github.com/chris2511/xca/actions/workflows/cmake.yaml/badge.svg)](https://github.com/chris2511/xca/actions/workflows/cmake.yaml)

## __Release Notes__

* The latest release is *2.9.0*
* This release fixes some minor issues:
  * Improve remote database support on macosx
  * Do not revoke renewed certificate with same serial
  * Fix default template finding on linux
  * Use latest OpenSSL and Qt releases for the precompiled releases.
* Please report issues on github <https://github.com/chris2511/xca/issues>

## __Changelog:__

A detailed changelog can be found here:

<https://hohnstaedt.de/xca/index.php/software/changelog>

## __Documentation__

This application is documented in the *Help* menu and here:

<https://www.hohnstaedt.de/xca/index.php/documentation/manual>

## __Build from Source__

### Dependencies

To build XCA you need:
 - a toolchain
 - cmake: https://cmake.org (3.25 or higher)
 - Qt5 or Qt6: https://www.qt.io (5.10.1 or higher)
 - OpenSSL: https://www.openssl.org (4.1 or higher; this fork does not build
   against OpenSSL 3 or LibreSSL). Point CMake to it with
   `-DOPENSSL_ROOT_DIR=<prefix>` when the system OpenSSL is older.
 - Sphinx-Build: https://www.sphinx-doc.org

### Linux / Unix

 - Install the dependencies
   ```
   # Bookworm
   sudo apt install build-essential libssl-dev pkg-config cmake qttools5-dev python3-sphinxcontrib.qthelp
   # Bullseye
   sudo apt install build-essential libssl-dev pkg-config cmake qttools5-dev python3-sphinx
   # Either Qt5
   sudo apt install qtbase5-dev qttools5-dev-tools libqt5sql5 libqt5help5 qttools5-dev
   # Or Qt6
   sudo apt install qt6-base-dev qt6-tools-dev
   ```
 - Clone: `git clone https://github.com/chris2511/xca.git`
 - Configure: `cmake -B build xca`
 - Make: `cmake --build build -j5`
 - Install: `sudo cmake --install build`
 - Or install local and copy later as root: `DESTDIR=DEST cmake --install build --prefix /usr`

### Apple macos

- Install the dependencies
  ```
  xcode-select --install
  brew install openssl@3 qt6 python3 cmake
  pip3 install sphinx
  ```
- Clone: `git clone https://github.com/chris2511/xca.git`
- Configure: `cmake -B build xca`
- Make: `cmake --build build -j5`
- Build the DMG: `cd build && cpack`
- Build the PKG: `cd build && cpack -G productbuild`

XCA can be used with Xcode after initializing the directory with:
`cmake -G Xcode -B .`

### Windows

This fork builds with MSVC (Visual Studio 2022) against OpenSSL 4.1 and Qt 6.12
(`msvc2022_64`). Untested in this fork: no Windows build has run yet, the steps
below follow the MSVC setup and are checked when it is done.

- Install the dependencies
  - Visual Studio 2022 Build Tools with the workload "Desktop development with C++"
    (cl, nmake and CMake 3.25 or later)
  - Strawberry Perl and NASM, both on PATH, for the OpenSSL build
  - Python 3 with Sphinx (documentation) and aqtinstall (Qt):
    ```
    pip3 install sphinx aqtinstall
    aqt install-qt windows desktop 6.12.0 win64_msvc2022_64 -O C:\Qt
    ```
  - `https://wixtoolset.org/releases/` (WiX 3) if you want to create the MSI installer
- OpenSSL 4.1 has no official Windows binaries. Build it from source in an
  "x64 Native Tools Command Prompt for VS 2022"; the script checks the SHA-256 of
  the release tarball and installs `libcrypto-4-x64.dll`:
  ```
  pwsh -File xca\release\build-openssl-msvc.ps1 -Prefix C:\OpenSSL-4.1
  ```
- Clone: `git clone https://github.com/chris2511/xca.git`
- Configure (same prompt): `cmake -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=C:\OpenSSL-4.1 -DCMAKE_PREFIX_PATH=C:\Qt\6.12.0\msvc2022_64 xca`
- Make: `cmake --build build`
- Create the Portable App: `cmake --install build`
- Build the MSI installer (and the Portable App): `cd build ; cpack`

The installer ships the libcrypto DLL of the OpenSSL found
(`libcrypto-<major>-x64.dll`), and the MinGW runtime DLLs only from a MinGW build.
`release/build-w64.sh` still builds with MinGW in MSYS2, with OpenSSL 4.1 from
source; it is untested in this fork as well.

## __SQL Remote Database Drivers__

MySQL plugins are not shipped with QT anymore because of license issues.

### Linux

- Debian: `libqt6sql6-psql` `libqt6sql6-mysql` or `libqt6sql6-odbc`.
- RPM: `libqt6-database-plugin-pgsql` `libqt6-database-plugin-mysql` `libqt6-database-plugin-odbc`

They should pull in all necessary dependencies.

### Apple macos

- **PostgreSQL**: Driver included since XCA 2.9.0
- **ODBC**: It requires the `/usr/local/opt/libiodbc/lib/libiodbc.2.dylib`.
    When installing unixodbc via `brew` the library must be symlinked from
    `/opt/homebrew/Cellar/libiodbc/3.52.16/lib/libiodbc.2.dylib`
- **MariaDB**: Driver included since XCA 2.8.0

### Windows

- **PostgreSQL**: https://www.enterprisedb.com/downloads/postgres-postgresql-downloads (Commandline tools).
  Add the `bin` directory of the Postgres installation directory to your PATH (C:\\Program Files\\PostgreSQL\\16)
- **ODBC**: Use the `ODBC Datasources 64bit app` to configure the SQL Server
- **MariaDB (MySQL)**: Install the Plugin from here: https://github.com/thecodemonkey86/qt_mysql_driver.
  Select the MinGW variant and install it as documented.
