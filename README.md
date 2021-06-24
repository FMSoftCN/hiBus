# HiDataBus

HiDataBus is the data bus for device side of HybridOS.

- [Introduction](#introduction)
- [Dependencies](#dependencies)
- [Current Status](#current-status)
- [Build HiDataBus for Standalone Use](#build-hibus-for-standalone-use)
- [TODO List](#todo-list)
- [Copying](#copying)
   + [Commercial License](#commercial-license)
   + [Special Statement](#special-statement)

## Introduction

In HybridOS, an important design idea is always implemented: data-driven.
Regardless of whether it is a single app scenario or multiple apps scenarios,
hiDataBus will act as the link between HybridOS app and the underlying functional
modules; and even in the future, it will become the link between different
device nodes in the LAN.

Some ideas of hiDataBus come from OpenWRT's uBus, such as passing data in JSON format.
But compared to uBus, hiDataBus has the following important improvements:

- Two types of underlying connection channels are provided: local Unix Domain Socket
  and Web Socket, so that modules developed in different programming languages can
  be easily connected to hiDataBus.
- Providing a basic security mechanism to determine whether an application or a remote
  node can subscribe to a specific event or call a specific procedure.
- Considering that in the future, hiDataBus can provide services to other IoT device nodes
  in the local area network through Web Socket, we include host name
  information when subscribing to events and calling remote procedures.
- The redesigned hiDataBus protocol can avoid deadlock when the same app plays
  different roles.

HiDataBus includes the following three components:

1. HiDataBus server, an executable program which runs as a daemon in the system.
1. HiDataBus cmdline, an executable program which provides an interactive command line program
   for test and debugging.
1. HiDataBus library, an library which provides some APIs for clients to use hiDataBus easily.

For more information, please refer to:

<https://github.com/FMSoftCN/hybridos/blob/master/docs/design/hybridos-data-bus-zh.md>

## Dependencies

HiDataBus depends on the following libraries:

- [hiBox](https://github.com/FMSoft/hibox) provides some utilities for HybridOS device side in C language.
- [glib](https://github.com/GNOME/glib) provides data structure handling for C language.
- OpenSSL (optional) provides support for secure WebSocket connections.

## Current Status

- Jan. 2021: Version 1.0.
- Dec. 2020: First release (version 0.9).
- Oct. 2020: Skeleton of source code.

## Build HiDataBus for Standalone Use

To build hiDataBus for your own usage on a generic Linux box without
the app management of HybridOS, use the following options for `cmake`:

```
$ cmake -DBUILD_APP_AUTH=OFF <directory_to_source_code>
```

If you use the `-DBUILD_APP_AUTH=OFF` option, hiDataBus will use a dummy app
authentication method to avoid preparing your app authentication system.

## TODO List

- Version 1.2
   1. Support for WebSocket in `libhibus`.
   1. Support for plugins of builtin endpoints.
   1. Unit tests.

## Copying

Copyright (C) 2020 FMSoft <https://www.fmsoft.cn>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

### Commercial License

If you cannot accept GPLv3, you need to be licensed from FMSoft.

For more information about the commercial license, please refer to
<https://hybridos.fmsoft.cn/blog/hybridos-licensing-policy>.

### Special Statement

The above open source or free software license(s) does
not apply to any entity in the Exception List published by
Beijing FMSoft Technologies Co., Ltd.

If you are or the entity you represent is listed in the Exception List,
the above open source or free software license does not apply to you
or the entity you represent. Regardless of the purpose, you should not
use the software in any way whatsoever, including but not limited to
downloading, viewing, copying, distributing, compiling, and running.
If you have already downloaded it, you MUST destroy all of its copies.

The Exception List is published by FMSoft and may be updated
from time to time. For more information, please see
<https://www.fmsoft.cn/exception-list>.

