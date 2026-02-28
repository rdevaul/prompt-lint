<h1 align="center">
  <img src="https://raw.githubusercontent.com/neovim/neovim.github.io/master/static/logos/neovim-logo-300x87.png" alt="Neovim">

  <a href="https://neovim.io/doc/">Documentation</a> |
  <a href="https://app.element.io/#/room/#neovim:matrix.org">Chat</a>
</h1>

[](https://scan.coverity.com/projects/2227)
[](https://repology.org/metapackage/neovim)
[](https://buildd.debian.org/neovim)
[](https://github.com/neovim/neovim/releases/)

Neovim is a project that seeks to aggressively refactor [Vim](https://www.vim.org/) in order to:

- Simplify maintenance and encourage [contributions](CONTRIBUTING.md)
- Split the work between multiple developers
- Enable [advanced UIs] without modifications to the core
- Maximize [extensibility](https://neovim.io/doc/user/api-ui-events.html#api-ui-events)

See the [Introduction](https://github.com/neovim/neovim/wiki/Introduction) wiki page and [Roadmap]
for more information.

Features
--------

- Modern [GUIs](https://github.com/neovim/neovim/wiki/Related-projects#gui)
- [API access](https://github.com/neovim/neovim/wiki/Related-projects#api-clients)
  from any language including C/C++, C#, Clojure, D, Elixir, Go, Haskell, Java/Kotlin,
  JavaScript/Node.js, Julia, Lisp, Lua, Perl, Python, Racket, Ruby, Rust
- Embedded, scriptable [terminal emulator](https://neovim.io/doc/user/terminal.html)
- Asynchronous [job control](https://github.com/neovim/neovim/pull/2247)
- [Shared data (shada)](https://github.com/neovim/neovim/pull/2506) among multiple editor instances
- [XDG base directories](https://github.com/neovim/neovim/pull/3470) support
- Compatible with most Vim plugins, including Ruby and Python plugins

See [`:help nvim-features`][nvim-features] for the full list, and [`:help news`][nvim-news] for noteworthy changes in the latest version!

Install from package
--------------------

Pre-built packages for Windows, macOS, and Linux are found on the
[Releases](https://github.com/neovim/neovim/releases/) page.

[Managed packages] are in [Homebrew], [Debian], [Ubuntu], [Fedora], [Arch Linux], [Void Linux], [Gentoo], and more!

Install from source
-------------------

See [BUILD.md](./BUILD.md) and [supported platforms](https://neovim.io/doc/user/support.html#supported-platforms) for details.

The build is CMake-based, but a Makefile is provided as a convenience.
After installing the dependencies, run the following command.
```bash
make CMAKE_BUILD_TYPE=RelWithDebInfo
sudo make install
```

To install to a non-default location:
```bash
make CMAKE_BUILD_TYPE=RelWithDebInfo CMAKE_INSTALL_PREFIX=/full/path/
make install
```

CMake hints for inspecting the build:

- `cmake --build build --target help` lists all build targets.
- `build/CMakeCache.txt` (or `cmake -LAH build/`) contains the resolved values of all CMake variables.
- `build/compile_commands.json` shows the full compiler invocations for each translation unit.

Transitioning from Vim
--------------------

See [`:help nvim-from-vim`](https://neovim.