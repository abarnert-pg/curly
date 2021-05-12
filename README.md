# curly
Android test app for CurlWrapper and PGEngine builds of curl and prereqs

To build, you must have the static libs and includes for curl and its prereqs, as built for Dragons/PGEngine, in `../dragons3d/Externals/pgengine/Externals`. You can do this by just cloning curly and dragons3d as siblings in the same directory.

If everything works, when you run it, you should see the contents of https;//example.com (as raw HTML).

Unlike Dragons itself, when debugging this project, it should be possible to step into curl, mbedtls, etc. source code, see the parameters and locals, etc.
