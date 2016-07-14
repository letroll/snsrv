
# snsrv [![Build Status](https://travis-ci.org/swalladge/snsrv.svg?branch=master)](https://travis-ci.org/swalladge/snsrv)

A [Simplenote](http://simplenote.com/) compatible API / self hosted notes server.

## WARNING

While the implementation is almost complete, this has not been fully tested yet. Use at own risk!


## Features

- aims to be 100% compatible with the simplenote third party api (this means you should be able to point your simplenote client to the address of this server and it will work out of the box)
- multiuser, secure, etc...
- selfhosted!!
- scalable with tornado and sqlalchemy
- web admin interface (TODO - currently very limited)

## Dependencies

The following software and libraries are used:

- python3

Python libraries:

- tornado
- sqlalchemy
- bcrypt

These can be installed with your package manager, or with pip once python is installed.


## Running

For running/testing, you can simply do the following:

1. clone the repo
2. edit config.py to suit
3. install deps and run (preferably in a virtual env)!

```
git clone https://github.com/swalladge/snsrv.git
cd snsrv
vim config.py
pyvenv env
source env/bin/activate
pip install -r requirements.txt
python app.py
```

## TODO/ROADMAP

- work out versioning with notes (merges? reject with version newer/older? use modifydate instead?)
- work out how to handle tag versioning
- handle note version conflicts (find more info and test against simplenote's api)
- work out how note/tag sharing works to be able to implement it
- test for stability and security (unittests? how to unittest tornado apps?)
- admin interface/api (for managing users, etc.)
- add extra features like note sharing/public notes (sharekey, publickey)


## Contributing

At the moment the server needs a lot of work!
Many things must be implemented, and then thoroughly tested for compatibility, stability, and security.
If you would like to contribute, feel free to contact me, raise an issue, or submit a pull request. :)


## Documentation

The API is documented using [raml](http://raml.org/). Docs can be generated with the `build_docs.sh` script included.

See `config.py` for example configuration options.


## Contributors

Thanks to everyone who has contributed to this project! The contributor list:

- Samuel Walladge (author)
- Alexandre Bulté


## License

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


Copyright © 2015-2016 Samuel Walladge and contributors
