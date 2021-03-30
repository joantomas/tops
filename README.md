# TOPS - Tooling for Operations

This will try to be a docker with the main utils that I use to need in my daily tasks.
It will be a continuously WIP.

To generate the executable you just need to run ```./argbash-generator```. In order to generate the bash script, I'm
using [Argbash](https://argbash.io/).

The script will be generated inside ```dist/tops.sh```, I will recommend creating a link inside ```/usr/local/bin```.

By default the script will use ```${HOME}/.env``` file as environment variables. For instance:

```shell
AWS_PROFILE=yourprofile

# SOPS to enable AWS_PROFILE https://github.com/mozilla/sops/issues/439
AWS_SDK_LOAD_CONFIG=1
```