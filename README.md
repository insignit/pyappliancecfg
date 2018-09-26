# pyappliancecfg

This will help you configure simple network settings for an appliance / vm

http://g.recordit.co/uBwLg8J95a.gif

This is a fork with parents:
- https://github.com/pasqumirk/pydialog-interfaces
- https://github.com/pragbits/pydialog-interfaces

Changes:    
 - Added parsers to get current ip, mask and gateway (borrowed from saltstack)
 - added py3 support
 - Removed ifconfig calls
 - changed some formatting 
 - added options to set ntp settings
 - added docker file to build with
 - added option to embed secondary configuration ui

# requirements

- `apt install dialog` if not already
- those in the `requirements.txt` (`python3 -m pip install -r requirements.txt`)


# building

will result in an executable `appliancecfg` and some `so` files

`docker build -t pyappliancecfg .`
`docker run -ti --name pyappliancecfg pyappliancecfg bash`

open second terminal
`docker cp pyappliancecfg:/pyappliancecfg/appliancecfg.dist/appliancecfg.tar.gz $PWD/`
`docker rm -f pyappliancecfg`


# running

```
./appliancecfg --external_config someexecutable --external_config_name MyConfigurator --external_config_desc 'Configure other cool stuff'
```

