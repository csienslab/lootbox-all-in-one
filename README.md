# Loot Box Protocol All-in-One

Projects:

* https://github.com/csienslab/toy-headstart-py
* https://github.com/csienslab/loot-box-protocol
* https://github.com/csienslab/chiavdf

## Requirements

* Docker on Linux amd64 (Tested on Docker 27.1.2)

## How to use

```bash
DOCKER_BUILDKIT=1 docker build . -t lb  # build the image and tag it as `lb`
docker run -it --rm --name lootbox --network host lb  # run the container, please make sure that port 5000 and 12121 are not in use
```
