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

## Per-project isolation

Each host repo is mounted at `/workspace/<org>/<repo>` (derived from the last two components of the
launch path) and the container's working directory is set there. Because Claude Code keys its per-project
memory and session history by the working directory, this gives every repo its own isolated store instead
of everything collapsing onto a single `/workspace` bucket. Launch `tops` from the **repo root** so the
`<org>/<repo>` identity is derived correctly.

## Reaching services in the container

On a Linux host, each running container is reachable directly at its bridge IP — no port publishing is
needed, so any number of containers can run at once without coordinating ports. The container prints its
IP in the shell banner on start; you can also read it with `hostname -i` inside, or from the host with
`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container-name>`.

Any port bound to `0.0.0.0` inside the container is reachable at `http://<container-ip>:<port>` — the port
number is arbitrary (no ports are published to the host), just pick a free local port and reuse it in the
URL. To expose a cluster service on your laptop:

1. Inside the container: `kubectl port-forward --address 0.0.0.0 -n <ns> svc/<svc> <port>:<targetPort>`
2. On the laptop: open `http://<container-ip>:<port>`

The `--address 0.0.0.0` is **required**: `kubectl port-forward` binds to loopback by default, which the
host cannot reach through the container's bridge IP. Any other server you run in the container must
likewise bind `0.0.0.0`, not `127.0.0.1`.

Note: this direct-IP access is Linux-specific. On a macOS/Windows Docker Desktop host the bridge IP is not
routable from the host, and you would need to publish ports instead.

## Docker inside the container (docker-in-docker)

The image ships the Docker engine, but the daemon is **not** started automatically. Start it on demand
from inside the tops session:

```shell
dockerd-start      # launches dockerd in the background and waits until it is ready
docker compose up  # docker / docker compose now work
dockerd-stop       # optional; the daemon is torn down anyway when the container exits
```

Because this is real docker-in-docker (not the host's daemon), `$(pwd)` and bind mounts refer to the
container's filesystem, so `docker compose` volumes that mount the repo work as expected.

Storage is **per session**: each container gets its own `/var/lib/docker` (an anonymous volume) that is
removed when the container exits, so several tops containers can run at once without clashing. Images and
built layers therefore do not persist between runs; to keep them, replace the anonymous `-v /var/lib/docker`
with a per-project named volume in `tops.m4`.

## IDE integration

Claude Code's IDE integration uses a local WebSocket server on `127.0.0.1` (an ephemeral port) plus a lock
file at `~/.claude/ide/<port>.lock`. The CLI and the IDE backend must share the same loopback interface.
Since the CLI runs inside this container, a host-side IDE cannot reach it (separate network namespace), and
mounting `~/.claude` is not enough on its own. The supported setups run the IDE backend **inside the
container** too:

- **JetBrains Gateway** — connect Gateway to the container (over SSH or Docker), install the Claude Code
  plugin on the remote host (inside the container), and run `claude` in the integrated terminal. This
  requires an SSH server in the image, which is not yet included.
- **Dev Containers** (VS Code or Gateway) — add a `.devcontainer/devcontainer.json` using the
  `ghcr.io/anthropics/devcontainer-features/claude-code` feature, then open the container and run `claude`
  in its integrated terminal.

The current "host IDE + containerized CLI" layout is not a supported configuration for IDE integration.

See: <https://code.claude.com/docs/en/jetbrains>, <https://code.claude.com/docs/en/vs-code>,
<https://code.claude.com/docs/en/devcontainer>.
