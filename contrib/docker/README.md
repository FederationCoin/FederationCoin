
# 🚀 FederationCoin Docker Image (Headless Node)

This Dockerfile builds and runs a **FederationCoin** full node from source.

## 🧱 Features

* Stripped of all non-essential components (tests, debug data, documentation, etc.)
* Data directory persisted via volume
* Accessible via RPC

---

## 📦 Build the Docker Image

**make sure you're at the root of the repo first!**

```bash
docker build \
  -f contrib/docker/Dockerfile \
  -t federationcoin \
  --build-arg USER_ID=$(id -u) \
  --build-arg GROUP_ID=$(id -g) \
  --load .
```

---

## ▶️ Run the Node

```bash
docker run -d \
  --init \
  --user $(id -u):$(id -g) \
  --name federationcoin \
  -p 8333:8333 -p 127.0.0.1:8332:8332 \
  -v path/to/conf:/etc/federationcoin/federationcoin.conf:ro \
  -v path/to/data:/var/lib/federationcoind:rw \
  federationcoin
```

In case you want to use ZeroMQ sockets, make sure to expose those ports as well by adding `-p host_port:container_port` directives to the command above.
In case `path/to/data` is not writable by your user, consider overriding the `--user` flag.

This will:

* Start the node in the background
* Save the blockchain and config in `/path/to/data`
* Expose peer and RPC ports

---

## 📊 Check Node Status

```bash
docker logs federationcoin
```

---

## 🛑 Stop the Node

```bash
docker stop federationcoin
```

---
