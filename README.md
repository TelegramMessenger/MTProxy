# MTProxy
Simple MT-Proto proxy

## Building
Install dependencies, you would need common set of tools for building from source, and development packages for `openssl` and `zlib`.

On Debian/Ubuntu:
```bash
apt install git curl build-essential libssl-dev zlib1g-dev
```
On CentOS/RHEL:
```bash
yum install openssl-devel zlib-devel
yum groupinstall "Development Tools"
```

Clone the repo:
```bash
git clone https://github.com/TelegramMessenger/MTProxy
cd MTProxy
```

To build, simply run `make`, the binary will be in `objs/bin/mtproto-proxy`:

```bash
make && cd objs/bin
```

If the build has failed, you should run `make clean` before building it again.

## Running
1. Obtain a secret, used to connect to telegram servers.
```bash
curl -s https://core.telegram.org/getProxySecret -o proxy-secret
```
2. Obtain current telegram configuration. It can change (occasionally), so we encourage you to update it once per day.
```bash
curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
```
3. Generate a secret to be used by users to connect to your proxy.
```bash
head -c 16 /dev/urandom | xxd -ps
```
4. Run `mtproto-proxy`:
```bash
./mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> --aes-pwd proxy-secret proxy-multi.conf -M 1
```
... where:
- `nobody` is the username. `mtproto-proxy` calls `setuid()` to drop privilegies.
- `443` is the port, used by clients to connect to the proxy.
- `8888` is the local port. You can use it to get statistics from `mtproto-proxy`. Like `wget localhost:8888/stats`. You can only get this stat via loopback.
- `<secret>` is the secret generated at step 3. Also you can set multiple secrets: `-S <secret1> -S <secret2>`.
- `proxy-secret` and `proxy-multi.conf` are obtained at steps 1 and 2.
- `1` is the number of workers. You can increase the number of workers, if you have a powerful server.

Also feel free to check out other options using `mtproto-proxy --help`.

5. Generate the link with following schema: `tg://proxy?server=SERVER_NAME&port=PORT&secret=SECRET` (or let the official bot generate it for you).
6. Register your proxy with [@MTProxybot](https://t.me/MTProxybot) on Telegram.
7. Set received tag with arguments: `-P <proxy tag>`
8. Enjoy.

## Random padding
Due to some ISPs detecting MTProxy by packet sizes, random padding is
added to packets if such mode is enabled.

It's only enabled for clients which request it.

Add `dd` prefix to secret (`cafe...babe` => `ddcafe...babe`) to enable
this mode on client side.

Adding argument "-R" to the command line will cause MTProxy to allow connections only from the clients with random padding mode enabled.

## Systemd example configuration
1. Create systemd service file (it's standard path for the most Linux distros, but you should check it before):
```bash
nano /etc/systemd/system/MTProxy.service
```
2. Edit this basic service (especially paths and params):
```bash
[Unit]
Description=MTProxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/MTProxy
ExecStart=/opt/MTProxy/mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> -P <proxy tag> <other params>
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
3. Reload daemons:
```bash
systemctl daemon-reload
```
4. Test fresh MTProxy service:
```bash
systemctl restart MTProxy.service
# Check status, it should be active
systemctl status MTProxy.service
```
5. Enable it, to autostart service after reboot:
```bash
systemctl enable MTProxy.service
```

## Docker image
Telegram is also providing [official Docker image](https://hub.docker.com/r/telegrammessenger/proxy/).
Note: the image is outdated.
