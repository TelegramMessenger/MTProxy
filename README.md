# MTProxy
To build, simply run `make`. Your binary will be in `objs/bin/mtproto-proxy`. If build was failed, you would do `make clear` at first, before building it again.

To run `mtproto-proxy`:
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
mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> --aes-pwd proxy-secret proxy-multi.conf -M 1
```
... where:
- `nobody` is the username. `mtproto-proxy` calls `setuid()` to drop privilegies.
- `443` is the port, used by clients to connect to the proxy.
- `8888` is the local port. You can use it to get statistics from `mtproto-proxy`. Like `wget localhost:8888/stats`. You can only get this stat via loopback.
- `<secret>` is the secret generated at step 3. 
- `proxy-secret` and `proxy-multi.conf` are obtained at steps 1 and 2.
- `1` is the number of workers. You can increase the number of workers, if you have a powerful server.
- also feel free to check out other options using `mtproto-proxy --help`.
5. Generate the link with followed schema: `tg://proxy?server=SERVER_NAME&port=443&secret=SECRET` (by the way official bot provides links anyway).
6. Register your proxy with [@MTProxybot](https://t.me/MTProxybot) on Telegram.
7. Enjoy.
