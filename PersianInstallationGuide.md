<div dir="rtl">
<h1>راهنمای نصب و راه اندازی به زبان فارسی</h1>
راهنمای نصب و راه اندازی پروکسی به زبان فارسی. 

<h2>نصب:</h2>
<h3>نصب وابستگی ها:</h3>

<li>در توزیع های برپایه دبیان:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>apt install git curl build-essential libssl-dev zlib1g-dev</pre></div>
<li>نصب در توزیع های بر پایه رد هت:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>yum install openssl-devel zlib-devel
yum groupinstall <span class="pl-s"><span class="pl-pds">"</span>Development Tools<span class="pl-pds">"</span></span></pre></div>
<li>:کلون کردن مخزن:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>git clone https://github.com/TelegramMessenger/MTProxy
<span class="pl-c1">cd</span> MTProxy</pre></div>
<li>کامپایل کردن (باینری ها در مسیر objs/bin/mtproto-proxy قرار میگیرند):</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>make <span class="pl-k">&amp;&amp;</span> <span class="pl-c1">cd</span> objs/bin</pre></div>
اگر make با شکست مواجه شد از دستور <code>make clean</code> استفاده کنید.

<h2>راه اندازی:</h2>

<li>دریافت یک سکرت، مورد استفاده برای اتصال به سرور تلگرام:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>curl -s https://core.telegram.org/getProxySecret -o proxy-secret</pre></div>
<li>دریافت تنظیمات فعلی تلگرام. (این تنظیمات ممکن است تغییر کنند، بنابراین بهتر است یک بار در روز بروزرسانی کنید)</li>
<div dir="ltr" class="highlight highlight-source-shell"><pre>curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf</pre></div>
<li>ساخت یک سکرت، مورد استفاده برای اتصال کاربران به پروکسی شما:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>head -c 16 /dev/urandom <span class="pl-k">|</span> xxd -ps</pre></div>
<li>اجرای پروکسی:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>./mtproto-proxy -u nobody -p 8888 -H 443 -S <span class="pl-k">&lt;</span>secret<span class="pl-k">&gt;</span> --aes-pwd proxy-secret proxy-multi.conf -M 1</pre></div>

راهنما:
<li><code>nobody</code> نام کاربری است، mt-proxy با استفاده از stupid امتیازات و وابستگی های آن را پاک میکند</li>
<li><code>8888</code> پورت داخلی شما است، شما میتوانید از آن برای دریافت اطلاعات پروکسی استفاده  کنید، مانند <code>wget localhost:8888/stats</code></li>
<li><code>433</code> پورتی است که کابران از طریق آن به پروکسی شما وصل میشوند.</li>
<li><code>secret</code> همان سکرتی است که در مرحله سه ساخته اید، شما همچنین میتوانید از چند سکرت استفاده کنید: <code dir="ltr">-S سکرت اول -S سکرت دوم</code></li>
<li><code>proxy-secret</code> و <code>proxy-multi.conf</code> در مراحل اول و دوم دریافت شدند.</li>
<li><code>1</code> تعداد کارگران است. اگر شما یک سرور قدرت مند دارید میتوانید تعداد کارگران را افزایش دهید.</li>

همچنین شما میتوانید از دستور <code dir="ltr">mtproto-proxy --help</code> .برای دیدن دیگر گزینه ها استفاده کنید.

<li>لینک را طبق این الگو بسازید: <code dir="ltr">tg://proxy?server=دامنه یا ایپی سرور&port=پورت&secret=سکرت</code></li>
<li>پروکسی خود را توسط ربات <code dir="ltr">@MtProxybot</code> ثبت کنید.</li>
<li>تگ دریافت شده را با این سویچ تنظیم کنید: <code dir="ltr">-P تگ</code></li>

<h2>پد تصادفی:</h2>

برخی از سرویس دهنده ها پروکسی هارا از طریق اندازه بسته ها پیدا میکنند، اگر چنین حالتی فعال باشد پد تصادفی به بسته ها اضافه میشود
این تنها برای کاربران با درخواست آنها فعال میشود
با اضافه کردن <code>dd</code> به ابتدای سکرت

<h2>پیکر بندی saystemd:</h2>

<li>ساخت فایل سرویس:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>nano /etc/systemd/system/MTProxy.service</pre></div>
<li>ویرایش سرویس پایه:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>[Unit]
Description=MTProxy
After=network.target
[Service]
Type=simple
WorkingDirectory=/opt/MTProxy
ExecStart=/opt/MTProxy/mtproto-proxy -u nobody -p 8888 -H 443 -S <span class="pl-k">&lt;</span>secret<span class="pl-k">&gt;</span> -P <span class="pl-k">&lt;</span>proxy tag<span class="pl-k">&gt;</span> <span class="pl-k">&lt;</span>other params<span class="pl-k">&gt;</span>
Restart=on-failure

[Install]
WantedBy=multi-user.target</pre></div>
<li>تست کردن سرویس</li>
<div dir="ltr" class="highlight highlight-source-shell"><pre>systemctl restart MTProxy.service
<span class="pl-c"><span class="pl-c">#</span> برسی وضعیت</span>
systemctl status MTProxy.service</pre></div>
<li>قرار دادن سرویس در autorun:</li>

<div dir="ltr" class="highlight highlight-source-shell"><pre>systemctl <span class="pl-c1">enable</span> 
MTProxy.service</pre></div>
</div>
