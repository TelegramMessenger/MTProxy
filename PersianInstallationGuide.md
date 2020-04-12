<div dir="rlt">
<h1>راهنمای نصب و راه اندازی به زبان فارسی</h1>
راهنمای نصب و راه اندازی پروکسی به زبان فارسی 

<h2>نصب</h2>
<h3>نصب وابستگی ها</h3>
<li>در توزیع های برپایه دبیان:</li>
<div dir="ltr" class="highlight highlight-source-shell"><pre>apt install git curl build-essential libssl-dev zlib1g-dev</pre></div>
<li>نصب در توزیع های بر پایه رد هت</li>
<div dir="ltr" class="highlight highlight-source-shell"><pre>yum install openssl-devel zlib-devel
yum groupinstall <span class="pl-s"><span class="pl-pds">"</span>Development Tools<span class="pl-pds">"</span></span></pre></div>
<li>کلون کردن مخزن:</li>
<div dir="ltr" class="highlight highlight-source-shell"><pre>git clone https://github.com/TelegramMessenger/MTProxy
<span class="pl-c1">cd</span> MTProxy</pre></div>
<li>کامپایل کردن (باینری ها در مسیر objs/bin/mtproto-proxy قرار میگیرند)</li>
<div dir="ltr" class="highlight highlight-source-shell"><pre>make <span class="pl-k">&amp;&amp;</span> <span class="pl-c1">cd</span> objs/bin</pre></div>
اگر make با شکست مواجه شد از دستور <code>make clean</code> استفاده کنید

<h2>راه اندازی</h2>
<li>دریافت یک سکرت، مورد استفاده برای اتصال به سرور تلگرام</li>
<div class="highlight highlight-source-shell"><pre>curl -s https://core.telegram.org/getProxySecret -o proxy-secret</pre></div>
<li>دریافت تنظیمات فعلی تلگرام. (این تنظیمات ممکن است تغییر کنند، بنابراین بهتر است یک بار در روز بروزرسانی کنید)</li>
<div class="highlight highlight-source-shell"><pre>curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf</pre></div>
<li>ساخت یک سکرت، مورد استفاده برای اتصال کاربران به پروکسی شما</li>
<div class="highlight highlight-source-shell"><pre>head -c 16 /dev/urandom <span class="pl-k">|</span> xxd -ps</pre></div>
<li>اجرای پروکسی</li>
<div class="highlight highlight-source-shell"><pre>./mtproto-proxy -u nobody -p 8888 -H 443 -S <span class="pl-k">&lt;</span>secret<span class="pl-k">&gt;</span> --aes-pwd proxy-secret proxy-multi.conf -M 1</pre></div>
