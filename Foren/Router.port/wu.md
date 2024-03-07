## Router |port|

### Des : 

![image](https://github.com/KMANVK/vishwactf-2024/assets/94669750/32d9693b-f6b3-4984-b4c8-85e6f142b35a)

### Sol : 

+ Phân tích file bằng wireshark + mô tả đề bài nhận thấy điều bất thường ở các packet liên quan đến protocol `DAYTIME` 

![image](https://github.com/KMANVK/vishwactf-2024/assets/94669750/2043165d-1064-4366-8974-9d12e19f6af8)


+ Dùng tshark extract các data này ra : `$ tshark -r Capture.pcapng -Tfields -Y "daytime" -e`

![image](https://github.com/KMANVK/vishwactf-2024/assets/94669750/827b245d-6c1f-436f-bf0c-333adfb0f732)

=> Decode caeser mình nhận được đoạn chat : 

```
Hey, mate!
Yo, long time no see!
You sure this mode of communication is still safe?
Yeah, unless someone else is capturing network packets on the same network we're using. Anyhow, our text is encrypted, and it would be difficult to interpret.
So let's hope no one else is capturing.
What's so confidential that you're about to share?
It's about cracking the password of a person with the username 'Anonymous.'
Oh wait! Don't you know I'm not so good at password cracking?
Yeah, I know, but it's not about cracking. It's about the analysis of packets. I've completed most of the job, even figured out a way to get the session key to decrypt and decompress the packets.
Holy cow! How in the world did you manage to get this key from his device?
Firstly, I hacked the router of our institute and closely monitored the traffic, waiting for 'Anonymous' to download some software that requires admin privilege to install. Once he started the download, I, with complete control of the router, replaced the incoming packets with the ones I created containing malicious scripts, and thus gained a backdoor access to his device. The further job was a piece of cake.
Whoa! It's so surprising to see how much you know about networking or hacking, to be specific.
Yeah, I did a lot of research on that. Now, should we focus on the purpose of this meet?
Yes, of course. So, what should I do for you?
Have you started the packet capture as I told you earlier?
Yes, I did.
Great! I will be sending his SSL key, so find the password of 'Anonymous.'
Yes, I would, but I need some details like where to start.
The only details I have are he uses the same password for every website, and he just went on to register for a CTF event.
Okay, I will search for it.
Wait a second, I won't be sending the SSL key on this Daytime Protocol port; we need to keep this untraceable.
I will be sending it through FTP. Since the file is too large, I will be sending it in two parts. Please remember to merge them before using it. Additionally, some changes may be made to it during transfer due to the method I'm using. Ensure that you handle these issues.
Okay! ...
```


+ Đoạn chat có đề cập đến password của user `Anonymous` nhưng không đi crack để tìm mà dựa vào ssl key. Và nó được chia làm 2 phần do quá dài nằm trong protocol `FTP-DATA` 

+ Đến đây mình extract data của 2 packets FTP này ra :  

![image](https://github.com/KMANVK/vishwactf-2024/assets/94669750/efc74f7e-9ef9-420e-a675-e372b5647fed)


![image](https://github.com/KMANVK/vishwactf-2024/assets/94669750/6fdbced2-aa9a-423e-8427-bf2ad7aec359)


+ Khi ghép chúng lại thành sslkey log thì vẫn chưa thể import vào file pcap được vì nó đã bị mã hóa caeser => viết kịch bản để giải mã nó : 

```
from string import ascii_uppercase

def Caeser(c):
    s = ''
    for i in range(len(c)):
        if c[i].isupper():
            s += chr((ord(c[i]) - 6 - 65) % 26 + ord('A'))
        elif c[i].islower():
            s += chr((ord(c[i]) - 6 - ord('a')) % 26 + ord('a'))
        else:
            s += c[i]
    return s 

f = open('ssl-keylog.txt', 'r').read()
li = f.split('\n')
res = ''
for i in li:
    res += Caeser(i.split(' ')[0]) + ' ' + Caeser(i.split(' ')[1]) + ' ' + Caeser(i.split(' ')[2])
    res += '\n'

f = open('sslkey.log', 'w').write(res)
```

+ oke bây giờ mình sẽ import file `sslkey.log` vào wireshark và phân tích tiếp. 

+ Ở đây thấy khá nhiều protocols HTTP2 xuất hiện => dùng strings grep pass để xem có gì không? 

![image](https://github.com/KMANVK/vishwactf-2024/assets/94669750/08a40520-909f-4a68-a6f2-160ab332f890)


+ Và mình tìm được pass of user `Anonymous` : `{"username":"Anonymous","password":"K3Y5_CAN_0P3N_10CK5"}`

![image](https://github.com/KMANVK/vishwactf-2024/assets/94669750/b184407b-143f-46aa-8550-3e6c6ce1aa9b)

### Flag : `VishwaCTF{K3Y5_CAN_0P3N_10CK5}`
