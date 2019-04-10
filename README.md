# ngFish

ngFish is a Hexchat plugin that provides OTR encryption using Twofish in CBC mode.

Advantages over FiSHLiM bundled into HexChat:

  - Twofish-CBC instead of Blowfish-ECB
  - 256-bit key using SHA2
  - Solid against common cryptanalysis
  - We do not reimplement cryptography
  - No bug relatively large utf-8 messages using non-latin characters. 
  - Any size data will be transmitted consistently without garbling.

## Quick comparisson

#### Improved cryptanalysis resistance

**Weak using FiSHLiM:**

_user1 computer:_
```
<user1> Hello
<user1> Hello
<user1> Hello
<user1> Hi
<user1> Hi
<user1> The quick brown fox jumps over the lazy dog
<user1> The quick brown fox jumps over the lazy dog
```
_user2 computer (no key):_
```
<user1> +OK pAsQN1QWoa2/
<user1> +OK pAsQN1QWoa2/
<user1> +OK pAsQN1QWoa2/
<user1> +OK 87IfN1w/vhE.
<user1> +OK 87IfN1w/vhE.
<user1> +OK f6yNE0ePcjK/sSs8T.rPP.j/RBLPp0YsLKR0iBX1m1hVFXg1Osi5c1M4yyj1Pknw./SB5Ic/
<user1> +OK f6yNE0ePcjK/sSs8T.rPP.j/RBLPp0YsLKR0iBX1m1hVFXg1Osi5c1M4yyj1Pknw./SB5Ic/
```



**Strong using ngFish:**

_user1 computer:_
```
<user1> Hello
<user1> Hello
<user1> Hello
<user1> Hi
<user1> Hi
<user1> The quick brown fox jumps over the lazy dog
<user1> The quick brown fox jumps over the lazy dog
```
_user2 computer (no key):_
```
<user1> +ОK dg5zYop37XT77CW4YSi2vGSO2ibbwIZSWx4h5gW9DTc
<user1> +ОK uJ7xcOaM9eWkW8eVdnj18T/AzLRtF4wqfXU3K+o6Xdw
<user1> +ОK mHUtOQzznqlHJGE0loAPdOLqjh7XVYOnGoHm1H9VDSQ
<user1> +ОK HWmMJcOdY07IGebJ+7VA0FUG3OGeIqQC36hMEBwV+K8
<user1> +ОK 4TBQJU7i1FfprAQf2D5tLTRdRWRpcJmGxvfHWbz1Y4Y
<user1> +ОK /FfhwRGOSX1c3b86+RAcgB6f5jGzsahtYPJjG4BnyaFrrLMAORhCyFVUjbc/1uo32wmb8njrJ7ma\zWfZH2ogHA
<user1> +ОK Ec7ptBikfqyNLyyl1wZdZilfuIVOLWKx0beHTl6jWl5jDKKYRSKPWPGbn9t4e1Y79oiC0bLY3OMX\bK+P+5H0Gw
```

#### Proper message length handling & No data corruption
**Corrupted using FiSHLiM:**

user1 computer:
```
<user1> Дотогава единствената сериозна алтернатива за нетехнически потребители е било KDE. Но KDE е базирано на Qt библиотеките на Trolltech – софтуер, който не ползва лиценз за свободен софтуер и е несъвместим с GNU General Public License (GPL). Този проблем е частично решен с освобождаването на Qt под Q Public License (QPL) – лиценз за свободен софтуер, но все още несъвместим с GPL; и накрая е решено Qt да бъде реализиран и под QPL и под GPL. Подход, известен като двоен лиценз.
```
user2 computer:
```
<user1> Дотогава единствената сериозна алтернатива за нетехнически потребители е било KDE. Но KDE е базирано на Qt библиотеките на Trolltech – софтуер, който не ползва лиценз за 
```

**Consistent using ngFish:**

user1 computer:
```
<user1> Дотогава единствената сериозна алтернатива за нетехнически потребители е било KDE. Но KDE е базирано на Qt библиотеките на Trolltech – софтуер, който не ползва лиценз за свободен софтуер и е несъвместим с GNU General Public License (GPL). Този проблем е частично решен с освобождаването на Qt под Q Public License (QPL) – лиценз за свободен софтуер, но все още несъвместим с GPL; и накрая е решено Qt да бъде реализиран и под QPL и под GPL. Подход, известен като двоен лиценз.
```
user2 computer:
```
<user1> Дотогава единствената сериозна алтернатива за нетехнически потребители е било KDE. Но KDE е базирано на Qt библиотеките на Trolltech – софтуер, който не ползва 
<user1> лиценз за свободен софтуер и е несъвместим с GNU General Public License (GPL). Този проблем е частично решен с освобождаването на Qt под Q Public License (QPL)
<user1>  – лиценз за свободен софтуер, но все още несъвместим с GPL; и накрая е решено Qt да бъде реализиран и под QPL и под GPL. Подход, известен като двоен лиценз.
```

## Commands & Usage


| Command | Description |
| ------ | ------ |
| setkey [<nick or #channel>] &lt;password&gt; | sets the key for a channel or nick |
| delkey &lt;nick or #channel> | deletes the key for a channel or nick |
| notice+ &lt;nick or #channel> &lt;notice> | sends an encrypted notice to a channel or nick |
| msg+ &lt;nick or #channel> &lt;message> | sends an encrypted message to a channel or nick |
| me &lt;message> | sends an encrypted action if the key is present in the current context  |
| topic+ &lt;topic> | sets a new encrypted topic for the current channel |

Every above command should be prefixed with '/ng' when the FiSHLiM plugin is present (compatibility mode)

It is strongly recommended to change the config encryption password upon first usage, find it here:
```perl
# config encryption password encoded in hex, you must change it before the first use
	CP => '0344ed6c3830fbe3f292ca8f82df',
```

## Fast dependencies (Crypt::Twofish, Crypt::CBC)

 -- Debian/Ubuntu: 
```
# apt install libcrypt-twofish-perl libcrypt-cbc-perl 
```
-- RHEL/CentOS:
```
# yum install perl-Crypt-Twofish perl-Crypt-CBC 
```
-- CPAN (no root required)
```
$ cpan -i Crypt::Twofish Crypt::CBC
```
