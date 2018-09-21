# ScurityEncrypt
常用加密算法（对称和非对称）案例实现
## 对称加密：
##### 1.采用单钥密码系统的加密方法，同一个密钥可以同时用作信息的加密和解密，这种加密方法称为对称加密，也称为单密钥加密。
##### 2.在对称加密算法中常用的算法有：DES、3DES、TDEA、Blowfish、RC2、RC4、RC5、IDEA、SKIPJACK、AES等。
### 缺点：
对称加密算法的缺点是在数据传送前，发送方和接收方必须商定好秘钥，然后使双方都能保存好秘钥。其实如果一方的秘钥被泄露，
那么加密信息也就不安全了。另外每个用户每次使用的对称加密算法时，都需要使用其他人都不知道的唯一秘钥，这会使得收发双方所拥有的钥匙
数量巨大，秘钥管理成为双方负担

## 非对称加密：
##### 1.需要两个秘钥来进行加密和解密，两个秘钥是公开秘钥和私有秘钥，
##### 2.过程（引用维基百科）：
###### 2.1：爱丽丝与鲍伯事先互不认识，也没有可靠安全的沟通渠道，但爱丽丝现在却要透过不安全的互联网向鲍伯发送信息
###### 2.2：爱丽丝撰写好原文，原文在未加密的状态下称之为明文 x
###### 2.3：鲍伯使用密码学安全伪随机数生成器产生一对密钥，其中一个作为公钥为  c，另一个作为私钥 d
###### 2.4：鲍伯可以用任何方法发送公钥 c 给爱丽丝，即使伊夫在中间窃听到 c 也没问题
###### 2.5：爱丽丝用公钥 c 把明文 x 进行加密，得到密文 c(x)
###### 2.6：爱丽丝可以用任何方法传输密文  c(x) 给鲍伯，即使伊夫在中间窃听到密文 c(x) 也没问题
###### 2.7：鲍伯收到密文，用私钥 d 对密文进行解密 d(c(x))}，得到爱丽丝撰写的明文  x
###### 2.8：由于伊夫没有得到鲍伯的私钥 d，所以无法得知明文 x
###### 2.9：如果爱丽丝丢失了她自己撰写的原文 x，在没有得到鲍伯的私钥 d 的情况下，她的处境将等同伊夫，即无法透过鲍伯的公钥 c 和密文 c(x) 重新得到原文 x
##### 3.常见算法实现：RSA、Elgamal、背包算法、Rabin、D-H、ECC等
### 缺点：
加密和解密花费时间长、速度慢，只适合对少量数据进行加密。