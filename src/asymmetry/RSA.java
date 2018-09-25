package asymmetry;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.stream.IntStream;

/**
 * @author: Cola
 * @date: 2018/09/09 20:27
 * @description: 非对称加密算法，使用RSA算法
 */
public class RSA {

    public  static String messageData = "Hello world!";
    public static void main(String[] args) {
        //RSA();



        Long start = System.currentTimeMillis();
        IntStream.range(0,10000).forEach(item->{
                RSATest();
        });
        Long startEnd = System.currentTimeMillis() - start;
        System.out.println(startEnd);

    }

    /**
     * 使用JDK提供的RSA算法
     * 1:比喻支付环节，商户拥有公钥和私钥，第三方平台只有公钥（商户提供）
     * 2:商户在发送数据时使用私钥加密传输给第三方平台，第三方利用公钥解密数据等到可视化数据
     * 3:第三方平台利用公钥加密数据传送给商户，商户利用私钥解密
     */
    public static void RSA(){
        try {
            //1：获取RSA实例对象
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            //指定生成秘钥的长度
            keyPairGenerator.initialize(1024);
            //2：获取publickey 和  privateKey
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();

            System.out.println("RSA算法公钥："+ Base64.encode(rsaPublicKey.getEncoded()));
            System.out.println("RSA算法私钥："+ Base64.encode(rsaPrivateKey.getEncoded()));
            //3: 使用私钥加密数据（公钥解密数据）
            Cipher cipher1 = Cipher.getInstance("RSA");
            cipher1.init(Cipher.ENCRYPT_MODE,keyPair.getPrivate());
            byte[] result = cipher1.doFinal(messageData.getBytes());
            System.out.println("原字符串：" + messageData + "加密后的结果:" + Base64.encode(result));

            //4: 使用公钥解密数据（公钥解密数据）
            Cipher cipher2 = Cipher.getInstance("RSA");
            cipher2.init(Cipher.DECRYPT_MODE,keyPair.getPublic());
            byte[] result2 = cipher2.doFinal(result);
            System.out.println("原字符串：" + messageData + "加密后的结果:" + new String(result2));

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void RSATest(){
        //公钥
        String publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGXtK72cU1Vfspu7TzHMGwwu40VwNQwP5+q1PZ\n" +
                "6VWpUYELYm6fLWcNctAJvPlAT7f06o+7oRw5gbMej9o4lmcYa4Ff6Nw0APTqdzDZqh94obMTvZJZ\n" +
                "xkr91OquLzDE94YTCntcdDwJi5fymKoowr8V2HkEfzjBOkS2x7VCDxplDwIDAQAB";
        //私钥
        String privateKeyStr = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIZe0rvZxTVV+ym7tPMcwbDC7jRX\n" +
                "A1DA/n6rU9npValRgQtibp8tZw1y0Am8+UBPt/Tqj7uhHDmBsx6P2jiWZxhrgV/o3DQA9Op3MNmq\n" +
                "H3ihsxO9klnGSv3U6q4vMMT3hhMKe1x0PAmLl/KYqijCvxXYeQR/OME6RLbHtUIPGmUPAgMBAAEC\n" +
                "gYAArCjR190szylapB3buaEeiVs319ekZ9LeP21EAe7z0fybWfrDwS5q2tA/vDpjIAMDrsjZX40M\n" +
                "nKGQ3ZdyAQ6zBrqoCUqLawi6inG+IiSSZyk4Ic1WhwReP3QaoZiAQcVLGZNR84hkSa1rFS023rAX\n" +
                "5Fx1gSKyNaYfgOAeaerDAQJBAMSArg4vH6Fr6aozUSMhJSolUuJIm26bO47UmyHXnhbZffyl+wl3\n" +
                "q61RiuQqgTU5VA2aGFI4X7fCtpPj70jjjV8CQQCvDiVoRYBoyVW9KMotd6f32TtgYnZCseTBIO9i\n" +
                "UXZGfRLQoK09OyQO5QgFcAIqbePHeZBlCkIFXsKLhvOG25ZRAkB/0cxmgZSrpcxa4AKZPUg1gA3I\n" +
                "D767VdKJ+BXpD55P8q2XGEiRQfy0QuR7woJFosLgDipf4TeyCsBEtvHBkfM1AkEAok0BTa2yonSY\n" +
                "s6qP2Jvp9ZdIv9JKRwfcSVsZ1xQkDrKDsT5noC+m/NBIIZJ5z5DW8Oi6gZODJqt2wBo8yznoIQJB\n" +
                "AJtu0DI5zTqWvbPlDxhT3E0BA1WCpDgeDMpZ6vhlcl2V8knK3d/XoY6vR2hRVpm8S3LkK1i+YVhL\n" +
                "zMOy++GlLW8=";

        try {
            byte[] publicKeyBytes = Base64.decode(publicKeyStr);

            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpecPublic);

            byte[] privateKeyBytes = (new BASE64Decoder()).decodeBuffer(privateKeyStr);
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpecPrivate);


            //3: 使用私钥加密数据（公钥解密数据）
            Cipher cipher1 = Cipher.getInstance("RSA");
            cipher1.init(Cipher.ENCRYPT_MODE,privateKey);
            byte[] result = cipher1.doFinal(messageData.getBytes());
            //System.out.println("原字符串：" + messageData + "加密后的结果:" + Base64.encode(result));

            //4: 使用公钥解密数据（公钥解密数据）
            Cipher cipher2 = Cipher.getInstance("RSA");
            cipher2.init(Cipher.DECRYPT_MODE,publicKey);
            byte[] result2 = cipher2.doFinal(result);
            //System.out.println("原字符串：" + messageData + "加密后的结果:" + new String(result2));

        }catch (Exception e){
            e.printStackTrace();
        }

    }
}
