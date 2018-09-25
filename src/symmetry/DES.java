package symmetry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import java.security.SecureRandom;
import java.util.stream.IntStream;

/**
 * @date: 2018/09/10 14:16
 * @description:
 */
public class DES {
    public static String messageData = "Hello world!";
    public static String password = "MIICWgIBAAKBgGK8b6Z0GfdDWotbenUpEKYKFcHZYDnBc8V9oED5SJSCzFHZXfOp\n" +
            "ksFyadPCKYWJVv56eu3YTf0A51PjaxKQVyrbIWs/So2SmmEwVl9YHv0B44md3dl0\n" +
            "RpcHu+jIXKJP94DyiDlmbMW4lq1DF+ZVGf4x/uyyc1xDp/ZAXsvuB8P/AgMBAAEC\n" +
            "gYAEe8oWJO+I6uYRrfXBnDvFTm/ufZCBDufS8AF28dr543ajwNsjVW/0mN11YDvC\n" +
            "dJoetDEg29Guy3u1s34JOcS7fvu5aaaqbQ5mR3OccQOGsoykoPJucQEyDypmH5e3\n" +
            "LMmxWQd7dCRTQRMZyvaXShu3OX/+4cdRw2yP800jLY/9AQJBAKwuXoor11PloO7C\n" +
            "V0CO1Ry3TU3cF510chypHKDcd16xYaB4tKNd4L2v43eIKMp6kBKeVrwY3vhpxRg6\n" +
            "o0lK7GUCQQCSzSqGUUkxj02EKxg12HBRndrMpZhA1KIibo68VOs+RkhgcNp4wS7W\n" +
            "keV9E6z3GG8M3RyxALjty6pJbIwyOo6TAkBdrpUNxLDSGxynC+KBY7WcfDd5Z4kJ\n" +
            "yLPV2EWVWJ8yTHz73PEb+hYv3yV6ggD/uhPtrW0vxrB6pMHyXuU9GaDpAkBLQ/eW\n" +
            "kByH1WI37mRmTwcfQWDJ5ekO7DYIk0iJVLyb3CsFjzbkDJ/4EStpGmpm8dcV8FPi\n" +
            "iG1INlCjfozOv+kTAkAn1RL5ZSpAw4Y6HktiCrWiW+HMs4c8Bkk7i/bwV7ZBzYxy\n" +
            "E/+ejz2yLkQJ6yMERshyp7noYiy0JPBco58qfIl5";

    public static void main(String[] args) {
        Long start = System.currentTimeMillis();
        IntStream.range(0,1).forEach(item->{
            String str = decrypt(encrypt(messageData, password),password);
            System.out.println(str);
        });
        Long startEnd = System.currentTimeMillis() - start;
        System.out.println(startEnd);


        Long start1 = System.currentTimeMillis();
        IntStream.range(0,10000).forEach(item->{
            encrypt(messageData, password);
            //System.out.println(str);
        });
        Long startEnd1 = System.currentTimeMillis() - start1;
        System.out.println(startEnd1);
    }

    /***
     * 数据加密
     * @param content
     * @param key
     * @return
     */
    public static byte[] encrypt(String content, String key) {
        try {
            SecureRandom random = new SecureRandom();
            DESKeySpec keySpec = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, random);
            byte[] result = cipher.doFinal(content.getBytes());
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     *
     * @param content 待解密内容
     * @param key     解密的密钥
     * @return
     */
    public static String decrypt(byte[] content, String key) {
        try {
            SecureRandom random = new SecureRandom();
            DESKeySpec desKey = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey securekey = keyFactory.generateSecret(desKey);
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, securekey, random);
            byte[] result = cipher.doFinal(content);
            return new String(result);
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return null;

    }
}