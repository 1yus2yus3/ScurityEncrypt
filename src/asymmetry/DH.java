package asymmetry;
 
import com.sun.org.apache.xml.internal.security.utils.Base64;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/****
 *  -Djdk.crypto.KeyAgreement.legacyKDF=true 指定JDK运行参数
 */
public abstract class DH {
    /**
     * 非对称加密密钥算法
     */
	private static final String KEY_ALGORITHM = "DH";
    /**
     * 本地密钥算法，即对称加密密钥算法
     * 可选DES、DESede或者AES
     */
	private static final String SELECT_ALGORITHM = "AES";
	/**
	 * 密钥长度
	 */
	private static final int KEY_SIZE = 512;
	//公钥
	private static final String PUBLIC_KEY = "DHPublicKey";
	//私钥
	private static final String PRIVATE_KEY = "DHPrivateKey";
	
	/**
	 * 初始化甲方密钥
	 * @return Map 甲方密钥Map
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception{
		//实例化密钥对生成器
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		//初始化密钥对生成器
		keyPairGenerator.initialize(KEY_SIZE);
		//生成密钥对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		//甲方公钥
		DHPublicKey publicKey = (DHPublicKey)keyPair.getPublic();
		//甲方私钥
		DHPrivateKey privateKey = (DHPrivateKey)keyPair.getPrivate();
		//将密钥对存储在Map中
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	/**
	 * 初始化乙方密钥
	 * @param key 甲方公钥
	 * @return Map 乙方密钥Map
	 * @throws Exception
	 */
	public static Map<String, Object> initKey(byte[] key) throws Exception{
		//解析甲方公钥
		//转换公钥材料
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);
		//实例化密钥工厂
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		//产生公钥
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
		//由甲方公钥构建乙方密钥
		DHParameterSpec dhParameterSpec = ((DHPublicKey)pubKey).getParams();
		//实例化密钥对生成器
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		//初始化密钥对生成器
		keyPairGenerator.initialize(KEY_SIZE);
		//产生密钥对
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		//乙方公钥
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		//乙方私约
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		//将密钥对存储在Map中
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	/**
	 * 加密
	 * @param data 待加密数据
	 * @param key 密钥
	 * @return byte[] 加密数据
	 * @throws Exception
	 */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception{
    	//生成本地密钥
    	SecretKey secretKey = new SecretKeySpec(key, SELECT_ALGORITHM);
    	//数据加密
    	Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
    	cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    	return cipher.doFinal(data);
    }
    
    /**
     * 解密
     * @param data 待解密数据
     * @param key 密钥
     * @return byte[] 解密数据
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception{
    	//生成本地密钥
    	SecretKey secretKey = new SecretKeySpec(key, SELECT_ALGORITHM);
    	//数据揭秘
    	Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
    	cipher.init(Cipher.DECRYPT_MODE, secretKey);
    	return cipher.doFinal(data);
    }
    
    /**
     * 构建密钥
     * @param publicKey 公钥
     * @param privateKey 私钥
     * @return byte[] 本地密钥
     * @throws Exception
     */
    public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey) throws Exception{
    	//实例化密钥工厂
    	KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    	//初始化公钥
    	//密钥材料转换
    	X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
    	//产生公钥
    	PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
    	//初始化私钥
    	//密钥材料转换
    	PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);
    	//产生私钥
    	PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
    	//实例化
    	KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory.getAlgorithm());
    	//初始化
    	keyAgree.init(priKey);
    	keyAgree.doPhase(pubKey, true);
    	//生成本地密钥
    	SecretKey secretKey = keyAgree.generateSecret(SELECT_ALGORITHM);
    	return secretKey.getEncoded();
    }
    
    /**
     * 取得私钥
     * @param keyMap 密钥Map
     * @return byte[] 私钥
     * @throws Exception
     */
    public static byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception{
    	Key key = (Key) keyMap.get(PRIVATE_KEY);
    	return key.getEncoded();
    }
    
    /**
     * 取得公钥
     * @param keyMap 密钥Map
     * @return byte[] 公钥
     * @throws Exception
     */
    public static byte[] getPublicKey(Map<String, Object> keyMap) throws Exception{
    	Key key = (Key) keyMap.get(PUBLIC_KEY);
    	return key.getEncoded();
    }


	//甲方公钥
	private static byte[] publicKey1;
	//甲方私钥
	private static byte[] privateKey1;
	//甲方本地密钥
	private static byte[] key1;
	//乙方公钥
	private static byte[] publicKey2;
	//乙方私钥
	private static byte[] privateKey2;
	//乙方本地密钥
	private static byte[] key2;

	/**
	 * 初始化密钥
	 * @throws Exception
	 */
	public static final void initKeyDH() throws Exception{
		//生成甲方密钥对
		Map<String, Object> keyMap1 = DH.initKey();
		publicKey1 = DH.getPublicKey(keyMap1);
		privateKey1 = DH.getPrivateKey(keyMap1);
		System.out.println("甲方公钥:\n" + Base64.encode(publicKey1));
		System.out.println("甲方私钥:\n" + Base64.encode(privateKey1));
		//由甲方公钥产生本地密钥对
		Map<String, Object> keyMap2 = DH.initKey(publicKey1);
		publicKey2 = DH.getPublicKey(keyMap2);
		privateKey2 = DH.getPrivateKey(keyMap2);
		System.out.println("乙方公钥:\n" + Base64.encode(publicKey2));
		System.out.println("乙方私钥:\n" + Base64.encode(privateKey2));
		key1 = DH.getSecretKey(publicKey2, privateKey1);
		System.out.println("甲方本地密钥:\n" + Base64.encode(key1));
		key2 = DH.getSecretKey(publicKey1, privateKey2);
		System.out.println("乙方本地密钥:\n" + Base64.encode(key2));
	}

	/**
	 * 主方法
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		initKeyDH();
		System.out.println();
		System.out.println("===甲方向乙方发送加密数据===");
		String input1 = "THIS IS 甲方";
		System.out.println("原文:\n" + input1);
		System.out.println("---使用甲方本地密钥对数据进行加密---");
		//使用甲方本地密钥对数据加密
		byte[] encode1 = DH.encrypt(input1.getBytes(), key1);
		System.out.println("加密:\n" + Base64.encode(encode1));
		System.out.println("---使用乙方本地密钥对数据库进行解密---");
		//使用乙方本地密钥对数据进行解密
		byte[] decode1 = DH.decrypt(encode1, key2);
		String output1 = new String(decode1);
		System.out.println("解密:\n" + output1);

		System.out.println("/~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~..~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~.~/");
		initKey();
		System.out.println("===乙方向甲方发送加密数据===");
		String input2 = "THIS IS 乙方";
		System.out.println("原文:\n" + input2);
		System.out.println("---使用乙方本地密钥对数据进行加密---");
		//使用乙方本地密钥对数据进行加密
		byte[] encode2 = DH.encrypt(input2.getBytes(), key2);
		System.out.println("加密:\n" + Base64.encode(encode2));
		System.out.println("---使用甲方本地密钥对数据进行解密---");
		//使用甲方本地密钥对数据进行解密
		byte[] decode2 = DH.decrypt(encode2, key1);
		String output2 = new String(decode2);
		System.out.println("解密:\n" + output2);
	}
}
