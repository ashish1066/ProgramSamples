public class CryptoUtility {

    /**
     *
     */
    public CryptoUtility() {
        // TODO Auto-generated constructor stub
    }

    //public static String key = "Bar12345Bar12345";
    public static String initVector = "RandomInitVector";

    public static String encrypt(String value,String key) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKey skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            System.out.println("encrypted string: "
                    + Base64.encodeToString(encrypted,Base64.DEFAULT));

            return Base64.encodeToString(encrypted,Base64.DEFAULT);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static String decrypt(String encrypted,String key) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.decode(encrypted,Base64.DEFAULT));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }


    public static String getKey(Context context){
        PackageInfo info;
        String hash = "";
        try {
            info = context.getPackageManager().getPackageInfo("com.theflyy.testingcryptography", PackageManager.GET_SIGNATURES);
            for (Signature signature : info.signatures) {
                MessageDigest md;
                md = MessageDigest.getInstance("SHA");
                md.update(signature.toByteArray());
                hash = new BigInteger(1, md.digest()).toString(16);
              //  String hash= new String(Base64.encode(md.digest(), 0));
                Log.e("hash", hash);
            }
            return hash;
        } catch (PackageManager.NameNotFoundException e1) {
            Log.e("name not found", e1.toString());
        } catch (NoSuchAlgorithmException e) {
            Log.e("no such an algorithm", e.toString());
        } catch (Exception e) {
            Log.e("exception", e.toString());
        }
        return null;
    }


}
