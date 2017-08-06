package local.snapintercept.modules;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.os.Environment;
import android.widget.Toast;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;


public class SnapInterceptLoader implements IXposedHookLoadPackage {
    private static Context mContext;
    private boolean mFrontCameraHasFlash;
    public static ConcurrentHashMap<String, Object> mCacheKeysMap = new ConcurrentHashMap();

    final int VersionCode = 1169;
    final String ExpectedVersion = "10.14.1.0";
    final String SnapEventKlass = "kfg";
    final String SnapEventGetCacheKey = "L";
    final String CbcEncryptionAlgorithmKlass = "com.snapchat.android.framework.crypto.CbcEncryptionAlgorithm";
    final String CbcEncryptionAlgorithmDecrypt = "b";
    final String SnapEventIsVideo = "bT_";
    final String SnapEventUsername = "aj";
    final String SnapEventTimestamp = "t";
    final String MediaCacheEntryKlass = "kli";
    final String MediaCacheEntryConstructorFirstParam = "lxe";
    final String EncryptionAlgorithmInterface = "com.snapchat.android.framework.crypto.EncryptionAlgorithm";
    final String RootDetectorKlass = "cit";
    final String RootDetectorFirst = "b";
    final String RootDetectorSecond = "c";
    final String RootDetectorThird = "d";
    final String RootDetectorForth = "e";
    final String FlashControllerKlass = "cvv";
    final String FlashControllerSetFlash = "a";
    final String ScFlashModeKlass = "cus";


    class RootDetectorOverrides extends XC_MethodReplacement {
        @Override
        protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
            return false;
        }
    }

    class SnapInfo {
        public String mUsername;
        public long mTimestamp;
        public boolean mIsVideo;

    }

    final String AdditionalFieldSnapInfo = "SnapInfo";

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        if(!lpparam.packageName.equals("com.snapchat.android")) {

            return;
        }
        log("Loaded app: " + lpparam.packageName);
        Object activityThread = XposedHelpers.callStaticMethod(XposedHelpers.findClass("android.app.ActivityThread", null), "currentActivityThread");
        mContext = (Context) XposedHelpers.callMethod(activityThread, "getSystemContext");
        PackageInfo snapchatPackage = mContext.getPackageManager().getPackageInfo(lpparam.packageName, 0);
        if(snapchatPackage.versionCode != VersionCode) {
            log("Incorrect version of Snapchat" + lpparam.packageName);
            Toast.makeText(mContext,"SnapIntercept: Wrong APK build. Ensure version "+ExpectedVersion+" is installed.",Toast.LENGTH_LONG).show();
            return;
        }

        mFrontCameraHasFlash = doesFrontCameraHaveFlash();

        // Hook all the root detector methods
        XposedHelpers.findAndHookMethod(RootDetectorKlass,lpparam.classLoader,RootDetectorFirst,new RootDetectorOverrides());
        XposedHelpers.findAndHookMethod(RootDetectorKlass,lpparam.classLoader,RootDetectorSecond,new RootDetectorOverrides());
        XposedHelpers.findAndHookMethod(RootDetectorKlass,lpparam.classLoader,RootDetectorThird,new RootDetectorOverrides());
        XposedHelpers.findAndHookMethod(RootDetectorKlass,lpparam.classLoader,RootDetectorForth,new RootDetectorOverrides());

        // Hook into the SnapEvent class and create a SnapInfo object with the necessary information, then add to the mCacheKeysMap
        XposedHelpers.findAndHookMethod(SnapEventKlass, lpparam.classLoader, SnapEventGetCacheKey, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                String cacheKey = (String)param.getResult();
                log("in get cache key for "+cacheKey);

                Object snapEvent = param.thisObject;

                boolean isVideo = (boolean)XposedHelpers.callMethod(snapEvent,SnapEventIsVideo);
                String username = (String)XposedHelpers.getObjectField(snapEvent,SnapEventUsername);
                long timestamp = XposedHelpers.getLongField(snapEvent,SnapEventTimestamp);

                log("isVideo="+isVideo+" username ="+username+" timestamp="+timestamp);

                SnapInfo snapInfo = new SnapInfo();
                snapInfo.mUsername = username;
                snapInfo.mTimestamp = timestamp;
                snapInfo.mIsVideo = isVideo;

                mCacheKeysMap.put(cacheKey, snapInfo);
            }
        });

        // hook into the constructor for the MediaCacheEntry, and find the related SnapInfo object from mCacheKeysMap
        // then attach the SnapInfo object to the encryptionObject parameter
        XposedHelpers.findAndHookConstructor(MediaCacheEntryKlass,
                lpparam.classLoader,
                MediaCacheEntryConstructorFirstParam,
                String.class,
                EncryptionAlgorithmInterface,
                boolean.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                        String cacheKey = (String)param.args[1];
                        Object encryptionObject = param.args[2];
                        log("in media cache entry hook for object"+cacheKey);
                        if(mCacheKeysMap.containsKey(cacheKey)) {
                            log("contains key, adding additional field");
                            Object snapInfo = mCacheKeysMap.get(cacheKey);
                            XposedHelpers.setAdditionalInstanceField(encryptionObject,AdditionalFieldSnapInfo,snapInfo);

                        }
                    }
                });

        // Hook into the decrypt method of the CbcEncryptionAlgorithm class and check to see if there
        // is a SnapInfo object associated to it
        XposedHelpers.findAndHookMethod(CbcEncryptionAlgorithmKlass,
                lpparam.classLoader,
                CbcEncryptionAlgorithmDecrypt,
                InputStream.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        log("in encryption hook");
                        InputStream returnedStream = (InputStream)param.getResult();
                        if(returnedStream == null) {
                            log("Returned stream is null");
                            return;
                        }
                        SnapInfo snapInfo = (SnapInfo) XposedHelpers.getAdditionalInstanceField(param.thisObject,AdditionalFieldSnapInfo);
                        if(snapInfo == null) {
                            log("snap info is null");

                            return;
                        }

                        String fileName = generateFileName(snapInfo);
                        File f = new File(getFileBasePath(snapInfo),fileName);

                        if(f.createNewFile()) {
                            copyInputStreamToFile(returnedStream, f);
                            returnedStream.close();
                            BufferedInputStream fis = new BufferedInputStream(new FileInputStream(f));
                            param.setResult(fis);
                        }
                    }
                });
        // Hook into the FlashController class and force it to use the physical flash on the front camera
        // if one exists.
        XposedHelpers.findAndHookMethod(FlashControllerKlass,
                lpparam.classLoader,
                FlashControllerSetFlash,
                boolean.class,
                ScFlashModeKlass,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        log("in set flash mode before hook");
                        boolean isFrontFacing = (boolean) param.args[0];

                        if(isFrontFacing && mFrontCameraHasFlash) {
                            // Set the front facing parameter to false to trick the controller into using flash
                            XposedHelpers.callMethod(param.thisObject,FlashControllerSetFlash,false,param.args[1]);

                        }
                    }


                });




    }

    public File getFileBasePath(SnapInfo snapInfo) {
        String baseDir = Environment.getExternalStorageDirectory().getAbsolutePath();

        String path = baseDir+File.separator+"snapintercept"+File.separator+snapInfo.mUsername;

        File filePath = new File(path);
        filePath.mkdirs();
        return filePath;
    }

    public String generateFileName(SnapInfo snapInfo) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss-SSS", Locale.getDefault());
        String extension = snapInfo.mIsVideo ? ".mp4" : ".jpg";
        String dateName = dateFormat.format(new Date(snapInfo.mTimestamp));
        return snapInfo.mUsername+"_"+dateName+extension;
    }

    public boolean doesFrontCameraHaveFlash() {
        CameraManager cm = (CameraManager) mContext.getSystemService(Context.CAMERA_SERVICE);
        try {
            for (String id : cm.getCameraIdList()) {
                CameraCharacteristics cc = cm.getCameraCharacteristics(id);
                try {
                    if(
                            CameraCharacteristics.LENS_FACING_FRONT == cc.get(CameraCharacteristics.LENS_FACING)
                        && cc.get(CameraCharacteristics.FLASH_INFO_AVAILABLE)) {
                        return true;
                    }
                } catch(Exception e) {
                    log("Exception during getting camera characteristics");
                    e.printStackTrace();
                }
            }
        }
        catch (Exception e) {
            log("Exception during locating Front Camera");
            e.printStackTrace();
        }
        return false;
    }

    public static void log(String str) {
        XposedBridge.log("SnapIntercept: "+str);
    }

    public static void copyInputStreamToFile(InputStream in, File file) {
        OutputStream out = null;

        try {
            out = new FileOutputStream(file);
            byte[] buf = new byte[1024];
            int len;
            while((len=in.read(buf))>0){
                out.write(buf,0,len);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            // Ensure that the InputStreams are closed even if there's an exception.
            try {
                if ( out != null ) {
                    out.flush();
                    out.close();
                }
            }
            catch ( IOException e ) {
                e.printStackTrace();
            }
        }
    }
}
